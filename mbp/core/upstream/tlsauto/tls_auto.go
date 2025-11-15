package tlsauto

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"mlkmbp/mbp/common/logx"
	"net"
	"strings"
	"sync"
	"time"
)

var tlsAutoLog = logx.New(logx.WithPrefix("tls.auto"))

type Options struct {
	HandshakeTimeout      time.Duration // 探测握手超时
	SuccessTTL            time.Duration // 缓存：TLS=ON
	FailTTL               time.Duration // 缓存：TLS=OFF
	MaxCacheSize          int           // 缓存上限
	FallbackOnTimeout     bool          // 探测超时 -> 明文回退（不缓存）
	EvictOnTLSError       bool          // 缓存TLS且握手失败 -> 剔除缓存
	DowngradeOnTLSError   bool          // 任何 TLS 握手错误都降级为明文
	CacheOnDowngradedFail bool          // 降级场景是否将该 key 标记为 OFF（多数情况下建议 false，避免误缓存）
}

var DefaultOptions = Options{
	HandshakeTimeout:      2 * time.Second,
	SuccessTTL:            10 * time.Minute,
	FailTTL:               5 * time.Minute,
	MaxCacheSize:          4096,
	FallbackOnTimeout:     true,
	EvictOnTLSError:       true,
	DowngradeOnTLSError:   true,  // 关键：默认任何 TLS 错误都回退明文，不报错
	CacheOnDowngradedFail: false, // 避免把临时性 TLS 问题当成永久 OFF
}

type entry struct {
	useTLS    bool
	expiresAt time.Time
}
type cache struct {
	mu sync.RWMutex
	m  map[string]entry
}

func (c *cache) get(key string) (bool, bool) {
	now := time.Now()
	c.mu.RLock()
	e, ok := c.m[key]
	c.mu.RUnlock()
	if !ok || now.After(e.expiresAt) {
		if ok {
			c.mu.Lock()
			delete(c.m, key)
			c.mu.Unlock()
		}
		return false, false
	}
	return e.useTLS, true
}
func (c *cache) set(key string, useTLS bool, ttl time.Duration, max int) {
	now := time.Now()
	c.mu.Lock()
	if c.m == nil {
		c.m = make(map[string]entry)
	}
	c.m[key] = entry{useTLS: useTLS, expiresAt: now.Add(ttl)}
	if max <= 0 {
		max = DefaultOptions.MaxCacheSize
	}
	if len(c.m) > max {
		for k, v := range c.m {
			if now.After(v.expiresAt) {
				delete(c.m, k)
			}
		}
	}
	c.mu.Unlock()
}
func (c *cache) del(key string) { c.mu.Lock(); delete(c.m, key); c.mu.Unlock() }

var tcpCache cache

// 明确不是 TLS 的典型错误
func clearlyNotTLS(err error) bool {
	var rhErr *tls.RecordHeaderError
	if errors.As(err, &rhErr) {
		return true
	}
	if errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	msg := err.Error()
	if strings.Contains(msg, "not a TLS handshake") ||
		strings.Contains(msg, "first record does not look like a TLS handshake") {
		return true
	}
	return false
}
func isTimeout(err error) bool {
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return true
	}
	return false
}

/*
AdaptiveDialTCP
- dialPlain: 明文拨号（不会发送任何协议字节）
- tlsConf  : 已构造好的 *tls.Config
- cacheKey : 缓存键（例如 upstreamAddr 或 targetAddr）
- opt      : 可为 nil 使用默认
返回：连接、是否TLS、错误（仅当明文/探测都失败时才返回错误）
*/
func AdaptiveDialTCP(
	dialPlain func() (net.Conn, error),
	tlsConf *tls.Config,
	cacheKey string,
	opt *Options,
) (net.Conn, bool, error) {
	if opt == nil {
		o := DefaultOptions
		opt = &o
	}

	// 命中缓存：TLS=ON -> 尝试握手；失败则降级并且“重拨”明文
	if useTLS, ok := tcpCache.get(cacheKey); ok {
		if useTLS {
			raw, err := dialPlain()
			if err != nil {
				return nil, false, fmt.Errorf("dial (cache tls): %w", err)
			}
			t := tls.Client(raw, tlsConf)
			if err := t.Handshake(); err != nil {
				_ = raw.Close()
				if opt.EvictOnTLSError {
					tcpCache.del(cacheKey)
				}
				// 关键点：不要把错误冒给上层，改为重新拨一条明文连接返回
				if opt.DowngradeOnTLSError {
					raw2, e2 := dialPlain()
					if e2 != nil {
						return nil, false, fmt.Errorf("downgrade dial failed: %w", e2)
					}
					// 可选：把该 key 记为 OFF（默认不记，避免误伤）
					if opt.CacheOnDowngradedFail {
						tcpCache.set(cacheKey, false, opt.FailTTL, opt.MaxCacheSize)
					}
					tlsAutoLog.Debugf("cache TLS failed -> downgraded to PLAINTEXT (new conn)")
					return raw2, false, nil
				}
				return nil, false, fmt.Errorf("tls handshake (cache): %w", err)
			}
			tlsAutoLog.Debugf("cache TLS ON sni=%q alpn=%v", tlsConf.ServerName, tlsConf.NextProtos)
			return t, true, nil
		}
		// 缓存 OFF：直接明文
		raw, err := dialPlain()
		return raw, false, err
	}

	// 未命中缓存：先拨“探针”，只用于 TLS 探测；不成功一定关闭并“重拨”明文
	rawProbe, err := dialPlain()
	if err != nil {
		return nil, false, fmt.Errorf("dial (probe): %w", err)
	}
	_ = rawProbe.SetDeadline(time.Now().Add(opt.HandshakeTimeout))
	t := tls.Client(rawProbe, tlsConf)
	hsErr := t.Handshake()
	_ = rawProbe.SetDeadline(time.Time{})

	if hsErr == nil {
		tcpCache.set(cacheKey, true, opt.SuccessTTL, opt.MaxCacheSize)
		tlsAutoLog.Debugf("probe TLS ON sni=%q alpn=%v", tlsConf.ServerName, tlsConf.NextProtos)
		// 只有 TLS 成功才复用探针连接
		return t, true, nil
	}

	// 任何非成功情形：先把探针关掉，再决定是否缓存并重拨一条明文
	_ = rawProbe.Close()

	if clearlyNotTLS(hsErr) {
		tcpCache.set(cacheKey, false, opt.FailTTL, opt.MaxCacheSize)
		tlsAutoLog.Debugf("probe says NON-TLS -> PLAINTEXT (new conn)")
		raw, e2 := dialPlain()
		return raw, false, e2
	}
	if isTimeout(hsErr) && opt.FallbackOnTimeout {
		tlsAutoLog.Debugf("probe TIMEOUT -> PLAINTEXT (no cache, new conn)")
		raw, e2 := dialPlain()
		return raw, false, e2
	}

	// 其他 TLS 错误：按策略降级为明文（新建连接）或返回错误
	if opt.DowngradeOnTLSError {
		tlsAutoLog.Debugf("probe TLS error (%v) -> PLAINTEXT (no cache, new conn)", hsErr)
		raw, e2 := dialPlain()
		return raw, false, e2
	}
	return nil, false, fmt.Errorf("tls probe failed: %v", hsErr)
}
