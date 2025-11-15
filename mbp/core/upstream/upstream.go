package upstream

import (
	"crypto/tls"
	"mlkmbp/mbp/common/logx"
	"mlkmbp/mbp/core/iface"
	"mlkmbp/mbp/core/policy"
	"mlkmbp/mbp/core/rule_runtime"
	"net"
	"net/url"
	"strings"
)

/************** 组件日志 **************/

var upstreamLog = logx.New(logx.WithPrefix("upstream"))

/************** 上游上下文 **************/

type UpstreamCtx struct {
	RC        iface.RuntimeCtx
	RR        rule_runtime.RuleRuntime
	AR        rule_runtime.AuthResult
	Remote    string
	StartTime int64
	Decision  policy.Decision
}

/************** Dialer 抽象 **************/

type UpstreamDialer interface {
	OpenForConnect(uctx UpstreamCtx, upstreamAddr, targetHostPort, httpProto string) (net.Conn, error)
	OpenForHTTPNonConnect(uctx UpstreamCtx, upstreamAddr string, u *url.URL, httpProto string) (conn net.Conn, needOriginForm bool, err error)
}

func ChooseDialer(proto string) UpstreamDialer {
	switch strings.ToLower(strings.TrimSpace(proto)) {
	case "socks5", "tls-socks5":
		return socks5Dialer{}
	case "http/s", "tls-http/s":
		fallthrough
	default:
		return httpProxyDialer{}
	}
}

/************** 公共工具 **************/

func PickCreds(uctx UpstreamCtx) (user, pass string) {
	switch {
	case uctx.RR.TargetAddr != "" && (uctx.RR.AuthUsername != "" || uctx.RR.AuthPassword != ""):
		upstreamLog.Debugf("pickCreds: use rule creds (haveUser=%t, havePass=%t)", uctx.RR.AuthUsername != "", uctx.RR.AuthPassword != "")
		return uctx.RR.AuthUsername, uctx.RR.AuthPassword
	case uctx.Decision.AuthUser != "" || uctx.Decision.AuthPass != "":
		upstreamLog.Debugf("pickCreds: use policy creds (haveUser=%t, havePass=%t)", uctx.Decision.AuthUser != "", uctx.Decision.AuthPass != "")
		return uctx.Decision.AuthUser, uctx.Decision.AuthPass
	default:
		upstreamLog.Debugf("pickCreds: use session creds (haveUser=%t, havePass=%t)", uctx.AR.Username != "", uctx.AR.Password != "")
		return uctx.AR.Username, uctx.AR.Password
	}
}

// makeTLSConfig 根据 UpstreamCtx 生成上游 TLS 客户端配置。
//   - 证书校验：按 Decision/RuleRuntime 的 SkipCertVerify
//   - ALPN：支持逗号分隔，自动去重/去空白
//   - TLSFingerprint 预设（大小写不敏感）：
//     "" / "default" -> 保持默认（MinVersion: 1.3）
//     "strict13"     -> 仅 TLS 1.3（最安全，兼容性最差）
//     "modern"       -> 1.3 优先、允许降到 1.2（推荐默认生产）
//     "compat"       -> 偏兼容 1.2 生态
//     "tls12-only"   -> 仅 TLS 1.2
func makeTLSConfig(uctx UpstreamCtx, upstreamAddr string) *tls.Config {
	host, _, _ := net.SplitHostPort(upstreamAddr)

	// 判断配置来源：RR（client模式直连）优先，否则用策略 Decision
	useRR := uctx.RR.TargetAddr != ""

	cfg := &tls.Config{
		ServerName:         host,
		MinVersion:         tls.VersionTLS12, // 默认更安全
		InsecureSkipVerify: false,
	}

	var (
		skipVerify  bool
		alpnCSV     string
		fingerprint string
	)

	if useRR {
		skipVerify = uctx.RR.SkipCertVerify
		alpnCSV = strings.TrimSpace(uctx.RR.ALPN)
		fingerprint = strings.ToLower(strings.TrimSpace(uctx.RR.TLSFingerprint))
	} else {
		skipVerify = uctx.Decision.SkipCertVerify
		alpnCSV = strings.TrimSpace(uctx.Decision.ALPN)
		fingerprint = strings.ToLower(strings.TrimSpace(uctx.Decision.TLSFingerprint))
	}

	// 证书校验
	if skipVerify {
		cfg.InsecureSkipVerify = true
	}

	// ALPN：逗号分隔、去空白、去重
	if alpnCSV != "" {
		var np []string
		seen := make(map[string]struct{}, 4)
		for _, p := range strings.Split(alpnCSV, ",") {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			lp := strings.ToLower(p)
			if _, ok := seen[lp]; ok {
				continue
			}
			seen[lp] = struct{}{}
			np = append(np, p)
		}
		if len(np) > 0 {
			cfg.NextProtos = np
		}
	}

	applyTLSFingerprintPreset(cfg, fingerprint)
	return cfg
}

/************** TLS 指纹预设（兼容无 SignatureSchemes 的 Go） **************/

// 仅对 TLS 1.2 有效的套件（1.3 的套件在 Go 中不可排序）
var cipherTLS12Modern = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
}

var cipherTLS12Compat = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,

	// 如确实需要更老端，才开启 CBC（默认关闭以减少攻击面/指纹暴露）
	// tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	// tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	// tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	// tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
}

var curvesModern = []tls.CurveID{
	tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521,
}

// 依据预设修改 tls.Config（不使用 SignatureSchemes）
func applyTLSFingerprintPreset(cfg *tls.Config, preset string) {
	switch preset {
	case "", "default":
		// 保持默认（MinVersion 已设为 1.2）
		return

	case "strict13":
		cfg.MinVersion = tls.VersionTLS13
		cfg.MaxVersion = 0     // 让标准库挑最高
		cfg.CipherSuites = nil // 仅 1.2 生效，置空即可
		cfg.CurvePreferences = curvesModern

	case "modern":
		cfg.MinVersion = tls.VersionTLS12
		cfg.MaxVersion = 0
		cfg.CipherSuites = cipherTLS12Modern
		cfg.CurvePreferences = curvesModern

	case "compat":
		cfg.MinVersion = tls.VersionTLS12
		cfg.MaxVersion = 0
		cfg.CipherSuites = cipherTLS12Compat
		cfg.CurvePreferences = curvesModern

	case "tls12-only":
		cfg.MinVersion = tls.VersionTLS12
		cfg.MaxVersion = tls.VersionTLS12
		cfg.CipherSuites = cipherTLS12Compat
		cfg.CurvePreferences = curvesModern

	default:
		// 未知预设：回落到 modern
		cfg.MinVersion = tls.VersionTLS12
		cfg.MaxVersion = 0
		cfg.CipherSuites = cipherTLS12Modern
		cfg.CurvePreferences = curvesModern
	}
}
