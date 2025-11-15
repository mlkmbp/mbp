package listener

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"math"
	"mlkmbp/mbp/common"
	"mlkmbp/mbp/common/logx"
	"mlkmbp/mbp/common/ttls"
	"mlkmbp/mbp/core/forward"
	"mlkmbp/mbp/core/forward/nat"
	"mlkmbp/mbp/core/iface"
	"mlkmbp/mbp/core/limiter"
	"mlkmbp/mbp/core/proxy"
	"mlkmbp/mbp/core/rule_runtime"
	"mlkmbp/mbp/model"
	"net"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// 统一并发控制/生命周期的 ListenerMgr
type ListenerMgr struct {
	wg     sync.WaitGroup
	ctx    context.Context
	cancel context.CancelFunc
	sem    chan struct{}

	lmu         sync.Mutex
	listenerMap map[net.Listener]struct{}
	connMap     map[net.Conn]struct{}
	stopOnce    sync.Once

	// ★ 组件级日志（默认前缀 listener，等级跟随全局）
	Log *logx.Logger
}

func (lm *ListenerMgr) Context() context.Context { return lm.ctx }

func (lm *ListenerMgr) AcquirePermit() (release func(), ok bool) {
	select {
	case lm.sem <- struct{}{}:
		return func() { <-lm.sem }, true
	default:
		return func() {}, false
	}
}

func NewListenerMgr(MaxConnection int) (lm *ListenerMgr, AcquirePermit func() (release func(), ok bool)) {
	lm = &ListenerMgr{
		listenerMap: make(map[net.Listener]struct{}),
		connMap:     make(map[net.Conn]struct{}),
		Log:         logx.New(logx.WithPrefix("listener")),
	}
	lm.ctx, lm.cancel = context.WithCancel(context.Background())
	if MaxConnection <= 0 {
		MaxConnection = math.MaxInt
	}
	lm.sem = make(chan struct{}, MaxConnection)

	AcquirePermit = func() (func(), bool) {
		select {
		case lm.sem <- struct{}{}:
			return func() { <-lm.sem }, true
		default:
			return func() {}, false
		}
	}
	return
}

// 统一登记/反登记 listener
func (lm *ListenerMgr) trackListener(ln net.Listener) {
	lm.lmu.Lock()
	lm.listenerMap[ln] = struct{}{}
	lm.lmu.Unlock()
}
func (lm *ListenerMgr) untrackListener(ln net.Listener) {
	lm.lmu.Lock()
	delete(lm.listenerMap, ln)
	lm.lmu.Unlock()
}

// 统一登记/反登记 conn
func (lm *ListenerMgr) trackConn(c net.Conn) {
	lm.lmu.Lock()
	lm.connMap[c] = struct{}{}
	lm.lmu.Unlock()
}
func (lm *ListenerMgr) untrackConn(c net.Conn) {
	lm.lmu.Lock()
	delete(lm.connMap, c)
	lm.lmu.Unlock()
}

// 连接处理器签名（各协议的“每连接处理逻辑”遵循它）
type ConnHandler func(rc iface.RuntimeCtx, rr rule_runtime.RuleRuntime, c net.Conn)

// 统一 listen+accept 循环；外界只给 handler
func (lm *ListenerMgr) serveLoop(rr rule_runtime.RuleRuntime, tlsCfg *tls.Config, protocol string, handler ConnHandler) error {
	ln, err := listen(rr, tlsCfg)
	if err != nil {
		if rr.OnReject != nil {
			rr.OnReject("listen_"+protocol+"_failed: "+err.Error(), rr.ListenAddr)
		}
		if lm.Log != nil {
			lm.Log.Errorf("[rule %d][%s] listen failed on %s: %v", rr.RuleId, protocol, rr.ListenAddr, err)
		}
		return err
	}
	lm.trackListener(ln)
	if lm.Log != nil {
		lm.Log.Infof("[rule %d][%s] listening on %s", rr.RuleId, protocol, rr.ListenAddr)
	}
	defer func() {
		_ = ln.Close()
		lm.untrackListener(ln)
		if lm.Log != nil {
			lm.Log.Debugf("[rule %d][%s] listener closed: %s", rr.RuleId, protocol, rr.ListenAddr)
		}
	}()

	// 缩短 Accept 轮询周期，提升停止响应速度
	if tl, ok := ln.(*net.TCPListener); ok {
		_ = tl.SetDeadline(time.Now().Add(200 * time.Millisecond))
	}

	for {
		c, err := ln.Accept()
		if err != nil {
			// 被 Stop() 关闭 listener 或 ctx 取消
			if lm.ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				if lm.Log != nil {
					lm.Log.Debugf("[rule %d][%s] accept loop exit (context cancelled)", rr.RuleId, protocol)
				}
				return nil
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if tl, ok2 := ln.(*net.TCPListener); ok2 {
					_ = tl.SetDeadline(time.Now().Add(200 * time.Millisecond))
				}
				select {
				case <-lm.ctx.Done():
					_ = ln.Close()
					if lm.Log != nil {
						lm.Log.Debugf("[rule %d][%s] accept loop break on cancel", rr.RuleId, protocol)
					}
					return nil
				default:
				}
				continue
			}
			if lm.Log != nil {
				lm.Log.Errorf("[rule %d][%s] accept error: %v", rr.RuleId, protocol, err)
			}
			return err
		}

		remote := c.RemoteAddr().String()
		if lm.Log != nil {
			lm.Log.Debugf("[rule %d][%s] accept %s", rr.RuleId, protocol, remote)
		}
		lm.trackConn(c)

		go func(c net.Conn) {
			defer lm.untrackConn(c)
			remote := c.RemoteAddr().String()

			release, ok := rr.AcquirePermit()
			if !ok {
				if rr.OnReject != nil {
					rr.OnReject("too_many_connections", remote)
				}
				if lm.Log != nil {
					lm.Log.Infof("[rule %d][%s] reject %s: too many connections", rr.RuleId, protocol, remote)
				}
				_ = c.Close()
				return
			}
			defer release()

			lh, lp, sh, sp, th, tp := common.ParseAddrPorts(rr.ListenAddr, remote, rr.TargetAddr)
			countingConn := limiter.NewCountingConn(c, limiter.CountingOpts{
				Protocol:   protocol,
				ListenAddr: lh, ListenPort: lp,
				SourceAddr: sh, SourcePort: sp,
				TargetAddr: th, TargetPort: tp,
				Ctx:                   lm.ctx,
				StartTime:             time.Now().UnixMilli(),
				Direction:             false,
				PerDownLimiter:        limiter.NewLimiter(rr.DownLimit),
				RuleSharedDownLimiter: rr.RuleSharedDownLimiter,
				OnFinish:              rr.OnFinish,
			})

			handler(lm, rr, countingConn) // handler 内部或管道里自行 Close
		}(c)
	}
}

// 统一监听：可选 TLS
func listen(rr rule_runtime.RuleRuntime, tlsCfg *tls.Config) (net.Listener, error) {
	if tlsCfg != nil {
		return tls.Listen("tcp", rr.ListenAddr, tlsCfg)
	}
	return net.Listen("tcp", rr.ListenAddr)
}

// —— 各协议“Server 函数”：签名统一为 func(rr) error ——
// 这些是对 serveLoop 的薄封装，把具体的 ConnHandler 带进去。

func (lm *ListenerMgr) ServeTCP(rr rule_runtime.RuleRuntime) error {
	return lm.serveLoop(rr, nil, "tcp", forward.HandleTCP)
}

func (lm *ListenerMgr) ServeTLSTCP(rr rule_runtime.RuleRuntime, tlsCfg *tls.Config) error {
	return lm.serveLoop(rr, tlsCfg, "tls-tcp", forward.HandleTCP)
}

func (lm *ListenerMgr) ServeHTTPProxy(rr rule_runtime.RuleRuntime, tlsCfg *tls.Config) error {
	return lm.serveLoop(rr, tlsCfg, "http/s", proxy.HandleHTTP)
}

func (lm *ListenerMgr) ServeSOCKS5(rr rule_runtime.RuleRuntime, tlsCfg *tls.Config) error {
	return lm.serveLoop(rr, tlsCfg, "socks5", proxy.HandleSOCKS5)
}

// UDP 保持独立（报文型，与 stream 不同）
func (lm *ListenerMgr) ServeUDP(rr rule_runtime.RuleRuntime) error {
	if lm.Log != nil {
		lm.Log.Infof("[rule %d][udp] listening on %s => %s", rr.RuleId, rr.ListenAddr, rr.TargetAddr)
	}
	return forward.ServeUDP(lm, rr)
}

// —— 启动入口：统一只传“Server 函数” —— //

func (m *ListenerMgr) StartRule(rr rule_runtime.RuleRuntime) {
	startOne := func(kind string, fn func(rule_runtime.RuleRuntime) error) {
		m.wg.Add(1)
		go func() {
			defer m.wg.Done()
			if err := fn(rr); err != nil && m.ctx.Err() == nil {
				if m.Log != nil {
					m.Log.Errorf("[rule %d][%s] stopped: %v", rr.RuleId, kind, err)
				}
			}
		}()
	}

	wantKernel := rr.InterfaceName != "" && runtime.GOOS != "windows" && runtime.GOOS != "darwin"

	tryKernel := func(protocol string) bool {
		if !wantKernel {
			return false
		}
		if err := m.startKernelNAT(rr); err != nil {
			if errors.Is(err, nat.ErrUnsupported) {
				m.Log.Errorf("[rule %d][nat-%s] kernel NAT unsupported on this platform; falling back to user-space %v", rr.RuleId, protocol, err)
				return false
			}
			m.Log.Errorf("[rule %d][nat-%s] failed: %v; falling back to user-space", rr.RuleId, protocol, err)
			return false
		}
		// kernel NAT started successfully; nothing else to start
		return true
	}

	switch strings.ToLower(rr.Protocol) {
	case "all":
		if tryKernel("all") {
			return
		}
		if m.Log != nil {
			m.Log.Infof("[rule %d][tcp] %s -> %s", rr.RuleId, rr.ListenAddr, rr.TargetAddr)
		}
		startOne("tcp", m.ServeTCP)
		if m.Log != nil {
			m.Log.Infof("[rule %d][udp] %s => %s", rr.RuleId, rr.ListenAddr, rr.TargetAddr)
		}
		startOne("udp", m.ServeUDP)

	case "tcp":
		if tryKernel("tcp") {
			return
		}
		if m.Log != nil {
			m.Log.Infof("[rule %d][tcp] %s -> %s", rr.RuleId, rr.ListenAddr, rr.TargetAddr)
		}
		startOne("tcp", m.ServeTCP)

	case "udp":
		if tryKernel("udp") {
			return
		}
		if m.Log != nil {
			m.Log.Infof("[rule %d][udp] %s => %s", rr.RuleId, rr.ListenAddr, rr.TargetAddr)
		}
		startOne("udp", m.ServeUDP)

	case "tls-tcp":
		// 走代理/转发栈，NAT 不适用
		tlsCfg, err := ttls.LoadTLSConfig(rr.TLSCert, rr.TLSKey, rr.TLSSNIGuard)
		if err != nil {
			if rr.OnReject != nil {
				rr.OnReject("bad tls config", rr.ListenAddr)
			}
			if m.Log != nil {
				m.Log.Errorf("[rule %d][tls-tcp] bad tls config: %v", rr.RuleId, err)
			}
			return
		}
		if m.Log != nil {
			m.Log.Infof("[rule %d][tls-tcp] %s -> %s", rr.RuleId, rr.ListenAddr, rr.TargetAddr)
		}
		startOne("tls-tcp", func(r rule_runtime.RuleRuntime) error { return m.ServeTLSTCP(r, tlsCfg) })

	case "http/s":
		if m.Log != nil {
			m.Log.Infof("[rule %d][http/s] %s => %s", rr.RuleId, rr.ListenAddr, rr.TargetAddr)
		}
		startOne("http/s", func(r rule_runtime.RuleRuntime) error { return m.ServeHTTPProxy(r, nil) })

	case "tls-http/s":
		tlsCfg, err := ttls.LoadTLSConfig(rr.TLSCert, rr.TLSKey, rr.TLSSNIGuard)
		if err != nil {
			if rr.OnReject != nil {
				rr.OnReject("bad tls config", rr.ListenAddr)
			}
			if m.Log != nil {
				m.Log.Errorf("[rule %d][tls-http/s] bad tls config: %v", rr.RuleId, err)
			}
			return
		}
		if m.Log != nil {
			m.Log.Infof("[rule %d][tls-http/s] %s => %s", rr.RuleId, rr.ListenAddr, rr.TargetAddr)
		}
		startOne("tls-http/s", func(r rule_runtime.RuleRuntime) error { return m.ServeHTTPProxy(r, tlsCfg) })

	case "socks5":
		if m.Log != nil {
			m.Log.Infof("[rule %d][socks5] %s => %s", rr.RuleId, rr.ListenAddr, rr.TargetAddr)
		}
		startOne("socks5", func(r rule_runtime.RuleRuntime) error { return m.ServeSOCKS5(r, nil) })

	case "tls-socks5":
		tlsCfg, err := ttls.LoadTLSConfig(rr.TLSCert, rr.TLSKey, rr.TLSSNIGuard)
		if err != nil {
			if rr.OnReject != nil {
				rr.OnReject("bad tls config", rr.ListenAddr)
			}
			if m.Log != nil {
				m.Log.Errorf("[rule %d][tls-socks5] bad tls config: %v", rr.RuleId, err)
			}
			return
		}
		if m.Log != nil {
			m.Log.Infof("[rule %d][tls-socks5] %s => %s", rr.RuleId, rr.ListenAddr, rr.TargetAddr)
		}
		startOne("tls-socks5", func(r rule_runtime.RuleRuntime) error { return m.ServeSOCKS5(r, tlsCfg) })

	default:
		if m.Log != nil {
			m.Log.Infof("[rule %d][%s] unknown protocol", rr.RuleId, rr.Protocol)
		}
	}
}

// 走内核 NAT（支持 tcp/udp/all）
func (m *ListenerMgr) startKernelNAT(rr rule_runtime.RuleRuntime) error {
	k := nat.NewKernel(rr.RuleId) // 跨平台工厂
	ctx, cancel := context.WithCancel(m.ctx)

	// 协议 → 监听字符串
	p := strings.ToLower(rr.Protocol)
	var tcpListen, udpListen string
	switch p {
	case "tcp":
		tcpListen = rr.ListenAddr
	case "udp":
		udpListen = rr.ListenAddr
	case "all":
		tcpListen, udpListen = rr.ListenAddr, rr.ListenAddr
	default:
		cancel()
		return fmt.Errorf("kernel NAT only supports tcp/udp/all, got %s", rr.Protocol)
	}

	// 解析 target
	host, portStr, err := net.SplitHostPort(rr.TargetAddr)
	if err != nil {
		cancel()
		return err
	}
	port, _ := strconv.Atoi(portStr)

	// 绑定网卡
	var eg *nat.Egress
	if rr.InterfaceName != "" {
		eg = &nat.Egress{IfName: rr.InterfaceName}
	}

	// 放在 startKernelNAT 顶部其它变量之后：
	var uid2name sync.Map // userID -> username（在 Auth 时缓存）

	hooks := nat.Hooks{
		Auth: func(ctx context.Context, fm nat.FlowMeta) (int64, bool, string) {
			res := rr.Auth(fm.SrcIP, "", "", rr.RuleId, rr.UserId)
			if !res.OK {
				return 0, false, string(res.Reason)
			}
			// 缓存用户名，供 OnClose 落库
			if res.Username != "" {
				uid2name.Store(res.UserId, res.Username)
			}
			return res.UserId, true, ""
		},
		OnReject: rr.OnReject,

		OnClose: func(s nat.FlowStats) {
			if rr.OnFinish == nil {
				return
			}

			// 1) 监听端：优先内核上报，兜底用配置
			lAddr, lPort := s.ListenAddr, s.ListenPort
			if lAddr == "" || lPort == 0 {
				lh, lp, _, _, _, _ := common.ParseAddrPorts(rr.ListenAddr, "", rr.TargetAddr)
				lAddr, lPort = lh, lp
			}

			// 2) 目标端：优先内核上报，兜底用配置
			tAddr, tPort := s.TargetAddr, s.TargetPort
			if tAddr == "" || tPort == 0 {
				th, tpStr, _ := net.SplitHostPort(rr.TargetAddr)
				if p, err := strconv.Atoi(tpStr); err == nil {
					tAddr, tPort = th, p
				}
			}

			// 3) 用户名
			uname := ""
			if v, ok := uid2name.Load(s.UserID); ok {
				uname, _ = v.(string)
			}

			// 4) 时间与时长
			whenMs := s.When.UnixMilli()
			durMs := s.DurMS // 内核无法取到就会是 0

			// 5) 协议/源端
			proto := s.Proto
			srcA, srcP := s.SourceAddr, s.SourcePort

			rr.OnFinish(int64(s.UserID), model.TrafficLog{
				Time:       whenMs,
				Username:   uname,
				Direction:  "nat", // 单条记录
				ListenAddr: lAddr,
				ListenPort: lPort,
				Protocol:   proto,
				Up:         int64(s.UpBytes),
				Down:       int64(s.DownBytes),
				Dur:        durMs,
				SourceAddr: srcA,
				SourcePort: srcP,
				TargetAddr: tAddr,
				TargetPort: tPort,
			})
		},
	}

	isIP := net.ParseIP(host) != nil
	if !isIP {
		// —— 域名：用 DomainRunner（含 StartAuthGate/StartStats & 热更新），并绑定网卡 —— //
		if err := nat.DomainRunner(ctx, k, rr.RuleId,
			tcpListen, udpListen, host, port, eg, hooks); err != nil {
			cancel()
			return err
		}
	} else {
		// —— 目标是 IP：一次性安装 —— //
		var lt *net.TCPAddr
		var lu *net.UDPAddr
		var tt *net.TCPAddr
		var tu *net.UDPAddr
		if tcpListen != "" {
			a, err := net.ResolveTCPAddr("tcp", tcpListen)
			if err != nil {
				cancel()
				return err
			}
			lt = a
			ip := net.ParseIP(host)
			tt = &net.TCPAddr{IP: ip, Port: port}
		}
		if udpListen != "" {
			a, err := net.ResolveUDPAddr("udp", udpListen)
			if err != nil {
				cancel()
				return err
			}
			lu = a
			ip := net.ParseIP(host)
			tu = &net.UDPAddr{IP: ip, Port: port}
		}
		if err := k.Install(ctx, lt, tt, lu, tu, rr.RuleId, eg); err != nil {
			cancel()
			return err
		}
		if err := k.StartAuthGate(ctx, rr.RuleId, hooks); err != nil {
			cancel()
			_ = k.Uninstall(context.Background(), rr.RuleId)
			return err
		}
		if err := k.StartStats(ctx, rr.RuleId, hooks); err != nil {
			cancel()
			_ = k.Uninstall(context.Background(), rr.RuleId)
			return err
		}
	}

	// 生命周期：mgr 停止时清理 NAT
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		<-m.ctx.Done()
		cancel()
		_ = k.Uninstall(context.Background(), rr.RuleId)
		_ = k.Close()
	}()

	if m.Log != nil {
		m.Log.Infof("[rule %d][nat-%s] %s => %s (iface=%s)", rr.RuleId, p, rr.ListenAddr, rr.TargetAddr, rr.InterfaceName)
	}
	return nil
}

// 优雅停止
func (m *ListenerMgr) Stop() {
	m.StopWithTimeout(10 * time.Second)
}

// StopWithTimeout：更快且“到点必停”
func (m *ListenerMgr) StopWithTimeout(timeout time.Duration) {
	m.stopOnce.Do(func() {
		if m.Log != nil {
			m.Log.Infof("stopping listener mgr (timeout=%s)", timeout)
		}
		// 1) 广播取消
		if m.cancel != nil {
			m.cancel()
		}

		// 2) 立刻关闭所有 listener，打断 Accept()
		m.lmu.Lock()
		for ln := range m.listenerMap {
			_ = ln.Close()
		}
		m.lmu.Unlock()

		// 3) 给所有活动连接打断 IO（SetDeadline 到现在）
		now := time.Now()
		m.lmu.Lock()
		for c := range m.connMap {
			_ = c.SetDeadline(now) // 同时影响读/写
		}
		m.lmu.Unlock()

		// 4) 等待 goroutine 收尾（只跟 serve 循环 wg 绑定）
		done := make(chan struct{})
		go func() { m.wg.Wait(); close(done) }()

		select {
		case <-done:
			if m.Log != nil {
				m.Log.Debugf("listener mgr stopped gracefully")
			}
		case <-time.After(timeout):
			// 5) 超时仍未退出：强制关闭所有连接
			if m.Log != nil {
				m.Log.Infof("force close all active conns after timeout")
			}
			m.lmu.Lock()
			for c := range m.connMap {
				_ = c.Close()
			}
			m.lmu.Unlock()
		}
	})
}
