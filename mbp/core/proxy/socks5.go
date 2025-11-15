package proxy

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"mlkmbp/mbp/common"
	"mlkmbp/mbp/common/logx"
	"mlkmbp/mbp/core/iface"
	"mlkmbp/mbp/core/limiter"
	"mlkmbp/mbp/core/policy"
	"mlkmbp/mbp/core/rule_runtime"
	"mlkmbp/mbp/core/transport"
	"mlkmbp/mbp/core/upstream"
	"mlkmbp/mbp/model"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

/************** 组件日志 **************/

var proxySocks5Log = logx.New(logx.WithPrefix("proxy.socks5"))

/* ---------- 常量 ---------- */

const (
	socksVer5       = 0x05
	socksCmdConnect = 0x01
	socksCmdBind    = 0x02
	socksCmdUDP     = 0x03

	atypeIPv4   = 0x01
	atypeDomain = 0x03
	atypeIPv6   = 0x04

	readPoll     = 200 * time.Millisecond
	maxUDPPacket = 64 * 1024
)

type s5Parsed struct {
	br     *bufio.Reader
	cmd    byte
	target string // host:port
}

/************** 入口 **************/

func HandleSOCKS5(rc iface.RuntimeCtx, rr rule_runtime.RuleRuntime, c net.Conn) {
	if rr.TargetAddr == "" {
		handleSocks5Server(rc, rr, c)
	} else {
		handleSocks5Client(rc, rr, c)
	}
}

/************** 公共：鉴权+读 CMD/ADDR **************/

func s5AuthHandshakeAndParse(rr rule_runtime.RuleRuntime, c net.Conn) (ar rule_runtime.AuthResult, out s5Parsed, ok bool) {
	remote := c.RemoteAddr().String()

	// 读 VER + NMETHODS
	var g [2]byte
	if _, err := io.ReadFull(c, g[:]); err != nil || g[0] != socksVer5 {
		proxySocks5Log.Debugf("socks5 handshake failed ver from=%s err=%v ver=%d", remote, err, g[0])
		_ = c.Close()
		return ar, out, false
	}
	nm := int(g[1])
	if nm <= 0 {
		proxySocks5Log.Debugf("socks5 handshake nm<=0 from=%s", remote)
		_ = c.Close()
		return ar, out, false
	}

	// 读 METHODS
	ms := make([]byte, nm)
	if _, err := io.ReadFull(c, ms); err != nil {
		proxySocks5Log.Debugf("socks5 read methods failed from=%s err=%v", remote, err)
		_ = c.Close()
		return ar, out, false
	}

	// 只支持用户名密码(0x02)
	support := false
	for _, m := range ms {
		if m == 0x02 {
			support = true
			break
		}
	}
	if !support {
		proxySocks5Log.Errorf("socks5 no supported method(0x02) from=%s offered=%v", remote, ms)
		_, _ = c.Write([]byte{socksVer5, 0xFF})
		_ = c.Close()
		return ar, out, false
	}
	_, _ = c.Write([]byte{socksVer5, 0x02})

	// RFC1929 用户名密码
	var v [1]byte
	if _, err := io.ReadFull(c, v[:]); err != nil || v[0] != 0x01 {
		proxySocks5Log.Debugf("socks5 auth version bad from=%s err=%v ver=%d", remote, err, v[0])
		_, _ = c.Write([]byte{0x01, 0x01})
		_ = c.Close()
		return ar, out, false
	}
	var bl [1]byte
	_, _ = io.ReadFull(c, bl[:])
	ub := make([]byte, int(bl[0]))
	if _, err := io.ReadFull(c, ub); err != nil {
		proxySocks5Log.Debugf("socks5 auth read user failed from=%s err=%v", remote, err)
		_, _ = c.Write([]byte{0x01, 0x01})
		_ = c.Close()
		return ar, out, false
	}
	_, _ = io.ReadFull(c, bl[:])
	pb := make([]byte, int(bl[0]))
	if _, err := io.ReadFull(c, pb); err != nil {
		proxySocks5Log.Debugf("socks5 auth read pass failed from=%s err=%v", remote, err)
		_, _ = c.Write([]byte{0x01, 0x01})
		_ = c.Close()
		return ar, out, false
	}

	if rr.Auth == nil {
		proxySocks5Log.Errorf("socks5 auth missing rr.Auth from=%s", remote)
		_, _ = c.Write([]byte{0x01, 0x01})
		_ = c.Close()
		return ar, out, false
	}
	user, pass := string(ub), string(pb)
	ar = rr.Auth(common.RemoteIPFromConn(c), user, pass, 0, 0)
	if !ar.OK {
		proxySocks5Log.Errorf("socks5 auth failed from=%s user=%q reason=%s", remote, user, ar.Reason)
		_, _ = c.Write([]byte{0x01, 0x01})
		if rr.OnReject != nil {
			reason := string(ar.Reason)
			if reason == "" {
				reason = "auth_failed"
			}
			rr.OnReject(reason, c.RemoteAddr().String())
		}
		return ar, out, false
	}
	_, _ = c.Write([]byte{0x01, 0x00})
	proxySocks5Log.Debugf("socks5 auth ok from=%s user=%q uid=%d", remote, ar.Username, ar.UserId)

	// 读请求头 VER CMD RSV ATYP
	var h [4]byte
	if _, err := io.ReadFull(c, h[:]); err != nil || h[0] != socksVer5 {
		proxySocks5Log.Debugf("socks5 read request head failed from=%s err=%v ver=%d", remote, err, h[0])
		_ = c.Close()
		return ar, out, false
	}
	cmd := h[1]
	atyp := h[3]

	// 读目标地址
	target, err := readSocks5AddrFromConn(c, atyp)
	if err != nil {
		proxySocks5Log.Debugf("socks5 read target failed from=%s err=%v", remote, err)
		replySocks5(c, 0x04, nil)
		_ = c.Close()
		return ar, out, false
	}

	out = s5Parsed{cmd: cmd, target: target}
	proxySocks5Log.Debugf("socks5 cmd=%d target=%s from=%s uid=%d", cmd, target, remote, ar.UserId)
	return ar, out, true
}

func readSocks5AddrFromConn(c net.Conn, atyp byte) (string, error) {
	switch atyp {
	case atypeIPv4:
		var ip [4]byte
		if _, err := io.ReadFull(c, ip[:]); err != nil {
			return "", err
		}
		var p [2]byte
		if _, err := io.ReadFull(c, p[:]); err != nil {
			return "", err
		}
		return net.JoinHostPort(net.IP(ip[:]).String(), strconv.Itoa(int(binary.BigEndian.Uint16(p[:])))), nil
	case atypeDomain:
		var l [1]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return "", err
		}
		host := make([]byte, int(l[0]))
		if _, err := io.ReadFull(c, host); err != nil {
			return "", err
		}
		var p [2]byte
		if _, err := io.ReadFull(c, p[:]); err != nil {
			return "", err
		}
		return net.JoinHostPort(string(host), strconv.Itoa(int(binary.BigEndian.Uint16(p[:])))), nil
	case atypeIPv6:
		var ip [16]byte
		if _, err := io.ReadFull(c, ip[:]); err != nil {
			return "", err
		}
		var p [2]byte
		if _, err := io.ReadFull(c, p[:]); err != nil {
			return "", err
		}
		return net.JoinHostPort(net.IP(ip[:]).String(), strconv.Itoa(int(binary.BigEndian.Uint16(p[:])))), nil
	default:
		return "", errors.New("bad atyp")
	}
}

/************** 服务端路径（动态目的） **************/

func handleSocks5Server(rc iface.RuntimeCtx, rr rule_runtime.RuleRuntime, c net.Conn) {
	start := time.Now().UnixMilli()
	remote := c.RemoteAddr().String()

	ar, p, ok := s5AuthHandshakeAndParse(rr, c)
	if !ok {
		return
	}

	// 无损刷新共享配额镜像（不会覆盖并发会话已扣的量）
	limiter.GlobalUserQuotas.Refresh(ar.UserId, ar.Remain)

	// 注入用户限速（TCP 下行）
	limiter.AttachUserDownLimiters(c, ar)

	switch p.cmd {
	case socksCmdConnect:
		dec, err := rr.Decider.Decide(ar.UserId, rr.UserId, rr.RuleId, p.target)
		if err != nil {
			proxySocks5Log.Errorf("policy decide error (socks5 CONNECT) uid=%d target=%s err=%v", ar.UserId, p.target, err)
			replySocks5(c, 0x01, nil)
			_ = c.Close()
			return
		}

		switch dec.Action {
		case model.ActionReject:
			proxySocks5Log.Debugf("policy reject (socks5 CONNECT) uid=%d target=%s", ar.UserId, p.target)
			replySocks5(c, 0x02, nil)
			_ = c.Close()
			return
		case model.ActionForward:
			upAddr := dec.TargetAddress
			if upAddr == "" {
				upAddr = rr.TargetAddr
			}
			proxySocks5Log.Debugf("policy forward (socks5 CONNECT) uid=%d via=%s to=%s proto=%s", ar.UserId, upAddr, p.target, dec.Protocol)
			uctx := upstream.UpstreamCtx{RC: rc, RR: rr, AR: ar, Remote: remote, StartTime: start, Decision: dec}
			up, err := upstream.ChooseDialer(dec.Protocol).OpenForConnect(uctx, upAddr, p.target, "HTTP/1.1")
			if err != nil {
				proxySocks5Log.Errorf("upstream tunnel failed (socks5 CONNECT) uid=%d: %v", ar.UserId, err)
				replySocks5(c, 0x05, nil)
				_ = c.Close()
				return
			}
			replySocks5(c, 0x00, &net.TCPAddr{IP: net.IPv4zero, Port: 0})
			transport.Pipe(rc.Context(), c, up)
			return
		default: // direct
			proxySocks5Log.Debugf("direct (socks5 CONNECT) uid=%d to=%s", ar.UserId, p.target)
			replySocks5(c, 0x00, &net.TCPAddr{IP: net.IPv4zero, Port: 0})
			dst, err := limiter.DialTimeout("tcp", rr.Protocol, remote, p.target, rc.Context(), start, ar, rr)
			if err != nil {
				proxySocks5Log.Errorf("dial target error (socks5 CONNECT) %s -> %s : %v", remote, p.target, err)
				if rr.OnReject != nil {
					rr.OnReject(fmt.Sprintf("dial_target_err:%v", err), remote)
				}
				_ = c.Close()
				return
			}
			transport.Pipe(rc.Context(), c, dst)
			return
		}

	case socksCmdUDP:
		proxySocks5Log.Debugf("socks5 UDP associate uid=%d firstTarget=%s", ar.UserId, p.target)
		s5UDPAssociate(rc, ar, rr, c, remote, start, p.target)

	case socksCmdBind:
		proxySocks5Log.Debugf("socks5 BIND uid=%d target=%s", ar.UserId, p.target)
		s5Bind(rc, ar, rr, c, remote, p.target, start)

	default:
		proxySocks5Log.Debugf("socks5 unsupported cmd=%d from=%s", p.cmd, remote)
		replySocks5(c, 0x07, nil)
		_ = c.Close()
	}
}

/************** 客户端路径（固定上游） **************/

func handleSocks5Client(rc iface.RuntimeCtx, rr rule_runtime.RuleRuntime, c net.Conn) {
	start := time.Now().UnixMilli()
	remote := c.RemoteAddr().String()

	ar, p, ok := s5AuthHandshakeAndParse(rr, c)
	if !ok {
		return
	}

	// ✅ 无损刷新共享配额镜像
	limiter.GlobalUserQuotas.Refresh(ar.UserId, ar.Remain)

	// 注入用户限速
	limiter.AttachUserDownLimiters(c, ar)

	switch p.cmd {
	case socksCmdConnect:
		uctx := upstream.UpstreamCtx{RC: rc, RR: rr, AR: ar, Remote: remote, StartTime: start, Decision: policy.Decision{}}
		proxySocks5Log.Debugf("client socks5 CONNECT via=%s target=%s uid=%d", rr.TargetAddr, p.target, ar.UserId)
		up, err := upstream.ChooseDialer(rr.Protocol).OpenForConnect(uctx, rr.TargetAddr, p.target, "HTTP/1.1")
		if err != nil {
			proxySocks5Log.Errorf("upstream tunnel failed (client socks5 CONNECT) uid=%d: %v", ar.UserId, err)
			replySocks5(c, 0x05, nil)
			_ = c.Close()
			return
		}
		replySocks5(c, 0x00, &net.TCPAddr{IP: net.IPv4zero, Port: 0})
		transport.Pipe(rc.Context(), c, up)

	case socksCmdUDP:
		proxySocks5Log.Debugf("client socks5 UDP associate via=%s uid=%d", rr.TargetAddr, ar.UserId)
		s5UDPAssociate(rc, ar, rr, c, remote, start, p.target)

	case socksCmdBind:
		proxySocks5Log.Debugf("client socks5 BIND via=%s target=%s uid=%d", rr.TargetAddr, p.target, ar.UserId)
		s5Bind(rc, ar, rr, c, remote, p.target, start)

	default:
		proxySocks5Log.Debugf("client socks5 unsupported cmd=%d from=%s", p.cmd, remote)
		replySocks5(c, 0x07, nil)
		_ = c.Close()
	}
}

/************** UDP Associate **************/

func s5UDPAssociate(rc iface.RuntimeCtx, ar rule_runtime.AuthResult, rr rule_runtime.RuleRuntime, c net.Conn, remote string, startTime int64, firstTarget string) {
	// 每个会话独占一个本地 UDP 端口（:0）
	bindPort := rr.Socks5UDPPort
	if bindPort < 0 {
		bindPort = 0
	}
	udpAddr := &net.UDPAddr{IP: net.IPv4zero, Port: bindPort}
	pc, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		proxySocks5Log.Errorf("socks5 udp listen failed port=%d err=%v", bindPort, err)
		replySocks5(c, 0x01, nil)
		_ = c.Close()
		return
	}
	defer pc.Close()

	if baddr, ok := pc.LocalAddr().(*net.UDPAddr); ok {
		replySocks5(c, 0x00, &net.TCPAddr{IP: baddr.IP, Port: baddr.Port})
		proxySocks5Log.Debugf("socks5 udp bind=%s uid=%d", baddr.String(), ar.UserId)
	} else {
		replySocks5(c, 0x00, &net.TCPAddr{IP: net.IPv4zero, Port: 0})
	}

	// 限速/配额与通用 UDP 对齐
	limiter.GlobalUserQuotas.Refresh(ar.UserId, ar.Remain)
	uUp := limiter.GlobalUserLimiters.GetUp(ar.UserId)
	uDn := limiter.GlobalUserLimiters.GetDown(ar.UserId)
	perUpBps := common.MinNonZero(ar.UserUpLimit, rr.UpLimit)
	perUpBps = common.MinNonZero(perUpBps, ar.RuleUpLimit)
	perDnBps := common.MinNonZero(ar.UserDownLimit, rr.DownLimit)
	perDnBps = common.MinNonZero(perDnBps, ar.RuleDownLimit)
	upML := common.Compose(common.MkShaper(perUpBps, rr.UpLimit), uUp, rr.RuleSharedUpLimiter)
	dnML := common.Compose(common.MkShaper(perDnBps, rr.DownLimit), uDn, rr.RuleSharedDownLimiter)
	quota := limiter.GlobalUserQuotas.Get(ar.UserId)

	var upBytes, downBytes atomic.Int64
	fin := FinalizeAndLog(rr, ar.UserId, ar.Username, startTime, "udp", remote, rr.TargetAddr)

	ctx, cancel := context.WithCancel(rc.Context())
	defer cancel()

	// 上游 UDP（懒建且支持目标切换）
	var dst *net.UDPConn
	var dstMu sync.Mutex
	var cliAddrMu sync.Mutex
	var cliAddr *net.UDPAddr // 最近一次客户端地址，用于回写

	resolveUp := func(sendTo string) (*net.UDPConn, error) {
		raddr, e := net.ResolveUDPAddr("udp", sendTo)
		if e != nil {
			return nil, e
		}
		d, e := net.DialUDP("udp", nil, raddr)
		if e != nil {
			return nil, e
		}
		return d, nil
	}

	// client -> upstream
	go func() {
		buf := make([]byte, maxUDPPacket)
		for {
			if rr.ReadTimeout > 0 {
				_ = pc.SetReadDeadline(time.Now().Add(rr.ReadTimeout))
			} else {
				_ = pc.SetReadDeadline(time.Now().Add(readPoll))
			}
			n, ca, err := pc.ReadFromUDP(buf)
			if err != nil {
				// 良性关闭或轮询超时
				if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
					return
				}
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				proxySocks5Log.Debugf("udp read client failed: %v", err)
				cancel()
				return
			}

			cliAddrMu.Lock()
			cliAddr = ca
			cliAddrMu.Unlock()

			dstAddr, payload, err := parseSocks5UDPDatagram(buf[:n])
			if err != nil {
				proxySocks5Log.Debugf("udp parse datagram failed: %v", err)
				continue
			}
			// 目标选择
			sendTo := dstAddr
			if rr.TargetAddr != "" {
				sendTo = rr.TargetAddr
			} else if firstTarget != "" && dstAddr == "" {
				sendTo = firstTarget
			}

			// 限速（上行，整包）
			if upML != nil {
				if err := upML.WaitN(ctx, len(payload)); err != nil {
					if ctx.Err() != nil {
						return
					}
					continue
				}
			}
			// 配额（整包）：不足则丢包（不切片、不关闭）
			cr := quota.TryConsumeDetailed(len(payload))
			if !cr.Unlimited && cr.Allowed < len(payload) {
				proxySocks5Log.Debugf("udp quota drop up size=%d", len(payload))
				continue
			}

			// 懒建或切换上游
			dstMu.Lock()
			if dst == nil || (dst.RemoteAddr() != nil && dst.RemoteAddr().String() != sendTo) {
				if dst != nil {
					_ = dst.Close()
				}
				d, e := resolveUp(sendTo)
				if e != nil {
					dstMu.Unlock()
					proxySocks5Log.Debugf("udp resolve up failed sendTo=%s err=%v", sendTo, e)
					continue
				}
				dst = d
				proxySocks5Log.Debugf("udp upstream set %s", sendTo)
			}
			if rr.WriteTimeout > 0 {
				_ = dst.SetWriteDeadline(time.Now().Add(rr.WriteTimeout))
			} else {
				_ = dst.SetWriteDeadline(time.Now().Add(readPoll))
			}
			_, err = dst.Write(payload) // 整包
			dstMu.Unlock()
			if err != nil {
				if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
					return
				}
				proxySocks5Log.Debugf("udp write upstream failed: %v", err)
				cancel()
				return
			}

			upBytes.Add(int64(len(payload)))
		}
	}()

	// upstream -> client
	go func() {
		buf := make([]byte, maxUDPPacket)
		for {
			// 等待上游就绪
			dstMu.Lock()
			d := dst
			dstMu.Unlock()
			if d == nil {
				select {
				case <-time.After(50 * time.Millisecond):
					continue
				case <-ctx.Done():
					return
				}
			}

			if rr.ReadTimeout > 0 {
				_ = d.SetReadDeadline(time.Now().Add(rr.ReadTimeout))
			} else {
				_ = d.SetReadDeadline(time.Now().Add(readPoll))
			}
			n, src, err := d.ReadFromUDP(buf)
			if err != nil {
				if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
					return
				}
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				proxySocks5Log.Debugf("udp read upstream failed: %v", err)
				cancel()
				return
			}

			// 限速（下行，整包）
			if dnML != nil {
				if err := dnML.WaitN(ctx, n); err != nil {
					if ctx.Err() != nil {
						return
					}
					continue
				}
			}
			// 配额（整包）：不足则丢包
			cr := quota.TryConsumeDetailed(n)
			if !cr.Unlimited && cr.Allowed < n {
				proxySocks5Log.Debugf("udp quota drop down size=%d", n)
				continue
			}

			reply := buildSocks5UDPDatagram(src.String(), buf[:n]) // 整包

			cliAddrMu.Lock()
			ca := cliAddr
			cliAddrMu.Unlock()
			if ca == nil {
				continue
			}

			if rr.WriteTimeout > 0 {
				_ = pc.SetWriteDeadline(time.Now().Add(rr.WriteTimeout))
			} else {
				_ = pc.SetWriteDeadline(time.Now().Add(readPoll))
			}
			if _, err := pc.WriteToUDP(reply, ca); err != nil {
				if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
					return
				}
				proxySocks5Log.Debugf("udp write client failed: %v", err)
				cancel()
				return
			}
			downBytes.Add(int64(n))
		}
	}()

	// 占用 TCP 控制连接直至关闭
	tmp := make([]byte, 1)
	for {
		if _, err := c.Read(tmp); err != nil {
			break
		}
	}
	fin(upBytes.Load(), downBytes.Load())

	dstMu.Lock()
	if dst != nil {
		_ = dst.Close()
	}
	dstMu.Unlock()
	_ = c.Close()
}

/************** BIND **************/

func s5Bind(rc iface.RuntimeCtx, ar rule_runtime.AuthResult, rr rule_runtime.RuleRuntime, c net.Conn, remote, target string, startTime int64) {
	bindPort := rr.Socks5BindPort
	if bindPort < 0 {
		bindPort = 0
	}
	bindAddr := fmt.Sprintf("0.0.0.0:%d", bindPort)
	ln, err := net.Listen("tcp", bindAddr)
	if err != nil {
		proxySocks5Log.Errorf("socks5 bind listen failed bind=%s err=%v", bindAddr, err)
		replySocks5(c, 0x01, nil)
		_ = c.Close()
		return
	}
	defer ln.Close()

	if tcp, _ := ln.Addr().(*net.TCPAddr); tcp != nil {
		replySocks5(c, 0x00, tcp)
		proxySocks5Log.Debugf("socks5 bind ready bind=%s uid=%d", tcp.String(), ar.UserId)
	} else {
		replySocks5(c, 0x00, &net.TCPAddr{IP: net.IPv4zero, Port: 0})
	}

	peer, err := limiter.AcceptWithContext(rc.Context(), ln)
	if err != nil {
		_ = c.Close()
		return
	}
	defer peer.Close()

	if tcp, _ := peer.LocalAddr().(*net.TCPAddr); tcp != nil {
		replySocks5(c, 0x00, tcp)
	} else {
		replySocks5(c, 0x00, &net.TCPAddr{IP: net.IPv4zero, Port: 0})
	}

	if rr.TargetAddr != "" {
		dst, err := limiter.DialTimeout("tcp", rr.Protocol, remote, rr.TargetAddr, rc.Context(), startTime, ar, rr)
		if err != nil {
			proxySocks5Log.Errorf("socks5 bind dial upstream failed: %v", err)
			_ = c.Close()
			return
		}
		defer dst.Close()
		transport.Pipe(rc.Context(), peer, dst)
	} else if target != "" {
		dst, err := limiter.DialTimeout("tcp", rr.Protocol, remote, target, rc.Context(), startTime, ar, rr)
		if err != nil {
			proxySocks5Log.Errorf("socks5 bind dial target failed: %v", err)
			_ = c.Close()
			return
		}
		defer dst.Close()
		transport.Pipe(rc.Context(), peer, dst)
	} else {
		// peer <-> mbp（标准 SOCKS5 BIND）
		// 对“客户端上行”（mbp -> peer）做用户/规则级上行限速；下行仍由 CountingConn 控
		upML := buildUplinkLimiter(rr, ar)
		pipeWithUplinkLimit(rc.Context(), c, peer, upML)
	}
}

// 组合“上行”限速器：单连接整形 + 用户共享 + 规则共享（上行）
func buildUplinkLimiter(rr rule_runtime.RuleRuntime, ar rule_runtime.AuthResult) common.MultiLimiter {
	uUp := limiter.GlobalUserLimiters.GetUp(ar.UserId) // 用户共享上行
	per := common.MinNonZero(ar.UserUpLimit, rr.UpLimit)
	per = common.MinNonZero(per, ar.RuleUpLimit)
	shaper := common.MkShaper(per, rr.UpLimit)
	return common.Compose(shaper, uUp, rr.RuleSharedUpLimiter) // Compose 内部会忽略 nil
}

// 仅对 client->upstream 方向施加上行限速；另一方向保持原样（CountingConn 管下行）
func pipeWithUplinkLimit(ctx context.Context, client net.Conn, upstream net.Conn, upML common.MultiLimiter) {
	// 上行：client -> upstream
	go func() {
		buf := make([]byte, 64*1024)
		for {
			_ = client.SetReadDeadline(time.Now().Add(5 * time.Minute))
			n, rerr := client.Read(buf)
			if n > 0 {
				if upML != nil {
					if err := upML.WaitN(ctx, n); err != nil {
						_ = upstream.Close()
						return
					}
				}
				_ = upstream.SetWriteDeadline(time.Now().Add(5 * time.Minute))
				if _, werr := upstream.Write(buf[:n]); werr != nil {
					_ = client.Close()
					return
				}
			}
			if rerr != nil {
				_ = upstream.Close()
				return
			}
		}
	}()

	// 下行：upstream -> client（仍由 CountingConn 的下行 limiter 生效）
	buf := make([]byte, 64*1024)
	for {
		_ = upstream.SetReadDeadline(time.Now().Add(5 * time.Minute))
		n, rerr := upstream.Read(buf)
		if n > 0 {
			_ = client.SetWriteDeadline(time.Now().Add(5 * time.Minute))
			if _, werr := client.Write(buf[:n]); werr != nil {
				_ = upstream.Close()
				return
			}
		}
		if rerr != nil {
			_ = client.Close()
			return
		}
	}
}

/************** 工具：读/写地址 & UDP 编解码 **************/

func replySocks5(c net.Conn, rep byte, bind *net.TCPAddr) {
	if bind == nil {
		_, _ = c.Write([]byte{socksVer5, rep, 0x00, atypeIPv4, 0, 0, 0, 0, 0, 0})
		return
	}
	ip4 := bind.IP.To4()
	atyp := atypeIPv4
	addr := ip4
	if ip4 == nil {
		atyp = atypeIPv6
		addr = bind.IP
	}
	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, uint16(bind.Port))
	_ = c.SetWriteDeadline(time.Now().Add(3 * time.Second))
	_, _ = c.Write(append([]byte{socksVer5, rep, 0x00, byte(atyp)}, append(addr, port...)...))
}

func parseSocks5UDPDatagram(pkt []byte) (dst string, payload []byte, err error) {
	if len(pkt) < 4 {
		return "", nil, errors.New("short udp header")
	}
	if pkt[2] != 0x00 {
		return "", nil, errors.New("fragment not supported")
	}
	atyp := pkt[3]
	p := 4
	switch atyp {
	case atypeIPv4:
		if len(pkt) < p+4+2 {
			return "", nil, errors.New("short v4")
		}
		ip := net.IP(pkt[p : p+4]).String()
		p += 4
		port := int(binary.BigEndian.Uint16(pkt[p : p+2]))
		p += 2
		dst = net.JoinHostPort(ip, strconv.Itoa(port))
	case atypeDomain:
		if len(pkt) < p+1 {
			return "", nil, errors.New("short dom len")
		}
		l := int(pkt[p])
		p++
		if len(pkt) < p+l+2 {
			return "", nil, errors.New("short dom")
		}
		host := string(pkt[p : p+l])
		p += l
		port := int(binary.BigEndian.Uint16(pkt[p : p+2]))
		p += 2
		dst = net.JoinHostPort(host, strconv.Itoa(port))
	case atypeIPv6:
		if len(pkt) < p+16+2 {
			return "", nil, errors.New("short v6")
		}
		ip := net.IP(pkt[p : p+16]).String()
		p += 16
		port := int(binary.BigEndian.Uint16(pkt[p : p+2]))
		p += 2
		dst = net.JoinHostPort(ip, strconv.Itoa(port))
	default:
		return "", nil, errors.New("bad atyp")
	}
	if len(pkt) < p {
		return "", nil, errors.New("payload underflow")
	}
	return dst, pkt[p:], nil
}

func buildSocks5UDPDatagram(dst string, payload []byte) []byte {
	host, port := common.SplitHostPortFlexible(dst, 0)
	var hdr []byte
	ip := net.ParseIP(host)
	if ip4 := ip.To4(); ip4 != nil {
		hdr = append([]byte{0, 0, 0, atypeIPv4}, ip4...)
	} else if ip != nil {
		hdr = append([]byte{0, 0, 0, atypeIPv6}, ip...)
	} else {
		h := []byte(host)
		hdr = append([]byte{0, 0, 0, atypeDomain, byte(len(h))}, h...)
	}
	pb := make([]byte, 2)
	binary.BigEndian.PutUint16(pb, uint16(port))
	hdr = append(hdr, pb...)
	return append(hdr, payload...)
}

/* ---------- 统计工具（保持不变） ---------- */

func FinalizeAndLog(
	rr rule_runtime.RuleRuntime,
	uid int64,
	username string,
	startTime int64,
	proto string,
	remote string,
	target string,
) func(up, down int64) {
	lh, lp, sh, sp, th, tp := common.ParseAddrPorts(rr.ListenAddr, remote, target)
	return func(up, down int64) {
		if rr.OnFinish == nil {
			return
		}
		rr.OnFinish(uid, model.TrafficLog{
			Time:       time.Now().UnixMilli(),
			Username:   username,
			Direction:  "出站",
			ListenAddr: lh,
			ListenPort: lp,
			Protocol:   proto,
			Up:         up,
			Down:       down,
			Dur:        time.Now().UnixMilli() - startTime,
			SourceAddr: sh,
			SourcePort: sp,
			TargetAddr: th,
			TargetPort: tp,
		})
	}
}
