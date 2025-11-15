package upstream

import (
	"fmt"
	"io"
	"mlkmbp/mbp/common"
	"mlkmbp/mbp/core/limiter"
	"mlkmbp/mbp/core/upstream/tlsauto"
	"net"
	"net/url"
)

/************** SOCKS5 代理 Dialer（调用 tlsauto） **************/

type socks5Dialer struct{}

const (
	s5MethodNoAuth   = 0x00
	s5MethodUserPass = 0x02
)

func (d socks5Dialer) OpenForConnect(uctx UpstreamCtx, upstreamAddr, targetHostPort, _ string) (net.Conn, error) {
	host, port := common.SplitHostPortDefault(targetHostPort, 0)
	if host == "" || port <= 0 {
		return nil, fmt.Errorf("bad targetHostPort %q", targetHostPort)
	}
	return socks5ConnectWithAuth(uctx, upstreamAddr, host, port)
}

func (d socks5Dialer) OpenForHTTPNonConnect(uctx UpstreamCtx, upstreamAddr string, u *url.URL, _ string) (net.Conn, bool, error) {
	host, port := common.SplitHostPortDefault(u.Host, 0)
	if host == "" || port <= 0 {
		return nil, false, fmt.Errorf("bad http target %q", u.Host)
	}
	c, err := socks5ConnectWithAuth(uctx, upstreamAddr, host, port)
	return c, true, err
}

func socks5ConnectWithAuth(uctx UpstreamCtx, upstreamAddr, host string, port int) (net.Conn, error) {
	upstreamLog.Debugf("[socks5] dial upstream=%s target=%s:%d", upstreamAddr, host, port)

	up, _, err := tlsauto.AdaptiveDialTCP(
		func() (net.Conn, error) {
			return limiter.DialTimeout("tcp", uctx.RR.Protocol, uctx.Remote, upstreamAddr, uctx.RC.Context(), uctx.StartTime, uctx.AR, uctx.RR)
		},
		makeTLSConfig(uctx, upstreamAddr),
		upstreamAddr,
		nil,
	)

	if err != nil {
		return nil, fmt.Errorf("socks5 dial upstream: %w", err)
	}

	// 同时宣告 NO-AUTH 与 USER/PASS
	if _, err := up.Write([]byte{0x05, 0x02, s5MethodNoAuth, s5MethodUserPass}); err != nil {
		_ = up.Close()
		return nil, fmt.Errorf("socks5 greeting write: %w", err)
	}
	gr := make([]byte, 2)
	if _, err := io.ReadFull(up, gr); err != nil || gr[0] != 0x05 {
		_ = up.Close()
		return nil, fmt.Errorf("socks5 greeting read: %w ver=%#x", err, gr[0])
	}

	method := gr[1]
	switch method {
	case s5MethodNoAuth:
		upstreamLog.Debugf("[socks5] server selected NO-AUTH (0x00)")
	case s5MethodUserPass:
		user, pass := PickCreds(uctx)
		if len(user) > 255 || len(pass) > 255 {
			_ = up.Close()
			return nil, fmt.Errorf("socks5 creds too long (user=%d, pass=%d)", len(user), len(pass))
		}
		upstreamLog.Debugf("[socks5] server selected USER/PASS (0x02) haveUser=%t havePass=%t", user != "", pass != "")
		if _, err := up.Write([]byte{0x01, byte(len(user))}); err != nil {
			_ = up.Close()
			return nil, fmt.Errorf("socks5 auth write(ver/ulen): %w", err)
		}
		if _, err := up.Write([]byte(user)); err != nil {
			_ = up.Close()
			return nil, fmt.Errorf("socks5 auth write(user): %w", err)
		}
		if _, err := up.Write([]byte{byte(len(pass))}); err != nil {
			_ = up.Close()
			return nil, fmt.Errorf("socks5 auth write(plen): %w", err)
		}
		if _, err := up.Write([]byte(pass)); err != nil {
			_ = up.Close()
			return nil, fmt.Errorf("socks5 auth write(pass): %w", err)
		}
		verstat := make([]byte, 2)
		if _, err := io.ReadFull(up, verstat); err != nil {
			_ = up.Close()
			return nil, fmt.Errorf("socks5 auth read: %w", err)
		}
		if verstat[0] != 0x01 || verstat[1] != 0x00 {
			_ = up.Close()
			return nil, fmt.Errorf("socks5 auth failed (status=%#x)", verstat[1])
		}
	default:
		if method == 0xFF {
			_ = up.Close()
			return nil, fmt.Errorf("socks5 no acceptable auth methods (0xFF)")
		}
		_ = up.Close()
		return nil, fmt.Errorf("socks5 unsupported method selected by server: %#x", method)
	}

	// CONNECT
	var atyp byte
	var addr []byte
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			atyp, addr = 0x01, v4
		} else {
			atyp, addr = 0x04, ip.To16()
		}
	} else {
		atyp = 0x03
		addr = append([]byte{byte(len(host))}, []byte(host)...)
	}
	req := append([]byte{0x05, 0x01, 0x00, atyp}, addr...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := up.Write(req); err != nil {
		_ = up.Close()
		return nil, fmt.Errorf("socks5 connect write: %w", err)
	}
	upstreamLog.Debugf("[socks5] CONNECT to %s:%d atyp=%#x", host, port, atyp)

	h := make([]byte, 4)
	if _, err := io.ReadFull(up, h); err != nil {
		_ = up.Close()
		return nil, fmt.Errorf("socks5 connect resp: %w", err)
	}
	if h[1] != 0x00 {
		rep := h[1]
		_ = up.Close()
		return nil, fmt.Errorf("socks5 connect refused rep=%#x", rep)
	}
	// 跳过 BND.ADDR + BND.PORT
	var skip int
	switch h[3] {
	case 0x01:
		skip = 4
	case 0x04:
		skip = 16
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(up, l); err != nil {
			_ = up.Close()
			return nil, err
		}
		skip = int(l[0])
	default:
		_ = up.Close()
		return nil, fmt.Errorf("socks5 bad atyp=%#x in resp", h[3])
	}
	if _, err := io.CopyN(io.Discard, up, int64(skip+2)); err != nil {
		_ = up.Close()
		return nil, err
	}
	upstreamLog.Debugf("[socks5] CONNECT established")
	return up, nil
}
