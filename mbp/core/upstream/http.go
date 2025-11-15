package upstream

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"mlkmbp/mbp/core/limiter"
	"mlkmbp/mbp/core/upstream/tlsauto"
	"net"
	"net/url"
	"strings"
)

/************** HTTP 代理 Dialer（调用 tlsauto） **************/

type httpProxyDialer struct{}

func (d httpProxyDialer) OpenForConnect(uctx UpstreamCtx, upstreamAddr, targetHostPort, httpProto string) (net.Conn, error) {
	upstreamLog.Debugf("[http] dial upstream=%s connect=%s", upstreamAddr, targetHostPort)

	up, _, err := tlsauto.AdaptiveDialTCP(
		func() (net.Conn, error) {
			return limiter.DialTimeout("tcp", uctx.RR.Protocol, uctx.Remote, upstreamAddr, uctx.RC.Context(), uctx.StartTime, uctx.AR, uctx.RR)
		},
		makeTLSConfig(uctx, upstreamAddr),
		upstreamAddr,
		nil,
	)

	if err != nil {
		return nil, fmt.Errorf("dial upstream http: %w", err)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "CONNECT %s %s\r\nHost: %s\r\n", targetHostPort, httpProto, targetHostPort)
	if u, p := PickCreds(uctx); u != "" || p != "" {
		cred := base64.StdEncoding.EncodeToString([]byte(u + ":" + p))
		b.WriteString("Proxy-Authorization: Basic " + cred + "\r\n")
	}
	b.WriteString("\r\n")
	if _, err := io.WriteString(up, b.String()); err != nil {
		_ = up.Close()
		return nil, fmt.Errorf("send CONNECT: %w", err)
	}

	br := bufio.NewReader(up)
	status, err := br.ReadString('\n')
	if err != nil || !strings.HasPrefix(status, "HTTP/") || !strings.Contains(status, " 200 ") {
		_ = drainHTTPHeaders(br)
		_ = up.Close()
		return nil, fmt.Errorf("upstream CONNECT rejected: %q", strings.TrimSpace(status))
	}
	_ = drainHTTPHeaders(br)
	upstreamLog.Debugf("[http] CONNECT established via %s", upstreamAddr)
	return up, nil
}

func drainHTTPHeaders(r *bufio.Reader) error {
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return err
		}
		if strings.TrimRight(line, "\r\n") == "" {
			return nil
		}
	}
}

func (d httpProxyDialer) OpenForHTTPNonConnect(uctx UpstreamCtx, upstreamAddr string, _ *url.URL, _ string) (net.Conn, bool, error) {
	upstreamLog.Debugf("[http] dial upstream(non-CONNECT) upstream=%s", upstreamAddr)

	up, _, err := tlsauto.AdaptiveDialTCP(
		func() (net.Conn, error) {
			return limiter.DialTimeout("tcp", uctx.RR.Protocol, uctx.Remote, upstreamAddr, uctx.RC.Context(), uctx.StartTime, uctx.AR, uctx.RR)
		},
		makeTLSConfig(uctx, upstreamAddr),
		upstreamAddr,
		nil,
	)

	if err != nil {
		return nil, false, fmt.Errorf("dial upstream http: %w", err)
	}
	return up, false, nil
}
