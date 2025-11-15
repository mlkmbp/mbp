package proxy

import (
	"bufio"
	"encoding/base64"
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
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

/************** 组件日志 **************/

var proxyHttpLog = logx.New(logx.WithPrefix("proxy.http"))

/************** 轻量 header 容器 **************/

type httpHeader map[string]string

// 非 CONNECT 的 HTTP 代理请求需要在请求头里携带 Proxy-Authorization
func ensureUpstreamProxyAuthHeader(h httpHeader, user, pass string) {
	if user == "" && pass == "" {
		return
	}
	// 已有就不覆盖
	if _, ok := h["proxy-authorization"]; ok {
		return
	}
	cred := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
	h["proxy-authorization"] = "Basic " + cred
	proxyHttpLog.Debugf("inject upstream proxy auth header (basic)")
}

/************** 入口：先只读请求行+头；两分支内再做鉴权 **************/

func HandleHTTP(rc iface.RuntimeCtx, rr rule_runtime.RuleRuntime, c net.Conn) {
	// 仅解析请求行+头（未鉴权）
	p, ok := readParseNoAuth(c)
	if !ok {
		return
	}

	mode := "server"
	if rr.TargetAddr != "" {
		mode = "client"
	}
	proxyHttpLog.Debugf("[%s] %s %s %s from=%s", mode, p.method, p.reqURI, p.proto, c.RemoteAddr())

	if rr.TargetAddr == "" {
		handleHTTPServer(rc, rr, c, p)
	} else {
		handleHTTPClient(rc, rr, c, p)
	}
}

/************** 解析（不鉴权） **************/

type httpParsed struct {
	br      *bufio.Reader
	method  string
	reqURI  string
	proto   string
	headers httpHeader
}

func readParseNoAuth(c net.Conn) (p httpParsed, ok bool) {
	br := bufio.NewReaderSize(c, 32*1024)
	reqLine, err := br.ReadString('\n')
	if err != nil {
		proxyHttpLog.Debugf("read request line failed from %s: %v", c.RemoteAddr(), err)
		_ = c.Close()
		return p, false
	}
	m, u, pr, ok2 := parseRequestLine(reqLine)
	if !ok2 {
		proxyHttpLog.Debugf("invalid request line from %s: %q", c.RemoteAddr(), strings.TrimSpace(reqLine))
		writeHTTPAndClose(c, http.StatusBadRequest, "Bad Request", "invalid request line")
		return p, false
	}
	h, err := readHeaders(br)
	if err != nil {
		proxyHttpLog.Debugf("read headers failed from %s: %v", c.RemoteAddr(), err)
		_ = c.Close()
		return p, false
	}
	return httpParsed{br: br, method: m, reqURI: u, proto: pr, headers: h}, true
}

/************** 公共：鉴权+注入用户限速器 **************/

func authenticateAndAttach(rr rule_runtime.RuleRuntime, c net.Conn, headers httpHeader, remote string) (ar rule_runtime.AuthResult, ok bool) {
	user, pass, haveBasic := parseProxyBasic(headers.Get("Proxy-Authorization"))
	if !haveBasic {
		proxyHttpLog.Debugf("missing Proxy-Authorization from %s", remote)
		_ = writeRaw(c, "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"\"\r\nContent-Length: 0\r\n\r\n")
		return ar, false
	}

	ar = rr.Auth(common.RemoteIPFromConn(c), user, pass, 0, 0)
	if !ar.OK {
		switch ar.Reason {
		case rule_runtime.AuthMissing, rule_runtime.AuthBadCredentials:
			_ = writeRaw(c, "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"\"\r\nContent-Length: 0\r\n\r\n")
			proxyHttpLog.Debugf("auth failed (407) user=%q ip=%s reason=%s", user, common.RemoteIPFromConn(c), ar.Reason)
		case rule_runtime.AuthNotAuthorizedForRule, rule_runtime.AuthQuotaExceeded, rule_runtime.AuthUserDisabledOrExpired, rule_runtime.AuthUserExpired:
			writeHTTPAndClose(c, http.StatusForbidden, "Forbidden", string(ar.Reason))
			proxyHttpLog.Debugf("auth forbidden (403) user=%q ip=%s reason=%s", user, common.RemoteIPFromConn(c), ar.Reason)
		default:
			writeHTTPAndClose(c, http.StatusInternalServerError, "Internal Server Error", "auth internal error")
			proxyHttpLog.Debugf("auth internal error user=%q ip=%s", user, common.RemoteIPFromConn(c))
		}
		if rr.OnReject != nil {
			reason := string(ar.Reason)
			if reason == "" {
				reason = "auth_failed"
			}
			rr.OnReject(reason, remote)
		}
		return ar, false
	}

	// 注入用户限速（如果监听侧用 CountingConn 包裹）
	limiter.AttachUserDownLimiters(c, ar)
	proxyHttpLog.Debugf("auth ok user=%q uid=%d ip=%s", ar.Username, ar.UserId, common.RemoteIPFromConn(c))
	return ar, true
}

/************** 服务端（rr.TargetAddr==""） **************/

func handleHTTPServer(rc iface.RuntimeCtx, rr rule_runtime.RuleRuntime, c net.Conn, p httpParsed) {
	start := time.Now().UnixMilli()
	remote := c.RemoteAddr().String()

	ar, ok := authenticateAndAttach(rr, c, p.headers, remote)
	if !ok {
		return
	}

	// CONNECT：按策略
	if strings.EqualFold(p.method, "CONNECT") {
		host, port := common.SplitHostPortDefault(p.reqURI, 443)
		if host == "" || port <= 0 || port > 65535 {
			writeHTTPAndClose(c, http.StatusBadRequest, "Bad Request", "invalid CONNECT host")
			return
		}
		target := net.JoinHostPort(host, strconv.Itoa(port))
		proxyHttpLog.Debugf("CONNECT target=%s user=%q uid=%d", target, ar.Username, ar.UserId)

		dec, err := rr.Decider.Decide(ar.UserId, rr.UserId, rr.RuleId, target)
		if err != nil {
			proxyHttpLog.Debugf("policy decide error (CONNECT) target=%s: %v", target, err)
			writeHTTPAndClose(c, http.StatusInternalServerError, "Internal Server Error", "policy decide error")
			return
		}
		switch dec.Action {
		case model.ActionReject:
			proxyHttpLog.Debugf("policy reject (CONNECT) uid=%d target=%s", ar.UserId, target)
			writeHTTPAndClose(c, http.StatusForbidden, "Forbidden", "blocked by policy")
			return
		case model.ActionForward:
			upAddr := dec.TargetAddress
			if upAddr == "" {
				upAddr = rr.TargetAddr
			}
			proxyHttpLog.Debugf("policy forward (CONNECT) uid=%d via=%s to=%s proto=%s", ar.UserId, upAddr, target, dec.Protocol)
			uctx := upstream.UpstreamCtx{RC: rc, RR: rr, AR: ar, Remote: remote, StartTime: start, Decision: dec}
			up, err := upstream.ChooseDialer(dec.Protocol).OpenForConnect(uctx, upAddr, target, p.proto)
			if err != nil {
				proxyHttpLog.Errorf("upstream tunnel failed (CONNECT) uid=%d: %v", ar.UserId, err)
				writeHTTPAndClose(c, http.StatusBadGateway, "Bad Gateway", "upstream tunnel failed")
				return
			}
			_, _ = io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
			transport.Pipe(rc.Context(), c, up)
			return
		default: // direct
			proxyHttpLog.Debugf("direct (CONNECT) uid=%d to=%s", ar.UserId, target)
			if _, err := io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
				_ = c.Close()
				return
			}
			dst, err := limiter.DialTimeout("tcp", rr.Protocol, remote, target, rc.Context(), start, ar, rr)
			if err != nil {
				proxyHttpLog.Errorf("dial target error (CONNECT) %s -> %s : %v", remote, target, err)
				if rr.OnReject != nil {
					rr.OnReject(fmt.Sprintf("dial_target_err:%v", err), remote)
				}
				_ = c.Close()
				return
			}
			transport.Pipe(rc.Context(), c, dst)
			return
		}
	}

	// 非 CONNECT：absolute-form
	u, err := url.Parse(p.reqURI)
	if err != nil || u.Scheme == "" || u.Host == "" {
		writeHTTPAndClose(c, http.StatusBadRequest, "Bad Request", "invalid absolute-form URL")
		return
	}
	host, port := common.SplitHostPortDefault(u.Host, 80)
	if host == "" || port <= 0 || port > 65535 {
		writeHTTPAndClose(c, http.StatusBadRequest, "Bad Request", "invalid target host")
		return
	}
	target := net.JoinHostPort(host, strconv.Itoa(port))
	proxyHttpLog.Debugf("%s absolute-form target=%s user=%q uid=%d", p.method, target, ar.Username, ar.UserId)

	dec, err := rr.Decider.Decide(ar.UserId, rr.UserId, rr.RuleId, target)
	if err != nil {
		proxyHttpLog.Errorf("policy decide error (HTTP) target=%s: %v", target, err)
		writeHTTPAndClose(c, http.StatusInternalServerError, "Internal Server Error", "policy decide error")
		return
	}

	switch dec.Action {
	case model.ActionReject:
		proxyHttpLog.Debugf("policy reject (HTTP) uid=%d target=%s", ar.UserId, target)
		writeHTTPAndClose(c, http.StatusForbidden, "Forbidden", "blocked by policy")
		return

	case model.ActionForward:
		upAddr := dec.TargetAddress
		if upAddr == "" {
			upAddr = rr.TargetAddr
		}
		proxyHttpLog.Debugf("policy forward (HTTP) uid=%d via=%s to=%s proto=%s", ar.UserId, upAddr, target, dec.Protocol)
		uctx := upstream.UpstreamCtx{RC: rc, RR: rr, AR: ar, Remote: remote, StartTime: start, Decision: dec}
		dialer := upstream.ChooseDialer(dec.Protocol)
		up, needOrigin, err := dialer.OpenForHTTPNonConnect(uctx, upAddr, u, p.proto)
		if err != nil {
			proxyHttpLog.Errorf("open upstream failed (HTTP) uid=%d: %v", ar.UserId, err)
			writeHTTPAndClose(c, http.StatusBadGateway, "Bad Gateway", "open upstream failed")
			return
		}
		stripProxyHeaders(p.headers)
		if !needOrigin { // HTTP 代理
			u2, pw := upstream.PickCreds(upstream.UpstreamCtx{RR: rr, AR: ar, Decision: dec})
			ensureUpstreamProxyAuthHeader(p.headers, u2, pw)
			if err := forwardAbsoluteWithBuffered(up, p.method, p.reqURI, p.proto, p.headers, p.br); err != nil {
				_ = up.Close()
				_ = c.Close()
				return
			}
		} else { // SOCKS5 代理（已连到目标）
			if err := forwardOriginFormWithBuffered(up, p.method, u, p.proto, p.headers, p.br); err != nil {
				_ = up.Close()
				_ = c.Close()
				return
			}
		}
		transport.Pipe(rc.Context(), c, up)
		return

	default: // direct
		proxyHttpLog.Debugf("direct (HTTP) uid=%d to=%s", ar.UserId, target)
		dst, err := limiter.DialTimeout("tcp", rr.Protocol, remote, target, rc.Context(), start, ar, rr)
		if err != nil {
			proxyHttpLog.Errorf("dial target error (HTTP) %s -> %s : %v", remote, target, err)
			writeHTTPAndClose(c, http.StatusBadGateway, "Bad Gateway", "dial target error")
			if rr.OnReject != nil {
				rr.OnReject(fmt.Sprintf("dial_target_err:%v", err), remote)
			}
			_ = c.Close()
			return
		}
		stripProxyHeaders(p.headers)
		if err := forwardOriginFormWithBuffered(dst, p.method, u, p.proto, p.headers, p.br); err != nil {
			_ = dst.Close()
			_ = c.Close()
			return
		}
		transport.Pipe(rc.Context(), c, dst)
		return
	}
}

/************** 客户端（rr.TargetAddr!=""） **************/

func handleHTTPClient(rc iface.RuntimeCtx, rr rule_runtime.RuleRuntime, c net.Conn, p httpParsed) {
	start := time.Now().UnixMilli()
	remote := c.RemoteAddr().String()

	ar, ok := authenticateAndAttach(rr, c, p.headers, remote)
	if !ok {
		return
	}

	upAddr := rr.TargetAddr
	uctx := upstream.UpstreamCtx{RC: rc, RR: rr, AR: ar, Remote: remote, StartTime: start, Decision: policy.Decision{}}
	dialer := upstream.ChooseDialer(rr.Protocol)

	if strings.EqualFold(p.method, "CONNECT") {
		host, port := common.SplitHostPortDefault(p.reqURI, 443)
		if host == "" || port <= 0 || port > 65535 {
			writeHTTPAndClose(c, http.StatusBadRequest, "Bad Request", "invalid CONNECT host")
			return
		}
		hostport := net.JoinHostPort(host, strconv.Itoa(port))
		proxyHttpLog.Debugf("client CONNECT via=%s target=%s user=%q uid=%d", upAddr, hostport, ar.Username, ar.UserId)

		up, err := dialer.OpenForConnect(uctx, upAddr, hostport, p.proto)
		if err != nil {
			proxyHttpLog.Errorf("upstream tunnel failed (client CONNECT) uid=%d: %v", ar.UserId, err)
			writeHTTPAndClose(c, http.StatusBadGateway, "Bad Gateway", "upstream tunnel failed")
			return
		}
		_, _ = io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
		transport.Pipe(rc.Context(), c, up)
		return
	}

	u, err := url.Parse(p.reqURI)
	if err != nil || u.Scheme == "" || u.Host == "" {
		writeHTTPAndClose(c, http.StatusBadRequest, "Bad Request", "invalid absolute-form URL")
		return
	}
	proxyHttpLog.Debugf("client %s via=%s url=%s user=%q uid=%d", p.method, upAddr, p.reqURI, ar.Username, ar.UserId)

	up, needOrigin, err := dialer.OpenForHTTPNonConnect(uctx, upAddr, u, p.proto)
	if err != nil {
		proxyHttpLog.Errorf("open upstream failed (client HTTP) uid=%d: %v", ar.UserId, err)
		writeHTTPAndClose(c, http.StatusBadGateway, "Bad Gateway", "open upstream failed")
		return
	}

	stripProxyHeaders(p.headers)
	if !needOrigin { // HTTP 代理
		u2, pw := upstream.PickCreds(upstream.UpstreamCtx{RR: rr, AR: ar, Decision: policy.Decision{}})
		ensureUpstreamProxyAuthHeader(p.headers, u2, pw)
		if err := forwardAbsoluteWithBuffered(up, p.method, p.reqURI, p.proto, p.headers, p.br); err != nil {
			_ = up.Close()
			_ = c.Close()
			return
		}
	} else { // SOCKS5 上游（origin-form）
		if err := forwardOriginFormWithBuffered(up, p.method, u, p.proto, p.headers, p.br); err != nil {
			_ = up.Close()
			_ = c.Close()
			return
		}
	}
	transport.Pipe(rc.Context(), c, up)
}

/************** 写请求（带上 br 缓冲的 body 片段） **************/

func forwardOriginFormWithBuffered(dst net.Conn, method string, u *url.URL, proto string, headers httpHeader, br *bufio.Reader) error {
	path := u.RequestURI()
	if u.Opaque != "" {
		path = u.Opaque
	}
	if path == "" {
		path = "/"
	}
	if _, err := fmt.Fprintf(dst, "%s %s %s\r\n", method, path, proto); err != nil {
		return err
	}
	host := u.Host
	if h, p := common.SplitHostPortDefault(u.Host, 80); h != "" && p > 0 {
		host = net.JoinHostPort(h, strconv.Itoa(p))
	}
	w := bufio.NewWriter(dst)
	for k, v := range headers {
		if strings.EqualFold(k, "host") {
			v = host
		}
		if _, err := w.WriteString(canonHeaderKey(k) + ": " + v + "\r\n"); err != nil {
			return err
		}
	}
	if _, err := w.WriteString("\r\n"); err != nil {
		return err
	}
	if n := br.Buffered(); n > 0 {
		if _, err := io.CopyN(w, br, int64(n)); err != nil {
			return err
		}
	}
	return w.Flush()
}

func forwardAbsoluteWithBuffered(dst net.Conn, method, reqURI, proto string, headers httpHeader, br *bufio.Reader) error {
	if _, err := fmt.Fprintf(dst, "%s %s %s\r\n", method, reqURI, proto); err != nil {
		return err
	}
	w := bufio.NewWriter(dst)
	for k, v := range headers {
		if _, err := w.WriteString(canonHeaderKey(k) + ": " + v + "\r\n"); err != nil {
			return err
		}
	}
	if _, err := w.WriteString("\r\n"); err != nil {
		return err
	}
	if n := br.Buffered(); n > 0 {
		if _, err := io.CopyN(w, br, int64(n)); err != nil {
			return err
		}
	}
	return w.Flush()
}

/************** 工具 **************/

func (h httpHeader) Get(k string) string { return h[strings.ToLower(k)] }

func stripProxyHeaders(h httpHeader) {
	for _, k := range []string{"proxy-authorization", "proxy-connection"} {
		delete(h, k)
	}
	proxyHttpLog.Debugf("strip proxy headers (Proxy-Authorization/Proxy-Connection)")
}

func readHeaders(br *bufio.Reader) (httpHeader, error) {
	h := make(httpHeader)
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			return h, nil
		}
		if i := strings.IndexByte(line, ':'); i > 0 {
			k := strings.ToLower(strings.TrimSpace(line[:i]))
			v := strings.TrimSpace(line[i+1:])
			h[k] = v
		}
	}
}

func parseProxyBasic(h string) (user, pass string, ok bool) {
	if h == "" {
		return "", "", false
	}
	if !strings.HasPrefix(strings.ToLower(h), "basic ") {
		return "", "", false
	}
	raw := strings.TrimSpace(h[6:])
	dec, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return "", "", false
	}
	up := strings.SplitN(string(dec), ":", 2)
	if len(up) != 2 {
		return "", "", false
	}
	return up[0], up[1], true
}

func parseRequestLine(s string) (method, reqURI, proto string, ok bool) {
	parts := strings.SplitN(strings.TrimSpace(s), " ", 3)
	if len(parts) != 3 {
		return
	}
	method, reqURI, proto = parts[0], parts[1], parts[2]
	if method == "" || reqURI == "" || !strings.HasPrefix(strings.ToUpper(proto), "HTTP/") {
		return
	}
	ok = true
	return
}

func writeHTTPAndClose(c net.Conn, code int, text, body string) {
	_ = c.SetWriteDeadline(time.Now().Add(3 * time.Second))
	_, _ = fmt.Fprintf(c, "HTTP/1.1 %d %s\r\nContent-Length: %d\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n%s",
		code, text, len(body), body)
	_ = c.Close()
}

func writeRaw(c net.Conn, s string) error {
	_ = c.SetWriteDeadline(time.Now().Add(3 * time.Second))
	_, err := io.WriteString(c, s)
	return err
}

func canonHeaderKey(s string) string {
	parts := strings.Split(s, "-")
	for i := range parts {
		if len(parts[i]) == 0 {
			continue
		}
		parts[i] = strings.ToUpper(parts[i][:1]) + strings.ToLower(parts[i][1:])
	}
	return strings.Join(parts, "-")
}
