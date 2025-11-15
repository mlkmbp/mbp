package server

import (
	"context"
	"log"
	"mlkmbp/mbp/app"
	"mlkmbp/mbp/common/ttls"
	"net"
	"net/http"
	"strings"
	"time"
)

// 只负责构建一个服务器：有证书→HTTPS，否则→HTTP。绝不创建重定向服务。
func buildHTTPServer(a *app.App, handler http.Handler, errLog *log.Logger) (*http.Server, bool) {
	// 如需改绑定地址/端口，改这里即可
	addr := "0.0.0.0:14259"

	srv := &http.Server{
		Addr:    addr,
		Handler: handler,
	}

	// 读取证书配置
	tlsCert := strings.TrimSpace(a.Cfg.TLSConfig.Cert)
	tlsKey := strings.TrimSpace(a.Cfg.TLSConfig.Key)
	sni := strings.TrimSpace(a.Cfg.TLSConfig.SniGuard)

	// 无证书：纯 HTTP
	if tlsCert == "" || tlsKey == "" {
		return srv, false
	}

	// 有证书：加载 TLSConfig；失败则降级 HTTP（只打一条告警）
	cfg, err := ttls.LoadTLSConfig(tlsCert, tlsKey, sni)
	if err != nil {
		errLog.Printf("[boot] tls disabled (load error): %v", err)
		return srv, false
	}
	srv.TLSConfig = cfg
	return srv, true
}

func startMainAsync(srv *http.Server, useTLS bool, errLog *log.Logger) {
	go func() {
		if useTLS {
			// 这里“用 gin 的 tls 启动”的本质就是用 net/http 的 TLS——Gin 是 Handler
			if e := srv.ListenAndServeTLS("", ""); e != nil && e != http.ErrServerClosed {
				errLog.Fatalf("listen https: %v", e)
			}
			return
		}
		if e := srv.ListenAndServe(); e != nil && e != http.ErrServerClosed {
			errLog.Fatalf("listen http: %v", e)
		}
	}()
}

func shutdownAll(srv *http.Server, a *app.App, infoLog, errLog *log.Logger) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
	if err := a.Stop(); err != nil {
		errLog.Printf("stop error: %v", err)
	}
}

// —— 日志只打一套人类可读的 URL —— //
func printListenHints(bindAddr string, useTLS bool, infoLog *log.Logger) {
	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	host, port, err := net.SplitHostPort(bindAddr)
	if err != nil {
		// 兜底
		infoLog.Printf("[boot] listening: %s://%s", scheme, bindAddr)
		return
	}

	var urls []string
	// 若绑定的 host 不是 0.0.0.0/::，先提示这个绑定地址
	if host != "" && host != "0.0.0.0" && host != "::" {
		urls = append(urls, scheme+"://"+net.JoinHostPort(host, port))
	}
	// 常见本地 & 局域网
	urls = append(urls, scheme+"://"+net.JoinHostPort("127.0.0.1", port))
	if ip := firstLANIPv4(); ip != "" {
		urls = append(urls, scheme+"://"+net.JoinHostPort(ip, port))
	}

	infoLog.Printf("[boot] listening (%s):", scheme)
	for _, u := range urls {
		infoLog.Printf("       → %s", u)
	}
}

func firstLANIPv4() string {
	ifcs, _ := net.Interfaces()
	for _, itf := range ifcs {
		if itf.Flags&net.FlagUp == 0 || itf.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := itf.Addrs()
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip = ip.To4(); ip == nil {
				continue
			}
			// 排除 127.* 和 169.254.*
			if ip[0] == 127 || (ip[0] == 169 && ip[1] == 254) {
				continue
			}
			return ip.String()
		}
	}
	return ""
}
