package nat

import (
	"context"
	"net"
	"time"
)

func DomainRunner(ctx context.Context, k Kernel, ruleID int64,
	listenTCP, listenUDP string, targetHost string, targetPort int,
	eg *Egress, hooks Hooks) error {

	// 解析监听口
	var lTCP *net.TCPAddr
	var lUDP *net.UDPAddr
	var err error
	if listenTCP != "" {
		lTCP, err = net.ResolveTCPAddr("tcp", listenTCP)
		if err != nil {
			return err
		}
	}
	if listenUDP != "" {
		lUDP, err = net.ResolveUDPAddr("udp", listenUDP)
		if err != nil {
			return err
		}
	}

	installFor := func(ips []net.IP) error {
		var tTCP *net.TCPAddr
		var tUDP *net.UDPAddr
		for _, ip := range ips { // 先选 v4
			if ip.To4() != nil {
				tTCP = &net.TCPAddr{IP: ip, Port: targetPort}
				tUDP = &net.UDPAddr{IP: ip, Port: targetPort}
				break
			}
		}
		for _, ip := range ips { // 再补 v6（如只有 v6）
			if ip.To4() == nil {
				if tTCP == nil {
					tTCP = &net.TCPAddr{IP: ip, Port: targetPort}
				}
				if tUDP == nil {
					tUDP = &net.UDPAddr{IP: ip, Port: targetPort}
				}
				break
			}
		}
		return k.Install(ctx, lTCP, tTCP, lUDP, tUDP, ruleID, eg)
	}

	resolve := func() (ips []net.IP, ttl time.Duration, err error) {
		ips, err = net.DefaultResolver.LookupIP(ctx, "ip", targetHost)
		if err != nil {
			return nil, 0, err
		}
		return ips, 30 * time.Second, nil // 固定 30s
	}

	ips, ttl, err := resolve()
	if err != nil {
		return err
	}
	if err := installFor(ips); err != nil {
		return err
	}

	// 首包鉴权 + 统计
	if err := k.StartAuthGate(ctx, ruleID, hooks); err != nil {
		return err
	}
	if err := k.StartStats(ctx, ruleID, hooks); err != nil {
		return err
	}

	// ★ 程序退出时一定卸载（best-effort）
	go func() {
		<-ctx.Done()
		_ = k.Uninstall(context.Background(), ruleID)
	}()

	// 热更新（IP 变化则卸载+重装）
	t := time.NewTicker(ttl)
	go func() {
		defer t.Stop()
		prev := ipStrings(ips)
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				newIPs, _, err := resolve()
				if err != nil {
					continue
				}
				if eqSlice(prev, ipStrings(newIPs)) {
					continue
				}
				_ = k.Uninstall(context.Background(), ruleID)
				_ = installFor(newIPs)
				prev = ipStrings(newIPs)
			}
		}
	}()
	return nil
}

func ipStrings(ips []net.IP) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out
}
func eqSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := map[string]int{}
	for _, s := range a {
		m[s]++
	}
	for _, s := range b {
		m[s]--
	}
	for _, v := range m {
		if v != 0 {
			return false
		}
	}
	return true
}
