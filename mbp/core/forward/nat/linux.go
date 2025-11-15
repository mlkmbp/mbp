//go:build linux

package nat

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/florianl/go-nfqueue"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"mlkmbp/mbp/common/logx"
)

var natLinuxLog = logx.New(logx.WithPrefix("nat.linux"))

type linuxKernel struct {
	qnum       uint16
	tTCP, tUDP *net.UDPAddr
	tTCPAddr   *net.TCPAddr
	lTCPPort   int
	lUDPPort   int

	// 供统计阶段把 16 位 uid 还原成 int64（用 5 元组做 key）
	uidMu   sync.RWMutex
	uidBy5t map[string]int64

	closedMu sync.Mutex
	closed   map[string]time.Time

	statsBackend string
}

func NewKernel(ruleID int64) Kernel { return &linuxKernel{qnum: qnumFromRule(ruleID)} }
func (k *linuxKernel) Close() error { return nil }

// ---------- Install/Uninstall：iptables-only ----------

func (k *linuxKernel) Install(ctx context.Context, lt, tt *net.TCPAddr,
	lu, tu *net.UDPAddr, ruleID int64, eg *Egress) error {

	// 记住目标与监听端口（用于统计/事件过滤/回填）
	k.tTCPAddr = tt
	if tt != nil {
		k.tTCP = &net.UDPAddr{IP: tt.IP, Port: tt.Port}
	} else {
		k.tTCP = nil
	}
	if tu != nil {
		k.tUDP = &net.UDPAddr{IP: tu.IP, Port: tu.Port}
	} else {
		k.tUDP = nil
	}
	k.lTCPPort, k.lUDPPort = 0, 0
	if lt != nil {
		k.lTCPPort = lt.Port
	}
	if lu != nil {
		k.lUDPPort = lu.Port
	}

	// 只按需启用 v4/v6 与 tcp/udp
	wantV4TCP := (lt != nil && tt != nil && tt.IP.To4() != nil)
	wantV4UDP := (lu != nil && tu != nil && tu.IP.To4() != nil)
	wantV6TCP := (lt != nil && tt != nil && tt.IP.To4() == nil && tt.IP.To16() != nil)
	wantV6UDP := (lu != nil && tu != nil && tu.IP.To4() == nil && tu.IP.To16() != nil)
	wantV4 := wantV4TCP || wantV4UDP || (eg != nil && eg.External4 != nil)
	wantV6 := wantV6TCP || wantV6UDP || (eg != nil && eg.External6 != nil)

	// 开转发（非持久化）
	if wantV4 {
		_ = writeProc("/proc/sys/net/ipv4/ip_forward", "1")
	}
	if wantV6 {
		_ = writeProc("/proc/sys/net/ipv6/conf/all/forwarding", "1")
	}

	// 打开 conntrack 计数（非持久化）
	_ = writeProc("/proc/sys/net/netfilter/nf_conntrack_acct", "1")

	// 先清旧
	_ = k.uninstallIptables(ruleID)

	// 私有链名与匹配标记
	tag := fmt.Sprintf("mbp_r%d", ruleID) // comment 用完整 ID
	ruleShort := short16(ruleID)          // 高 16 位写短 ID
	markHi := uint32(ruleShort) << 16
	markMask := "0xffff0000"
	markSpec := fmt.Sprintf("0x%08x/%s", markHi, markMask)

	cPre := fmt.Sprintf("MBP%d_PRE", ruleID)   // mangle/PREROUTING
	cOut := fmt.Sprintf("MBP%d_OUT", ruleID)   // mangle/OUTPUT
	cFwd := fmt.Sprintf("MBP%d_FWD", ruleID)   // mangle/FORWARD（mark 持久化）
	cNPR := fmt.Sprintf("MBP%d_PR", ruleID)    // nat/PREROUTING（DNAT）
	cNO := fmt.Sprintf("MBP%d_NO", ruleID)     // nat/OUTPUT（本机->DNAT）
	cNPO := fmt.Sprintf("MBP%d_PO", ruleID)    // nat/POSTROUTING（SNAT/MASQ）
	cFilt := fmt.Sprintf("MBP%d_FILT", ruleID) // filter/FORWARD（放行）

	// ===== IPv4 =====
	if wantV4 {
		// ---------- mangle/PREROUTING（外部来流：首包进队鉴权 + mark 落地） ----------
		if wantV4TCP || wantV4UDP {
			_ = ipt("iptables", "-t", "mangle", "-N", cPre)
			_ = ipt("iptables", "-t", "mangle", "-F", cPre)

			if wantV4TCP && lt != nil {
				_ = ipt("iptables", "-t", "mangle", "-A", cPre,
					"-p", "tcp", "--dport", fmt.Sprint(lt.Port),
					"-j", "CONNMARK", "--restore-mark")
				_ = ipt("iptables", "-t", "mangle", "-A", cPre,
					"-p", "tcp", "--dport", fmt.Sprint(lt.Port),
					"-m", "conntrack", "--ctstate", "NEW",
					"-j", "NFQUEUE", "--queue-num", fmt.Sprint(k.qnum))
				_ = ipt("iptables", "-t", "mangle", "-A", cPre,
					"-p", "tcp", "--dport", fmt.Sprint(lt.Port),
					"-m", "conntrack", "--ctstate", "NEW",
					"-m", "mark", "!", "--mark", markSpec, "-j", "DROP")
				_ = ipt("iptables", "-t", "mangle", "-A", cPre,
					"-p", "tcp", "--dport", fmt.Sprint(lt.Port),
					"-j", "CONNMARK", "--save-mark",
					"--nfmask", "0xffffffff", "--ctmask", "0xffffffff")
			}
			if wantV4UDP && lu != nil {
				_ = ipt("iptables", "-t", "mangle", "-A", cPre,
					"-p", "udp", "--dport", fmt.Sprint(lu.Port),
					"-j", "CONNMARK", "--restore-mark")
				_ = ipt("iptables", "-t", "mangle", "-A", cPre,
					"-p", "udp", "--dport", fmt.Sprint(lu.Port),
					"-m", "conntrack", "--ctstate", "NEW",
					"-j", "NFQUEUE", "--queue-num", fmt.Sprint(k.qnum))
				_ = ipt("iptables", "-t", "mangle", "-A", cPre,
					"-p", "udp", "--dport", fmt.Sprint(lu.Port),
					"-m", "conntrack", "--ctstate", "NEW",
					"-m", "mark", "!", "--mark", markSpec, "-j", "DROP")
				_ = ipt("iptables", "-t", "mangle", "-A", cPre,
					"-p", "udp", "--dport", fmt.Sprint(lu.Port),
					"-j", "CONNMARK", "--save-mark",
					"--nfmask", "0xffffffff", "--ctmask", "0xffffffff")
			}
			// mangle/PREROUTING
			if err := ensureJump("iptables", "mangle", "PREROUTING", tag, cPre); err != nil {
				natLinuxLog.Errorf("ensureJump mangle/PREROUTING -> %s failed: %v", cPre, err)
			}

			// ---------- mangle/FORWARD：先 restore，再 save（把 skb mark 持久化到 conntrack） ----------
			_ = ipt("iptables", "-t", "mangle", "-N", cFwd)
			_ = ipt("iptables", "-t", "mangle", "-F", cFwd)
			_ = ipt("iptables", "-t", "mangle", "-A", cFwd,
				"-j", "CONNMARK", "--restore-mark", "--mask", "0xffffffff")
			_ = ipt("iptables", "-t", "mangle", "-A", cFwd,
				"-m", "mark", "--mark", markSpec,
				"-j", "CONNMARK", "--save-mark",
				"--nfmask", "0xffffffff", "--ctmask", "0xffffffff")
			// mangle/FORWARD
			if err := ensureJump("iptables", "mangle", "FORWARD", tag, cFwd); err != nil {
				natLinuxLog.Errorf("ensureJump mangle/FORWARD -> %s failed: %v", cFwd, err)
			}

			// ---------- mangle/OUTPUT（本机发起流同样过首包鉴权） ----------
			_ = ipt("iptables", "-t", "mangle", "-N", cOut)
			_ = ipt("iptables", "-t", "mangle", "-F", cOut)
			if wantV4TCP && lt != nil {
				_ = ipt("iptables", "-t", "mangle", "-A", cOut,
					"-p", "tcp", "--dport", fmt.Sprint(lt.Port),
					"-j", "CONNMARK", "--restore-mark")
				_ = ipt("iptables", "-t", "mangle", "-A", cOut,
					"-p", "tcp", "--dport", fmt.Sprint(lt.Port),
					"-m", "conntrack", "--ctstate", "NEW",
					"-j", "NFQUEUE", "--queue-num", fmt.Sprint(k.qnum))
				_ = ipt("iptables", "-t", "mangle", "-A", cOut,
					"-p", "tcp", "--dport", fmt.Sprint(lt.Port),
					"-m", "conntrack", "--ctstate", "NEW",
					"-m", "mark", "!", "--mark", markSpec, "-j", "DROP")
				_ = ipt("iptables", "-t", "mangle", "-A", cOut,
					"-p", "tcp", "--dport", fmt.Sprint(lt.Port),
					"-j", "CONNMARK", "--save-mark",
					"--nfmask", "0xffffffff", "--ctmask", "0xffffffff")
			}
			if wantV4UDP && lu != nil {
				_ = ipt("iptables", "-t", "mangle", "-A", cOut,
					"-p", "udp", "--dport", fmt.Sprint(lu.Port),
					"-j", "CONNMARK", "--restore-mark")
				_ = ipt("iptables", "-t", "mangle", "-A", cOut,
					"-p", "udp", "--dport", fmt.Sprint(lu.Port),
					"-m", "conntrack", "--ctstate", "NEW",
					"-j", "NFQUEUE", "--queue-num", fmt.Sprint(k.qnum))
				_ = ipt("iptables", "-t", "mangle", "-A", cOut,
					"-p", "udp", "--dport", fmt.Sprint(lu.Port),
					"-m", "conntrack", "--ctstate", "NEW",
					"-m", "mark", "!", "--mark", markSpec, "-j", "DROP")
				_ = ipt("iptables", "-t", "mangle", "-A", cOut,
					"-p", "udp", "--dport", fmt.Sprint(lu.Port),
					"-j", "CONNMARK", "--save-mark",
					"--nfmask", "0xffffffff", "--ctmask", "0xffffffff")
			}
			// mangle/OUTPUT
			if err := ensureJump("iptables", "mangle", "OUTPUT", tag, cOut); err != nil {
				natLinuxLog.Errorf("ensureJump mangle/OUTPUT -> %s failed: %v", cOut, err)
			}
		}

		// ---------- filter/FORWARD：放行标记流与回程 ----------
		_ = ipt("iptables", "-t", "filter", "-N", cFilt)
		_ = ipt("iptables", "-t", "filter", "-F", cFilt)
		_ = ipt("iptables", "-t", "filter", "-A", cFilt,
			"-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT")
		_ = ipt("iptables", "-t", "filter", "-A", cFilt,
			"-m", "mark", "--mark", markSpec, "-j", "ACCEPT")
		// filter/FORWARD
		if err := ensureJump("iptables", "filter", "FORWARD", tag, cFilt); err != nil {
			natLinuxLog.Errorf("ensureJump filter/FORWARD -> %s failed: %v", cFilt, err)
		}

		// ---------- nat/PREROUTING：DNAT 外部来流 ----------
		dnat4 := false
		if wantV4TCP || wantV4UDP {
			_ = ipt("iptables", "-t", "nat", "-N", cNPR)
			_ = ipt("iptables", "-t", "nat", "-F", cNPR)
			if wantV4TCP && lt != nil && tt != nil {
				_ = ipt("iptables", "-t", "nat", "-A", cNPR,
					"-p", "tcp", "--dport", fmt.Sprint(lt.Port),
					"-m", "mark", "--mark", markSpec,
					"-j", "DNAT", "--to-destination",
					net.JoinHostPort(tt.IP.String(), fmt.Sprint(tt.Port)))
				dnat4 = true
			}
			if wantV4UDP && lu != nil && tu != nil {
				_ = ipt("iptables", "-t", "nat", "-A", cNPR,
					"-p", "udp", "--dport", fmt.Sprint(lu.Port),
					"-m", "mark", "--mark", markSpec,
					"-j", "DNAT", "--to-destination",
					net.JoinHostPort(tu.IP.String(), fmt.Sprint(tu.Port)))
				dnat4 = true
			}
			if dnat4 {
				if err := ensureJump("iptables", "nat", "PREROUTING", tag, cNPR); err != nil {
					natLinuxLog.Errorf("ensureJump nat/PREROUTING -> %s failed: %v", cNPR, err)
				}

			} else {
				_ = ipt("iptables", "-t", "nat", "-X", cNPR)
			}
		}

		// ---------- nat/OUTPUT：DNAT 本机发起 ----------
		if wantV4TCP || wantV4UDP {
			_ = ipt("iptables", "-t", "nat", "-N", cNO)
			_ = ipt("iptables", "-t", "nat", "-F", cNO)
			if wantV4TCP && lt != nil && tt != nil {
				_ = ipt("iptables", "-t", "nat", "-A", cNO,
					"-p", "tcp", "--dport", fmt.Sprint(lt.Port),
					"-m", "mark", "--mark", markSpec,
					"-j", "DNAT", "--to-destination",
					net.JoinHostPort(tt.IP.String(), fmt.Sprint(tt.Port)))
			}
			if wantV4UDP && lu != nil && tu != nil {
				_ = ipt("iptables", "-t", "nat", "-A", cNO,
					"-p", "udp", "--dport", fmt.Sprint(lu.Port),
					"-m", "mark", "--mark", markSpec,
					"-j", "DNAT", "--to-destination",
					net.JoinHostPort(tu.IP.String(), fmt.Sprint(tu.Port)))
			}
			// nat/OUTPUT
			if err := ensureJump("iptables", "nat", "OUTPUT", tag, cNO); err != nil {
				natLinuxLog.Errorf("ensureJump nat/OUTPUT -> %s failed: %v", cNO, err)
			}
		}

		// ---------- nat/POSTROUTING：SNAT/MASQUERADE ----------
		if wantV4TCP || wantV4UDP {
			_ = ipt("iptables", "-t", "nat", "-N", cNPO)
			_ = ipt("iptables", "-t", "nat", "-F", cNPO)
			if eg != nil && eg.External4 != nil {
				// 先按 mark/connmark
				_ = ipt("iptables", "-t", "nat", "-A", cNPO,
					"-m", "mark", "--mark", markSpec,
					"-j", "SNAT", "--to-source", eg.External4.String())
				_ = ipt("iptables", "-t", "nat", "-A", cNPO,
					"-m", "connmark", "--mark", markSpec,
					"-j", "SNAT", "--to-source", eg.External4.String())

				// —— 兜底：按 DNAT 目标做 SNAT（不中 mark 也能出）
				if wantV4TCP && lt != nil && tt != nil {
					_ = ipt("iptables", "-t", "nat", "-A", cNPO,
						"-p", "tcp", "-d", tt.IP.String(), "--dport", fmt.Sprint(tt.Port),
						"-j", "SNAT", "--to-source", eg.External4.String())
				}
				if wantV4UDP && lu != nil && tu != nil {
					_ = ipt("iptables", "-t", "nat", "-A", cNPO,
						"-p", "udp", "-d", tu.IP.String(), "--dport", fmt.Sprint(tu.Port),
						"-j", "SNAT", "--to-source", eg.External4.String())
				}
			} else {
				// 先按 mark/connmark
				_ = ipt("iptables", "-t", "nat", "-A", cNPO,
					"-m", "mark", "--mark", markSpec, "-j", "MASQUERADE")
				_ = ipt("iptables", "-t", "nat", "-A", cNPO,
					"-m", "connmark", "--mark", markSpec, "-j", "MASQUERADE")

				// —— 兜底：按 DNAT 目标做 MASQUERADE
				if wantV4TCP && lt != nil && tt != nil {
					_ = ipt("iptables", "-t", "nat", "-A", cNPO,
						"-p", "tcp", "-d", tt.IP.String(), "--dport", fmt.Sprint(tt.Port),
						"-j", "MASQUERADE")
				}
				if wantV4UDP && lu != nil && tu != nil {
					_ = ipt("iptables", "-t", "nat", "-A", cNPO,
						"-p", "udp", "-d", tu.IP.String(), "--dport", fmt.Sprint(tu.Port),
						"-j", "MASQUERADE")
				}
			}
			if err := ensureJump("iptables", "nat", "POSTROUTING", tag, cNPO); err != nil {
				natLinuxLog.Errorf("ensureJump nat/POSTROUTING -> %s failed: %v", cNPO, err)
			}
		}

	}

	// ===== IPv6（与 IPv4 对称，换成 ip6tables）=====
	if wantV6 {
		// mangle/PREROUTING v6
		_ = ipt("ip6tables", "-t", "mangle", "-N", cPre)
		_ = ipt("ip6tables", "-t", "mangle", "-F", cPre)
		if wantV6TCP && lt != nil {
			_ = ipt("ip6tables", "-t", "mangle", "-A", cPre,
				"-p", "tcp", "--dport", fmt.Sprint(lt.Port),
				"-j", "CONNMARK", "--restore-mark")
			_ = ipt("ip6tables", "-t", "mangle", "-A", cPre,
				"-p", "tcp", "--dport", fmt.Sprint(lt.Port),
				"-m", "conntrack", "--ctstate", "NEW",
				"-j", "NFQUEUE", "--queue-num", fmt.Sprint(k.qnum))
			_ = ipt("ip6tables", "-t", "mangle", "-A", cPre,
				"-p", "tcp", "--dport", fmt.Sprint(lt.Port),
				"-m", "conntrack", "--ctstate", "NEW",
				"-m", "mark", "!", "--mark", markSpec, "-j", "DROP")
			_ = ipt("ip6tables", "-t", "mangle", "-A", cPre,
				"-p", "tcp", "--dport", fmt.Sprint(lt.Port),
				"-j", "CONNMARK", "--save-mark",
				"--nfmask", "0xffffffff", "--ctmask", "0xffffffff")
		}
		if wantV6UDP && lu != nil {
			_ = ipt("ip6tables", "-t", "mangle", "-A", cPre,
				"-p", "udp", "--dport", fmt.Sprint(lu.Port),
				"-j", "CONNMARK", "--restore-mark")
			_ = ipt("ip6tables", "-t", "mangle", "-A", cPre,
				"-p", "udp", "--dport", fmt.Sprint(lu.Port),
				"-m", "conntrack", "--ctstate", "NEW",
				"-j", "NFQUEUE", "--queue-num", fmt.Sprint(k.qnum))
			_ = ipt("ip6tables", "-t", "mangle", "-A", cPre,
				"-p", "udp", "--dport", fmt.Sprint(lu.Port),
				"-m", "conntrack", "--ctstate", "NEW",
				"-m", "mark", "!", "--mark", markSpec, "-j", "DROP")
			_ = ipt("ip6tables", "-t", "mangle", "-A", cPre,
				"-p", "udp", "--dport", fmt.Sprint(lu.Port),
				"-j", "CONNMARK", "--save-mark",
				"--nfmask", "0xffffffff", "--ctmask", "0xffffffff")
		}
		// mangle/PREROUTING
		if err := ensureJump("ip6tables", "mangle", "PREROUTING", tag, cPre); err != nil {
			natLinuxLog.Errorf("ensureJump6 mangle/PREROUTING -> %s failed: %v", cPre, err)
		}

		// mangle/FORWARD v6：restore + save
		_ = ipt("ip6tables", "-t", "mangle", "-N", cFwd)
		_ = ipt("ip6tables", "-t", "mangle", "-F", cFwd)
		_ = ipt("ip6tables", "-t", "mangle", "-A", cFwd,
			"-j", "CONNMARK", "--restore-mark", "--mask", "0xffffffff")
		_ = ipt("ip6tables", "-t", "mangle", "-A", cFwd,
			"-m", "mark", "--mark", markSpec,
			"-j", "CONNMARK", "--save-mark",
			"--nfmask", "0xffffffff", "--ctmask", "0xffffffff")
		// mangle/FORWARD
		if err := ensureJump("ip6tables", "mangle", "FORWARD", tag, cFwd); err != nil {
			natLinuxLog.Errorf("ensureJump6 mangle/FORWARD -> %s failed: %v", cFwd, err)
		}

		// mangle/OUTPUT v6
		_ = ipt("ip6tables", "-t", "mangle", "-N", cOut)
		_ = ipt("ip6tables", "-t", "mangle", "-F", cOut)
		if wantV6TCP && lt != nil {
			_ = ipt("ip6tables", "-t", "mangle", "-A", cOut,
				"-p", "tcp", "--dport", fmt.Sprint(lt.Port),
				"-j", "CONNMARK", "--restore-mark")
			_ = ipt("ip6tables", "-t", "mangle", "-A", cOut,
				"-p", "tcp", "--dport", fmt.Sprint(lt.Port),
				"-m", "conntrack", "--ctstate", "NEW",
				"-j", "NFQUEUE", "--queue-num", fmt.Sprint(k.qnum))
			_ = ipt("ip6tables", "-t", "mangle", "-A", cOut,
				"-p", "tcp", "--dport", fmt.Sprint(lt.Port),
				"-m", "conntrack", "--ctstate", "NEW",
				"-m", "mark", "!", "--mark", markSpec, "-j", "DROP")
			_ = ipt("ip6tables", "-t", "mangle", "-A", cOut,
				"-p", "tcp", "--dport", fmt.Sprint(lt.Port),
				"-j", "CONNMARK", "--save-mark",
				"--nfmask", "0xffffffff", "--ctmask", "0xffffffff")
		}
		if wantV6UDP && lu != nil {
			_ = ipt("ip6tables", "-t", "mangle", "-A", cOut,
				"-p", "udp", "--dport", fmt.Sprint(lu.Port),
				"-j", "CONNMARK", "--restore-mark")
			_ = ipt("ip6tables", "-t", "mangle", "-A", cOut,
				"-p", "udp", "--dport", fmt.Sprint(lu.Port),
				"-m", "conntrack", "--ctstate", "NEW",
				"-j", "NFQUEUE", "--queue-num", fmt.Sprint(k.qnum))
			_ = ipt("ip6tables", "-t", "mangle", "-A", cOut,
				"-p", "udp", "--dport", fmt.Sprint(lu.Port),
				"-m", "conntrack", "--ctstate", "NEW",
				"-m", "mark", "!", "--mark", markSpec, "-j", "DROP")
			_ = ipt("ip6tables", "-t", "mangle", "-A", cOut,
				"-p", "udp", "--dport", fmt.Sprint(lu.Port),
				"-j", "CONNMARK", "--save-mark",
				"--nfmask", "0xffffffff", "--ctmask", "0xffffffff")
		}
		// mangle/OUTPUT
		if err := ensureJump("ip6tables", "mangle", "OUTPUT", tag, cOut); err != nil {
			natLinuxLog.Errorf("ensureJump6 mangle/OUTPUT -> %s failed: %v", cOut, err)
		}

		// filter/FORWARD v6
		_ = ipt("ip6tables", "-t", "filter", "-N", cFilt)
		_ = ipt("ip6tables", "-t", "filter", "-F", cFilt)
		_ = ipt("ip6tables", "-t", "filter", "-A", cFilt,
			"-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT")
		_ = ipt("ip6tables", "-t", "filter", "-A", cFilt,
			"-m", "mark", "--mark", markSpec, "-j", "ACCEPT")
		// filter/FORWARD
		if err := ensureJump("ip6tables", "filter", "FORWARD", tag, cFilt); err != nil {
			natLinuxLog.Errorf("ensureJump6 filter/FORWARD -> %s failed: %v", cFilt, err)
		}

		// nat/PREROUTING v6
		dnat6 := false
		_ = ipt("ip6tables", "-t", "nat", "-N", cNPR)
		_ = ipt("ip6tables", "-t", "nat", "-F", cNPR)
		if wantV6TCP && lt != nil && tt != nil {
			_ = ipt("ip6tables", "-t", "nat", "-A", cNPR,
				"-p", "tcp", "--dport", fmt.Sprint(lt.Port),
				"-m", "mark", "--mark", markSpec,
				"-j", "DNAT", "--to-destination",
				net.JoinHostPort(tt.IP.String(), fmt.Sprint(tt.Port)))
			dnat6 = true
		}
		if wantV6UDP && lu != nil && tu != nil {
			_ = ipt("ip6tables", "-t", "nat", "-A", cNPR,
				"-p", "udp", "--dport", fmt.Sprint(lu.Port),
				"-m", "mark", "--mark", markSpec,
				"-j", "DNAT", "--to-destination",
				net.JoinHostPort(tu.IP.String(), fmt.Sprint(tu.Port)))
			dnat6 = true
		}
		if dnat6 {
			if err := ensureJump("ip6tables", "nat", "PREROUTING", tag, cNPR); err != nil {
				natLinuxLog.Errorf("ensureJump6 nat/PREROUTING -> %s failed: %v", cNPR, err)
			}
		} else {
			_ = ipt("ip6tables", "-t", "nat", "-X", cNPR)
		}

		// nat/OUTPUT v6
		_ = ipt("ip6tables", "-t", "nat", "-N", cNO)
		_ = ipt("ip6tables", "-t", "nat", "-F", cNO)
		if wantV6TCP && lt != nil && tt != nil {
			_ = ipt("ip6tables", "-t", "nat", "-A", cNO,
				"-p", "tcp", "--dport", fmt.Sprint(lt.Port),
				"-m", "mark", "--mark", markSpec,
				"-j", "DNAT", "--to-destination",
				net.JoinHostPort(tt.IP.String(), fmt.Sprint(tt.Port)))
		}
		if wantV6UDP && lu != nil && tu != nil {
			_ = ipt("ip6tables", "-t", "nat", "-A", cNO,
				"-p", "udp", "--dport", fmt.Sprint(lu.Port),
				"-m", "mark", "--mark", markSpec,
				"-j", "DNAT", "--to-destination",
				net.JoinHostPort(tu.IP.String(), fmt.Sprint(tu.Port)))
		}
		// nat/OUTPUT
		if err := ensureJump("ip6tables", "nat", "OUTPUT", tag, cNO); err != nil {
			natLinuxLog.Errorf("ensureJump6 nat/OUTPUT -> %s failed: %v", cNO, err)
		}

		// nat/POSTROUTING v6：SNAT/MASQUERADE
		_ = ipt("ip6tables", "-t", "nat", "-N", cNPO)
		_ = ipt("ip6tables", "-t", "nat", "-F", cNPO)
		// ---------- nat/POSTROUTING v6 ----------
		_ = ipt("ip6tables", "-t", "nat", "-N", cNPO)
		_ = ipt("ip6tables", "-t", "nat", "-F", cNPO)
		if eg != nil && eg.External6 != nil {
			_ = ipt("ip6tables", "-t", "nat", "-A", cNPO,
				"-m", "mark", "--mark", markSpec,
				"-j", "SNAT", "--to-source", eg.External6.String())
			_ = ipt("ip6tables", "-t", "nat", "-A", cNPO,
				"-m", "connmark", "--mark", markSpec,
				"-j", "SNAT", "--to-source", eg.External6.String())

			if wantV6TCP && lt != nil && tt != nil {
				_ = ipt("ip6tables", "-t", "nat", "-A", cNPO,
					"-p", "tcp", "-d", tt.IP.String(), "--dport", fmt.Sprint(tt.Port),
					"-j", "SNAT", "--to-source", eg.External6.String())
			}
			if wantV6UDP && lu != nil && tu != nil {
				_ = ipt("ip6tables", "-t", "nat", "-A", cNPO,
					"-p", "udp", "-d", tu.IP.String(), "--dport", fmt.Sprint(tu.Port),
					"-j", "SNAT", "--to-source", eg.External6.String())
			}
		} else {
			_ = ipt("ip6tables", "-t", "nat", "-A", cNPO,
				"-m", "mark", "--mark", markSpec, "-j", "MASQUERADE")
			_ = ipt("ip6tables", "-t", "nat", "-A", cNPO,
				"-m", "connmark", "--mark", markSpec, "-j", "MASQUERADE")

			if wantV6TCP && lt != nil && tt != nil {
				_ = ipt("ip6tables", "-t", "nat", "-A", cNPO,
					"-p", "tcp", "-d", tt.IP.String(), "--dport", fmt.Sprint(tt.Port),
					"-j", "MASQUERADE")
			}
			if wantV6UDP && lu != nil && tu != nil {
				_ = ipt("ip6tables", "-t", "nat", "-A", cNPO,
					"-p", "udp", "-d", tu.IP.String(), "--dport", fmt.Sprint(tu.Port),
					"-j", "MASQUERADE")
			}
		}
		if err := ensureJump("ip6tables", "nat", "POSTROUTING", tag, cNPO); err != nil {
			natLinuxLog.Errorf("ensureJump6 nat/POSTROUTING -> %s failed: %v", cNPO, err)
		}
	}

	natLinuxLog.Infof("[rule %d] iptables backend installed (tcp=%d udp=%d q=%d)", ruleID, k.lTCPPort, k.lUDPPort, k.qnum)
	return nil
}

func (k *linuxKernel) Uninstall(ctx context.Context, ruleID int64) error {
	return k.uninstallIptables(ruleID)
}

func (k *linuxKernel) uninstallIptables(ruleID int64) error {
	tag := fmt.Sprintf("mbp_r%d", ruleID)
	cPre := fmt.Sprintf("MBP%d_PRE", ruleID) // mangle PREROUTING
	cOut := fmt.Sprintf("MBP%d_OUT", ruleID) // mangle OUTPUT
	cFwd := fmt.Sprintf("MBP%d_FWD", ruleID) // mangle FORWARD
	cFF := fmt.Sprintf("MBP%d_FILT", ruleID) // filter FORWARD
	cNPR := fmt.Sprintf("MBP%d_PR", ruleID)  // nat PREROUTING
	cNO := fmt.Sprintf("MBP%d_NO", ruleID)   // nat OUTPUT
	cNPO := fmt.Sprintf("MBP%d_PO", ruleID)  // nat POSTROUTING

	delJumpIfExists := func(bin, table, base, chain string) {
		// 先删“带 comment”的
		_ = iptNoLog(bin, "-t", table, "-D", base, "-m", "comment", "--comment", tag, "-j", chain)
		// 再删“无 comment”的
		_ = iptNoLog(bin, "-t", table, "-D", base, "-j", chain)
	}

	flushDel := func(bin, table string, chains ...string) {
		for _, c := range chains {
			_ = iptNoLog(bin, "-t", table, "-F", c)
			_ = iptNoLog(bin, "-t", table, "-X", c)
		}
	}

	for _, bin := range []string{"iptables", "ip6tables"} {
		// 删 jump（各在对应表）
		delJumpIfExists(bin, "mangle", "PREROUTING", cPre)
		delJumpIfExists(bin, "mangle", "OUTPUT", cOut)
		delJumpIfExists(bin, "mangle", "FORWARD", cFwd)
		delJumpIfExists(bin, "filter", "FORWARD", cFF)
		delJumpIfExists(bin, "nat", "PREROUTING", cNPR)
		delJumpIfExists(bin, "nat", "OUTPUT", cNO)
		delJumpIfExists(bin, "nat", "POSTROUTING", cNPO)

		// 删链（按表分类）
		flushDel(bin, "mangle", cPre, cOut, cFwd)
		flushDel(bin, "filter", cFF)
		flushDel(bin, "nat", cNPR, cNO, cNPO)
	}
	return nil
}

// ---------- 首包鉴权（NFQUEUE）----------

func (k *linuxKernel) StartAuthGate(ctx context.Context, ruleID int64, hooks Hooks) error {
	q, err := nfqueue.Open(&nfqueue.Config{
		NfQueue:      k.qnum,
		MaxQueueLen:  32768,
		Copymode:     nfqueue.NfQnlCopyPacket,
		MaxPacketLen: 0xffff,
		ReadTimeout:  time.Second,
	})
	if err != nil {
		natLinuxLog.Errorf("[rule %d] nfqueue.Open(queue=%d) failed: %v", ruleID, k.qnum, err)
		return mapUnsupported(err)
	}
	ruleShort := short16(ruleID)
	cb := func(a nfqueue.Attribute) int {
		if a.Payload == nil || a.PacketID == nil {
			return 0
		}
		p, ok := parse5TuplePtr(a.Payload)
		if !ok {
			_ = q.SetVerdict(*a.PacketID, nfqueue.NfDrop)
			return 0
		}

		uid64, allow, reason := hooks.Auth(ctx, FlowMeta{
			Proto: p.Proto, SrcIP: p.SrcIP, SrcPort: p.SrcPort,
			ListenIP: p.DstIP, ListenPort: p.DstPort, RuleID: ruleID,
		})
		if !allow {
			if hooks.OnReject != nil {
				hooks.OnReject(ifEmpty(reason, "auth_failed"), net.JoinHostPort(p.SrcIP, fmt.Sprint(p.SrcPort)))
			}
			_ = q.SetVerdict(*a.PacketID, nfqueue.NfDrop)
			return 0
		}

		// —— 映射缓存：正向/反向 + DNAT 别名（正反向）全写入 —— //
		k.uidMu.Lock()
		if k.uidBy5t == nil {
			k.uidBy5t = make(map[string]int64)
		}
		fwdListen := fmt.Sprintf("%s|%s|%d|%s|%d", p.Proto, p.SrcIP, p.SrcPort, p.DstIP, p.DstPort)
		revListen := fmt.Sprintf("%s|%s|%d|%s|%d", p.Proto, p.DstIP, p.DstPort, p.SrcIP, p.SrcPort)
		k.uidBy5t[fwdListen] = uid64
		k.uidBy5t[revListen] = uid64
		if p.Proto == "tcp" && k.tTCPAddr != nil {
			fwdDNAT := fmt.Sprintf("tcp|%s|%d|%s|%d", p.SrcIP, p.SrcPort, k.tTCPAddr.IP.String(), k.tTCPAddr.Port)
			revDNAT := fmt.Sprintf("tcp|%s|%d|%s|%d", k.tTCPAddr.IP.String(), k.tTCPAddr.Port, p.SrcIP, p.SrcPort)
			k.uidBy5t[fwdDNAT] = uid64
			k.uidBy5t[revDNAT] = uid64
		}
		if p.Proto == "udp" && k.tUDP != nil {
			fwdDNAT := fmt.Sprintf("udp|%s|%d|%s|%d", p.SrcIP, p.SrcPort, k.tUDP.IP.String(), k.tUDP.Port)
			revDNAT := fmt.Sprintf("udp|%s|%d|%s|%d", k.tUDP.IP.String(), k.tUDP.Port, p.SrcIP, p.SrcPort)
			k.uidBy5t[fwdDNAT] = uid64
			k.uidBy5t[revDNAT] = uid64
		}
		k.uidMu.Unlock()

		uidShort := short16(uid64)
		mark := (uint32(ruleShort) << 16) | uint32(uidShort)

		if err := q.SetVerdictWithMark(*a.PacketID, nfqueue.NfAccept, int(mark)); err != nil {
			natLinuxLog.Errorf("[rule %d] verdict accept with mark failed: %v", ruleID, err)
		} else {
			natLinuxLog.Debugf("[rule %d] auth allow uid=%d %s:%d -> %s:%d mark=0x%08x",
				ruleID, uid64, p.SrcIP, p.SrcPort, p.DstIP, p.DstPort, mark)
		}
		return 0
	}
	var lastIdleLog time.Time
	errCb := func(e error) int {
		if e == nil {
			return 0
		}
		es := strings.ToLower(e.Error())
		if strings.Contains(es, "timeout") || strings.Contains(es, "i/o timeout") {
			if time.Since(lastIdleLog) > time.Minute {
				natLinuxLog.Debugf("[rule %d] NFQUEUE idle (no packet within %s)", ruleID, time.Second)
				lastIdleLog = time.Now()
			}
			return 0
		}
		natLinuxLog.Errorf("[rule %d] NFQUEUE callback error: %v", ruleID, e)
		return 0
	}

	if err := q.RegisterWithErrorFunc(ctx, cb, errCb); err != nil {
		_ = q.Close()
		natLinuxLog.Errorf("[rule %d] NFQUEUE register failed: %v", ruleID, err)
		return mapUnsupported(err)
	}
	go func() { <-ctx.Done(); _ = q.Close(); natLinuxLog.Debugf("[rule %d] NFQUEUE closed", ruleID) }()
	natLinuxLog.Debugf("[rule %d] NFQUEUE started on queue=%d", ruleID, k.qnum)
	return nil
}

func (k *linuxKernel) StartStats(ctx context.Context, ruleID int64, hooks Hooks) error {
	if v := readFileTrim("/proc/sys/net/netfilter/nf_conntrack_acct"); v != "1" {
		natLinuxLog.Warnf("[rule %d] nf_conntrack_acct=%s; statistics may miss bytes", ruleID, v)
	}
	_ = writeProc("/proc/sys/net/netfilter/nf_conntrack_events", "1")

	var started bool

	// events 后端（不再独占）
	if hasBinary("conntrack") {
		if err := k.startStatsEvents(ctx, ruleID, hooks); err == nil {
			k.statsBackend = "events+proc?/parallel"
			started = true
			natLinuxLog.Debugf("[rule %d] stats backend: events started", ruleID)
		} else {
			natLinuxLog.Warnf("[rule %d] startStatsEvents failed: %v", ruleID, err)
		}
	}
	// /proc 后端并行启动（即使 events 启动成功也一起跑，兜住 DESTROY 丢失的场景）
	if path := ctProcPath(); path != "" {
		if err := k.startStatsProc(ctx, ruleID, hooks, path); err == nil {
			started = true
			natLinuxLog.Debugf("[rule %d] stats backend: proc started (path=%s, poll=%s)", ruleID, path, statsPoll)
		} else {
			natLinuxLog.Warnf("[rule %d] startStatsProc failed: %v", ruleID, err)
		}
	}

	if started {
		return nil
	}
	natLinuxLog.Errorf("[rule %d] no stats backend available", ruleID)
	return ErrUnsupported
}

func (k *linuxKernel) emitCloseOnce(ruleID int64, rec ctRec, hooks Hooks) {
	if hooks.OnClose == nil {
		return
	}

	// 归一化“监听端口”（避免 PREROUTING DNAT 后事件里的 dport 变成 80 导致去重失败）
	listenPort := rec.dstPort
	if rec.proto == "tcp" && k.lTCPPort != 0 {
		listenPort = k.lTCPPort
	}
	if rec.proto == "udp" && k.lUDPPort != 0 {
		listenPort = k.lUDPPort
	}

	// 以 ruleID+proto+源五元组（去掉易变的 dst/dport）+userID 做键，保证多通路只上报一次
	key := fmt.Sprintf("%d|%s|%s|%d|%d|%d",
		ruleID, rec.proto, rec.srcIP, rec.srcPort, listenPort, rec.userID)

	now := time.Now()
	k.closedMu.Lock()
	if k.closed == nil {
		k.closed = make(map[string]time.Time)
	}
	if _, seen := k.closed[key]; seen {
		k.closedMu.Unlock()
		return
	}
	k.closed[key] = now
	// 简单的清理（防止 map 无限制增长）
	for k2, t2 := range k.closed {
		if now.Sub(t2) > 30*time.Minute {
			delete(k.closed, k2)
		}
	}
	k.closedMu.Unlock()

	// 目标地址补全
	var tgtIP string
	var tgtPort int
	if rec.proto == "tcp" && k.tTCPAddr != nil {
		tgtIP, tgtPort = k.tTCPAddr.IP.String(), k.tTCPAddr.Port
	}
	if rec.proto == "udp" && k.tUDP != nil {
		tgtIP, tgtPort = k.tUDP.IP.String(), k.tUDP.Port
	}
	durMS := int64(0)
	if !rec.start.IsZero() && now.After(rec.start) {
		durMS = now.Sub(rec.start).Milliseconds()
	}
	natLinuxLog.Debugf("[rule %d] close uid=%d proto=%s %s:%d -> :%d up=%d down=%d dur=%dms (emit)",
		ruleID, rec.userID, rec.proto, rec.srcIP, rec.srcPort, listenPort, rec.up, rec.down, durMS)
	hooks.OnClose(FlowStats{
		UserID:     rec.userID,
		RuleID:     ruleID,
		Proto:      rec.proto,
		UpBytes:    rec.up,
		DownBytes:  rec.down,
		When:       now,
		SourceAddr: rec.srcIP, SourcePort: rec.srcPort,
		ListenAddr: rec.dstIP, ListenPort: listenPort,
		TargetAddr: tgtIP, TargetPort: tgtPort,
		DurMS: durMS,
	})
}

// 尝试按 mark 或 5 元组（含反向）认领，并返回 uid（优先完整 uid，退化用短 uid）
func (k *linuxKernel) claimUID(proto string, aIP string, aPort int, bIP string, bPort int, ruleShort uint16, mark uint64) (int64, bool) {
	// 1) mark 高 16 命中
	if ((mark >> 16) & 0xffff) == uint64(ruleShort) {
		uidShort := uint16(mark & 0xffff)
		return k.readUID(proto, aIP, aPort, bIP, bPort, uidShort), true
	}
	// 2) 5 元组正向
	if u, ok := k.uidTupleKnown(proto, aIP, aPort, bIP, bPort); ok {
		return u, true
	}
	// 3) 5 元组反向（有些发行版 DESTROY 行里第一个 tuple 是 reply）
	if u, ok := k.uidTupleKnown(proto, bIP, bPort, aIP, aPort); ok {
		return u, true
	}
	return 0, false
}

type ctKey struct{ s string }
type ctRec struct {
	up, down uint64
	start    time.Time
	srcIP    string
	srcPort  int
	dstIP    string
	dstPort  int
	proto    string
	userID   int64 // <<<<<< 改成 int64
}

func (k *linuxKernel) readUID(proto, srcIP string, srcPort int, dstIP string, dstPort int, short uint16) int64 {
	key := fmt.Sprintf("%s|%s|%d|%s|%d", proto, srcIP, srcPort, dstIP, dstPort)
	k.uidMu.RLock()
	uid, ok := k.uidBy5t[key]
	k.uidMu.RUnlock()
	if ok {
		return uid
	}
	return int64(short) // 回退：用截断值
}

const statsPoll = 300 * time.Millisecond

func (k *linuxKernel) startStatsProc(ctx context.Context, ruleID int64, hooks Hooks, path string) error {
	testF, err := os.Open(path)
	if err != nil {
		return err // 读都读不到，明确失败，让上层去尝试 events 或最终 ErrUnsupported
	}
	_ = testF.Close()

	ruleShort := short16(ruleID)
	prev := map[ctKey]ctRec{}

	// 先做一次立即扫描，加快就绪
	cur := k.readConntrackByMark(path, ruleShort)
	if len(cur) > 0 {
		now := time.Now()
		for kx, v := range cur {
			v.start = now
			prev[kx] = v
		}
	}

	tk := time.NewTicker(statsPoll)
	go func() {
		defer tk.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tk.C:
				cur := k.readConntrackByMark(path, ruleShort)
				// 更新活跃与累计
				for kx, v := range cur {
					if p, ok := prev[kx]; !ok {
						v.start = time.Now()
						prev[kx] = v
					} else {
						p.up, p.down = v.up, v.down
						prev[kx] = p
					}
				}
				// 发现 /proc 不再出现的条目，视为关闭（仅 /proc 单活时才会走到这里）
				for kx, v := range prev {
					if _, ok := cur[kx]; !ok {
						k.emitCloseOnce(ruleID, v, hooks)
						delete(prev, kx)
					}
				}
			}
		}
	}()

	natLinuxLog.Infof("[rule %d] conntrack stats started (/proc=%s, poll=%s)", ruleID, path, statsPoll)
	return nil
}

func (k *linuxKernel) readConntrackByMark(path string, ruleShort uint16) map[ctKey]ctRec {
	out := map[ctKey]ctRec{}
	f, err := os.Open(path)
	if err != nil {
		return out
	}
	defer f.Close()
	r := bufio.NewReader(f)
	for {
		ln, err := r.ReadBytes('\n')
		if len(ln) == 0 && err != nil {
			break
		}
		line := string(bytes.TrimSpace(ln))
		if line == "" {
			continue
		}

		mark := parseKVHex(line, "mark")

		proto := "tcp"
		if strings.Contains(line, " udp ") {
			proto = "udp"
		}
		srcIP := parseKV(line, "src")
		dstIP := parseKV(line, "dst")
		sport := int(parseKVUint(line, "sport"))
		dport := int(parseKVUint(line, "dport"))

		uid, owned := k.claimUID(proto, srcIP, sport, dstIP, dport, ruleShort, mark)
		if !owned {
			continue
		}

		up := parseKVUint(line, "bytes")
		down := parseKVUintSecond(line, "bytes")

		kx := ctKey{s: fmt.Sprintf("%s|%s|%d|%s|%d", proto, srcIP, sport, dstIP, dport)}
		out[kx] = ctRec{
			up: up, down: down,
			srcIP: srcIP, srcPort: sport,
			dstIP: dstIP, dstPort: dport,
			proto: proto, userID: uid,
		}
	}
	return out
}

func (k *linuxKernel) startStatsEvents(ctx context.Context, ruleID int64, hooks Hooks) error {
	ruleShort := short16(ruleID)

	// 订阅 UPDATE+DESTROY；DESTROY 仍兜底，UPDATE 用来“判定可提前关闭”
	cmd := exec.CommandContext(ctx, "conntrack", "-E", "-e", "UPDATE,DESTROY", "-o", "timestamp,extended")
	stdout, err1 := cmd.StdoutPipe()
	if err1 != nil {
		return fmt.Errorf("conntrack StdoutPipe: %w", err1)
	}
	stderr, err2 := cmd.StderrPipe()
	if err2 != nil {
		return fmt.Errorf("conntrack StderrPipe: %w", err2)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("conntrack start failed: %w", err)
	}

	// 首次握手
	failCh := make(chan error, 1)
	readyCh := make(chan struct{}, 1)
	go func() {
		b, _ := ioReadAllLimit(stderr, 4<<10)
		s := strings.ToLower(strings.TrimSpace(string(b)))
		if s != "" && (strings.Contains(s, "bad parameter") || strings.Contains(s, "invalid") || strings.Contains(s, "permission")) {
			failCh <- fmt.Errorf("conntrack options/permission error: %s", s)
			return
		}
		if s != "" {
			natLinuxLog.Warnf("[rule %d] conntrack stderr: %s", ruleID, strings.TrimSpace(string(b)))
		}
		readyCh <- struct{}{}
	}()
	select {
	case err := <-failCh:
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return err
	case <-readyCh:
	case <-time.After(500 * time.Millisecond):
	}
	// 持续 drain stderr，防止阻塞
	go func(r io.Reader) { _, _ = io.Copy(io.Discard, r) }(stderr)

	// 主循环（失败后指数退避重拉）
	go func() {
		backoff := time.Second
		for {
			natLinuxLog.Infof("[rule %d] conntrack stats started (events)", ruleID)

			sc := bufio.NewScanner(stdout)
			buf := make([]byte, 0, 128<<10)
			sc.Buffer(buf, 256<<10)

		readLoop:
			for sc.Scan() {
				if ctx.Err() != nil {
					break readLoop
				}
				line := sc.Text()

				// 解析 5 元组（orig 方向）
				proto := "tcp"
				if strings.Contains(line, " udp ") {
					proto = "udp"
				}
				srcIP := parseKV(line, "src")
				dstIP := parseKV(line, "dst")
				sport := int(parseKVUint(line, "sport"))
				dport := int(parseKVUint(line, "dport"))

				// 认领：先看 mark，再回退到 5 元组缓存
				mark := parseKVHex(line, "mark")
				uid, owned := k.claimUID(proto, srcIP, sport, dstIP, dport, ruleShort, mark)
				if !owned {
					continue
				}

				// --- DESTROY：内核自带 bytes=，直接上报 ---
				if strings.Contains(line, "[DESTROY]") {
					up := parseKVUint(line, "bytes")
					down := parseKVUintSecond(line, "bytes")
					rec := ctRec{
						up: up, down: down,
						start: time.Time{},
						srcIP: srcIP, srcPort: sport,
						dstIP: dstIP, dstPort: dport,
						proto: proto, userID: uid,
					}
					k.emitCloseOnce(ruleID, rec, hooks)
					continue
				}

				// --- UPDATE：当进入“几乎结束”的 TCP 状态，主动删除该 conntrack 条目以立刻触发 DESTROY ---
				if proto == "tcp" {
					if state, ttl, ok := parseTCPState(line); ok {
						switch state {
						// 这些状态基本已收尾；包含有的内核只给 "FIN_WAIT" 的情况
						case "LAST_ACK", "TIME_WAIT", "CLOSE_WAIT", "CLOSING", "FIN_WAIT", "FIN_WAIT1", "FIN_WAIT2":
							// UPDATE 事件一般会带 TTL（DESTROY 没 TTL）；仅在 UPDATE 时给内核一点时间把 bytes 写进去
							if ttl >= 0 {
								time.Sleep(80 * time.Millisecond)
							}
							// 用 orig 方向精确删除，触发立刻的 DESTROY（带 bytes=...）
							_ = exec.CommandContext(ctx, "conntrack",
								"-D", "-p", "tcp",
								"-s", srcIP, "-d", dstIP,
								"--sport", fmt.Sprint(sport), "--dport", fmt.Sprint(dport),
							).Run()
						}
					}
				}

			}

			if err := sc.Err(); err != nil && ctx.Err() == nil {
				natLinuxLog.Errorf("[rule %d] conntrack scan error: %v", ruleID, err)
			}
			_ = cmd.Wait()
			if ctx.Err() != nil {
				return
			}

			// 重启订阅
			time.Sleep(backoff)
			if backoff < 5*time.Second {
				backoff *= 2
			}
			cmd = exec.CommandContext(ctx, "conntrack", "-E", "-e", "UPDATE,DESTROY", "-o", "timestamp,extended")
			stdout, _ = cmd.StdoutPipe()
			stderr, _ = cmd.StderrPipe()
			if err := cmd.Start(); err != nil {
				natLinuxLog.Errorf("[rule %d] conntrack restart failed: %v", ruleID, err)
				continue
			}
			go func(r io.Reader) { _, _ = io.Copy(io.Discard, r) }(stderr)
		}
	}()

	return nil
}

// ---------- 通用工具 ----------

// parseTCPState 解析 conntrack 行里的 TCP 状态和 TTL（若有）。
// 兼容：
//
//	[UPDATE] ... tcp 6 432000 ESTABLISHED ...
//	[DESTROY] ... tcp 6 TIME_WAIT ...
//
// 返回: state, ttl(无则为 -1), ok
func parseTCPState(line string) (string, int, bool) {
	// 快速排除非 TCP
	if !strings.Contains(line, " tcp ") {
		return "", 0, false
	}
	fields := strings.Fields(line)
	for i := 0; i < len(fields); i++ {
		if fields[i] == "tcp" {
			// 期望: tcp 6 <ttl?> <state>
			if i+2 >= len(fields) {
				return "", 0, false
			}
			// 跳过协议号 6，尝试把下一个字段当作 TTL
			// UPDATE 场景: fields[i+2] 是 TTL，fields[i+3] 是状态
			// DESTROY 场景: fields[i+2] 就是状态（没有 TTL）
			if i+3 < len(fields) {
				if n, err := strconv.Atoi(fields[i+2]); err == nil {
					return fields[i+3], n, true
				}
			}
			// 没有 TTL，只返回状态
			return fields[i+2], -1, true
		}
	}
	return "", 0, false
}

// 返回该 5 元组是否存在认证阶段留下的 uid 映射
func (k *linuxKernel) uidTupleKnown(proto, srcIP string, srcPort int, dstIP string, dstPort int) (int64, bool) {
	key := fmt.Sprintf("%s|%s|%d|%s|%d", proto, srcIP, srcPort, dstIP, dstPort)
	k.uidMu.RLock()
	uid, ok := k.uidBy5t[key]
	k.uidMu.RUnlock()
	return uid, ok
}

func tryNotify(ch chan struct{}) {
	if ch == nil {
		return
	}
	select {
	case ch <- struct{}{}:
	default:
	}
}

func waitReady(ctx context.Context, ch chan struct{}, d time.Duration) error {
	if ch == nil {
		return errors.New("nil ready channel")
	}
	select {
	case <-ch:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d):
		return errors.New("ready timeout")
	}
}

func be16(v uint16) []byte { b := make([]byte, 2); binary.BigEndian.PutUint16(b, v); return b }

func ctProcPath() string {
	for _, p := range []string{"/proc/net/nf_conntrack", "/proc/net/ip_conntrack"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

const (
	ipprotoTCP = 6
	ipprotoUDP = 17
)

type p5 struct {
	Proto, SrcIP, DstIP string
	SrcPort, DstPort    uint16
}

func parse5TuplePtr(pb *[]byte) (p p5, ok bool) {
	if pb == nil || *pb == nil {
		return p, false
	}
	return parse5Tuple(*pb)
}

func parse5Tuple(b []byte) (p p5, ok bool) {
	if len(b) < 1 {
		return p, false
	}
	switch b[0] >> 4 {
	case 4:
		// IPv4 header >= 20 bytes
		if len(b) < 20 {
			return p, false
		}
		l4 := b[9]
		src := net.IP(b[12:16])
		dst := net.IP(b[16:20])
		p.SrcIP, p.DstIP = src.String(), dst.String()

		off := int(b[0]&0x0f) * 4
		if len(b) < off+4 {
			return p, false
		}

		switch l4 {
		case ipprotoTCP:
			p.Proto = "tcp"
		case ipprotoUDP:
			p.Proto = "udp"
		default:
			return p, false
		}
		p.SrcPort = binary.BigEndian.Uint16(b[off : off+2])
		p.DstPort = binary.BigEndian.Uint16(b[off+2 : off+4])
		return p, true

	case 6:
		// IPv6 basic header = 40 bytes（若有扩展头，这里做最小守护：不足 44 直接返回）
		if len(b) < 44 {
			return p, false
		}
		l4 := b[6]
		src := net.IP(b[8:24])
		dst := net.IP(b[24:40])
		p.SrcIP, p.DstIP = src.String(), dst.String()

		switch l4 {
		case ipprotoTCP:
			p.Proto = "tcp"
		case ipprotoUDP:
			p.Proto = "udp"
		default:
			return p, false
		}

		// 简化：假定无扩展头，L4 端口在 40:44。若有 EH，会被丢弃（后续可升级遍历 EH）
		p.SrcPort = binary.BigEndian.Uint16(b[40:42])
		p.DstPort = binary.BigEndian.Uint16(b[42:44])
		return p, true

	default:
		return p, false
	}
}

func parseKV(s, key string) string {
	idx := strings.Index(s, key+"=")
	if idx < 0 {
		return ""
	}
	s2 := s[idx+len(key)+1:]
	if i := strings.IndexByte(s2, ' '); i >= 0 {
		return s2[:i]
	}
	return s2
}
func parseKVUint(s, key string) uint64 {
	v := parseKV(s, key)
	n, _ := strconv.ParseUint(v, 10, 64)
	return n
}
func parseKVUintSecond(s, key string) uint64 {
	needle := key + "="
	i1 := strings.Index(s, needle)
	if i1 < 0 {
		return 0
	}
	rest := s[i1+len(needle):]
	i2 := strings.Index(rest, needle)
	if i2 < 0 {
		return 0
	}
	valStart := i1 + len(needle) + i2 + len(needle)
	part := s[valStart:]
	if j := strings.IndexByte(part, ' '); j >= 0 {
		part = part[:j]
	}
	n, _ := strconv.ParseUint(part, 10, 64)
	return n
}

var lastRC int

func ipt(bin string, args ...string) error {
	args = append([]string{"-w", "3"}, args...) // 等待 xtables 锁，最多 3s
	cmd := exec.Command(bin, args...)
	out, err := cmd.CombinedOutput()

	// 正确设置 lastRC：区分 ExitError 和其他失败
	if ee, ok := err.(*exec.ExitError); ok {
		lastRC = ee.ExitCode()
	} else if err != nil {
		lastRC = 1 // 非 ExitError 但确实失败（如 *exec.Error）
	} else {
		lastRC = 0
	}

	if err != nil {
		natLinuxLog.Errorf("%s %s -> err=%v, out=%s",
			bin, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		return err
	}
	return nil
}

// iptWarn：执行 ip(6)tables，失败只打 Warn（用于卸载路径）
func iptWarn(bin string, args ...string) error {
	args = append([]string{"-w", "3"}, args...)
	cmd := exec.Command(bin, args...)
	out, err := cmd.CombinedOutput()

	// 正确设置 lastRC
	if ee, ok := err.(*exec.ExitError); ok {
		lastRC = ee.ExitCode()
	} else if err != nil {
		lastRC = 1
	} else {
		lastRC = 0
	}

	if err != nil {
		natLinuxLog.Warnf("%s %s -> rc=%d, out=%s",
			bin, strings.Join(args, " "), lastRC, strings.TrimSpace(string(out)))
		return err
	}
	return nil
}

// iptNoLog：静默检查（仅更新 lastRC）
func iptNoLog(bin string, args ...string) error {
	args = append([]string{"-w", "3"}, args...)
	cmd := exec.Command(bin, args...)
	out, err := cmd.CombinedOutput()
	_ = out

	// 正确设置 lastRC
	if ee, ok := err.(*exec.ExitError); ok {
		lastRC = ee.ExitCode()
	} else if err != nil {
		lastRC = 1
	} else {
		lastRC = 0
	}
	return err
}

func ensureJump(bin, table, base, tag, chain string) error {
	// 先检查无 comment 的是否已存在
	_ = iptNoLog(bin, "-t", table, "-C", base, "-j", chain)
	if lastRC == 0 {
		return nil
	}
	// 再检查带 comment 的是否已存在
	_ = iptNoLog(bin, "-t", table, "-C", base, "-m", "comment", "--comment", tag, "-j", chain)
	if lastRC == 0 {
		return nil
	}

	// 优先尝试插在第一条（带 comment）
	if err := ipt(bin, "-t", table, "-I", base, "1", "-m", "comment", "--comment", tag, "-j", chain); err == nil {
		return nil
	}
	// 尝试不带 comment 的插入
	if err := ipt(bin, "-t", table, "-I", base, "1", "-j", chain); err == nil {
		return nil
	}
	// 退化为追加（带 comment）
	if err := ipt(bin, "-t", table, "-A", base, "-m", "comment", "--comment", tag, "-j", chain); err == nil {
		return nil
	}
	// 再退化为无 comment 追加
	if err := ipt(bin, "-t", table, "-A", base, "-j", chain); err == nil {
		return nil
	}
	return fmt.Errorf("ensureJump: failed to add jump %s/%s -> %s", table, base, chain)
}

func hasBinary(name string) bool   { _, err := exec.LookPath(name); return err == nil }
func readFileTrim(p string) string { b, _ := os.ReadFile(p); return strings.TrimSpace(string(b)) }
func writeProc(p, v string) error  { return os.WriteFile(p, []byte(v), 0644) }
func ioReadAllLimit(r io.Reader, max int64) ([]byte, error) {
	var buf bytes.Buffer
	buf.Grow(4096)
	_, err := io.CopyN(&buf, r, max)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return buf.Bytes(), nil
}

// 把“不支持/无权限”的错误规范化，便于上层 fallback（仍保留以防后续用到）
func mapUnsupported(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, syscall.EOPNOTSUPP) || errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
		return ErrUnsupported
	}
	s := strings.ToLower(err.Error())
	if strings.Contains(s, "operation not supported") || strings.Contains(s, "not supported") || strings.Contains(s, "permission denied") {
		return ErrUnsupported
	}
	return err
}

func parseKVHex(s, key string) uint64 {
	v := parseKV(s, key)
	if strings.HasPrefix(v, "0x") || strings.HasPrefix(v, "0X") {
		n, _ := strconv.ParseUint(v[2:], 16, 64)
		return n
	}
	n, _ := strconv.ParseUint(v, 10, 64)
	return n
}

func ifEmpty(s, d string) string {
	if strings.TrimSpace(s) == "" {
		return d
	}
	return s
}

func short16(x int64) uint16 {
	u := uint64(x)
	return uint16(u ^ (u >> 16) ^ (u >> 32) ^ (u >> 48))
}
func qnumFromRule(ruleID int64) uint16 {
	const base = 1024
	const max = 65535
	return uint16(uint64(base) + (uint64(short16(ruleID)) % uint64(max-base)))
}
