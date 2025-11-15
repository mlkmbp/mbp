package policy

import (
	"context"
	"fmt"
	"mlkmbp/mbp/common/logx"
	"mlkmbp/mbp/db"
	"mlkmbp/mbp/db/dao"
	"mlkmbp/mbp/model"
	"net"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
)

/******** 对外结构 ********/

type Decision struct {
	Matched bool

	MatcherId int64
	Action    string

	PolicyForwardId int64
	Protocol        string
	TargetAddress   string

	AuthUser       string
	AuthPass       string
	SkipCertVerify bool
	ALPN           string
	TLSFingerprint string
	TLSSNIGuard    string
}

/******** 可初始化的 Decider ********/

type Decider struct {
	ctx   context.Context
	fwdDB *db.DB
	log   *logx.Logger
}

func NewDecider(ctx context.Context, fwdDB *db.DB) Decider {
	dec := Decider{
		ctx:   ctx,
		fwdDB: fwdDB,
		log:   logx.New(logx.WithPrefix("policy")), // 默认用全局等级+该前缀
	}
	return dec
}

// Decide：给 2 个 userId（uid/gid）、可选 ruleId（0=不限定）、目标地址 dest（host / host:port / IP）
// 决策：direct / forward / reject
func (d *Decider) Decide(uid, gid, ruleId int64, dest string) (Decision, error) {
	host := strings.TrimSpace(dest)
	if host == "" {
		d.log.Debugf("Decide: empty dest -> direct")
		return Decision{Matched: false, Action: model.ActionDirect}, nil
	}
	if isLocalhostOrLoopback(dest) {
		d.log.Debugf("Decide: local-target protected -> reject, target=%s", dest)
		return Decision{Matched: false, Action: model.ActionReject}, nil
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	// 预处理：解析为 IP 或域名（小写+去尾点+IDNA），并生成反转域名
	var (
		ip16     []byte
		ipOK     = 0
		hostNorm string
		revHost  string
		hostOK   = 0
	)
	if ip := net.ParseIP(host); ip != nil {
		ip16 = ipTo16(ip)
		ipOK = 1
		d.log.Debugf("Decide: dest is IP: %s", host)
	} else {
		if d0, err := normalizeDomain(host); err == nil && d0 != "" {
			hostNorm = d0
			revHost = reverseLabels(d0)
			hostOK = 1
			d.log.Debugf("Decide: dest is domain: %s", hostNorm)
		} else {
			d.log.Debugf("Decide: invalid dest: %s -> direct", host)
			return Decision{Matched: false, Action: model.ActionDirect}, nil
		}
	}

	// 查询候选
	d.log.Debugf("Decide: query candidates uid=%d gid=%d rule=%d", uid, gid, ruleId)
	rows, err := dao.QueryPolicyCandidates(d.ctx, d.fwdDB,
		uid, gid, ruleId, ipOK, ip16, hostOK, hostNorm, revHost)
	if err != nil {
		d.log.Errorf("Decide: query error: %v", err)
		return Decision{Matched: false, Action: model.ActionDirect}, err
	}

	// 选全局最优：用户专属优先 -> priority DESC -> id DESC
	d.log.Debugf("Decide: candidates=%d", len(rows))
	best := pickBest(uid, rows)
	if best == nil {
		d.log.Debugf("Decide: no match -> direct")
		return Decision{Matched: false, Action: model.ActionDirect}, nil
	}

	dec := Decision{Matched: true, MatcherId: best.Id, Action: best.Action}
	if dec.Action == model.ActionForward && best.PolicyForwardId > 0 {
		dec.PolicyForwardId = best.PolicyForwardId
		d.log.Debugf("Decide: forward pfid=%d", best.PolicyForwardId)
		if err := fillForward(d.ctx, d.fwdDB, &dec); err != nil {
			d.log.Errorf("Decide: fill forward error: %v -> direct", err)
			dec.Action = model.ActionDirect
			dec.PolicyForwardId = 0
		} else {
			// 本机地址保护：目标若是 loopback/localhost/0.0.0.0 等，改为拒绝
			if isLocalhostOrLoopback(dec.TargetAddress) {
				dec.Action = "reject"
				d.log.Debugf("Decide: local-target protected -> reject, target=%s", dec.TargetAddress)
			}
		}
	}

	d.log.Debugf("Decide: final=%+v", dec)
	return dec, nil
}

/******** 内部辅助 ********/

func pickBest(uid int64, list []model.PolicyMatcher) *model.PolicyMatcher {
	if len(list) == 0 {
		return nil
	}
	sort.Slice(list, func(i, j int) bool {
		iu := boolToInt(list[i].UserId == uid)
		ju := boolToInt(list[j].UserId == uid)
		if iu != ju {
			return iu > ju
		}
		if list[i].Priority != list[j].Priority {
			return list[i].Priority > list[j].Priority
		}
		return list[i].Id > list[j].Id
	})
	return &list[0]
}

func fillForward(ctx context.Context, fwdDB *db.DB, d *Decision) error {
	if d.Action != model.ActionForward || d.PolicyForwardId <= 0 {
		return nil
	}
	r, err := dao.GetPolicyForwardById(ctx, fwdDB.GormDataSource, d.PolicyForwardId)
	if err != nil || r == nil {
		return fmt.Errorf("policy_forward not found")
	}

	d.Protocol = r.Protocol
	if r.TargetAddress != "" && r.TargetPort > 0 {
		d.TargetAddress = net.JoinHostPort(r.TargetAddress, strconv.Itoa(r.TargetPort))
	}
	d.AuthUser = r.AuthUsername
	d.AuthPass = r.AuthPassword
	d.SkipCertVerify = r.SkipCertVerify
	d.ALPN = r.ALPN
	d.TLSFingerprint = r.TLSFingerprint
	d.TLSSNIGuard = r.TLSSNIGuard
	return nil
}

// IPv4/IPv6 统一为 16 字节（IPv4 放后4字节）
func ipTo16(ip net.IP) []byte {
	if ip == nil {
		return nil
	}
	if v4 := ip.To4(); v4 != nil {
		b := make([]byte, 16)
		copy(b[12:], v4)
		return b
	}
	v16 := ip.To16()
	if v16 == nil {
		return nil
	}
	b := make([]byte, 16)
	copy(b, v16)
	return b
}

// 小写 + 去尾点 + IDNA -> ASCII
func normalizeDomain(s string) (string, error) {
	s = strings.TrimSpace(strings.ToLower(strings.TrimSuffix(s, ".")))
	if s == "" {
		return "", nil
	}
	ascii, err := idna.ToASCII(s)
	if err != nil {
		return "", err
	}
	return ascii, nil
}

// 反转标签顺序：a.b.mbp -> mbp.b.a
func reverseLabels(d string) string {
	if d == "" {
		return ""
	}
	parts := strings.Split(d, ".")
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	return strings.Join(parts, ".")
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// 本机/环回/不可外连的地址保护
func isLocalhostOrLoopback(addr string) bool {
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return false
	}
	if host == "localhost" {
		return true
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() {
		return true
	} // 127.0.0.0/8, ::1
	// 也顺带保护 0.0.0.0 / ::（无意义目标）
	if ip.IsUnspecified() {
		return true
	}
	return false
}
