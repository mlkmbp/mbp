package common

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
	"mlkmbp/mbp/model"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const AESkye = "8ocguXJRslUM1njyCmpV5YUvIH5Ma01mBObj9RpyJRM"

const PK = "Hk_NBtK2-aYHFclhGY0WpttNY2Mm_fH5Wr2krE-scjg"

const AAD = "mlkmbp|license|v1"

type LicenseCfg struct {
	User        bool      `json:"user"`
	Rule        bool      `json:"rule"`
	Pve         bool      `json:"pve"`
	RunTime     time.Time `json:"run_time"`     // 超过该时间不可用
	MachineCode string    `json:"machine_code"` // 许可绑定的机器码
}

func TimeAndMachineCode(runTime time.Time, machineCode string) (bool, string) {
	if time.Now().After(runTime) {
		return false, "license expired"
	}
	// 机器码限制
	want := strings.TrimSpace(machineCode)
	have, _ := StableMachineID()
	if want != "" && !strings.EqualFold(want, have) {
		return false, "license not valid for this machine " + have
	}
	return true, ""
}

func PasswordOK(dbPlain, dbSHA256, inputPlain string) bool {
	if dbPlain != "" && dbPlain == inputPlain {
		return true
	}
	if dbSHA256 != "" && dbSHA256 == inputPlain {
		return true
	}
	return false
}

func StatusOK(s string) bool { return strings.EqualFold(s, "enabled") }

func QuotaOK(limit, up, down int64) bool {
	if limit <= 0 {
		return true // 0/负数 => 不限
	}
	return (up + down) <= limit
}

func GetPage(c *gin.Context) (page, size int) {
	page, _ = strconv.Atoi(c.DefaultQuery("page", "1"))
	size, _ = strconv.Atoi(c.DefaultQuery("size", "10"))
	if page < 1 {
		page = 1
	}
	if size <= 0 || size > 200 {
		size = 10
	}
	return
}

func IsAdminID(adminIDs []int, id int64) bool {
	for _, v := range adminIDs {
		if int64(v) == id {
			return true
		}
	}
	return false
}

func GetAuth(c *gin.Context) (uid int64, isAdmin bool) {
	if v, ok := c.Get("uid"); ok {
		switch t := v.(type) {
		case int64:
			uid = t
		case int:
			uid = int64(t)
		}
	}
	if v, ok := c.Get("isAdmin"); ok {
		if b, ok := v.(bool); ok {
			isAdmin = b
		}
	}
	return
}

/******** Helpers ********/

func BuildTargetAddr(r *model.Rule) string {
	addr := r.TargetAddress
	port := r.TargetPort
	switch r.Protocol {
	case "socks5", "tls-socks5", "http/s", "tls-http/s", "tls-tcp":
		// 代理协议允许留空：动态目的地
		if addr == "" || port == 0 {
			return ""
		}
	default:
		// 非代理协议必须固定目标
		if addr == "" || port == 0 {
			return ""
		}
	}
	return net.JoinHostPort(addr, fmt.Sprintf("%d", port))
}

/* -------------------- 小工具 -------------------- */

func Max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func SafeShowTarget(target string) string {
	if target == "" {
		return "(dynamic by protocol)"
	}
	return target
}

// password_sha256 = SHA256(password)
func HashUP(pass string) string {
	sum := sha256.Sum256([]byte(pass))
	return hex.EncodeToString(sum[:])
}

// 统一拆三端地址：监听、来源、目标
func ParseAddrPorts(listen, remote, target string) (
	lh string, lp int,
	sh string, sp int,
	th string, tp int,
) {
	lh, lp = SplitHostPortFlexible(listen, 0)
	sh, sp = SplitHostPortFlexible(remote, 0)
	th, tp = SplitHostPortFlexible(target, 0)
	return
}

// 兼容 IPv4/IPv6/域名、有无端口的拆解器
func SplitHostPortFlexible(s string, defPort int) (host string, port int) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", 0
	}
	// 标准形态优先（host:port / [v6]:port）
	if strings.Contains(s, "]") || (strings.Count(s, ":") == 1 && !strings.Contains(s, "::")) {
		if h, p, err := net.SplitHostPort(s); err == nil {
			if n, e := strconv.Atoi(p); e == nil {
				return h, n
			}
		}
	}
	// [v6] 无端口
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		return s[1 : len(s)-1], defPort
	}
	// 纯 IPv6（无 []，多冒号）当无端口
	if strings.Count(s, ":") >= 2 {
		return s, defPort
	}
	// IPv4/域名无端口
	if !strings.Contains(s, ":") {
		return s, defPort
	}
	// 兜底：按最后一个冒号切
	if i := strings.LastIndexByte(s, ':'); i > 0 && i < len(s)-1 {
		h := s[:i]
		if n, e := strconv.Atoi(s[i+1:]); e == nil {
			return h, n
		}
	}
	return s, defPort
}

// —— 新增：工具函数 ——

// 非零最小值（<=0 视为“不限”被忽略；全为 0 则返回 0）
func MinNonZero(vals ...int64) int64 {
	var m int64
	for _, v := range vals {
		if v <= 0 {
			continue
		}
		if m == 0 || v < m {
			m = v
		}
	}
	return m
}

// 构造单连接整形器：limit 为 bps；burst 用 hint/10，至少为 1
func MkShaper(limitBps, burstHintBps int64) *rate.Limiter {
	if limitBps <= 0 {
		return nil
	}
	burst := int(Max64(1, burstHintBps/10))
	return rate.NewLimiter(rate.Limit(limitBps), burst)
}

type MultiLimiter []*rate.Limiter

func (ml MultiLimiter) WaitN(ctx context.Context, n int) error {
	for _, l := range ml {
		if l == nil {
			continue
		}
		if err := l.WaitN(ctx, n); err != nil {
			return err
		}
	}
	return nil
}

// 工具：把若干 limiter 组合起来（nil 会被忽略）
func Compose(lims ...*rate.Limiter) MultiLimiter {
	out := make(MultiLimiter, 0, len(lims))
	for _, l := range lims {
		if l != nil {
			out = append(out, l)
		}
	}
	return out
}

// readPEMorFile: 若字符串本身包含 "-----BEGIN" 则视为 PEM 内容，否则按路径读取文件
func ReadPEMorFile(s string) ([]byte, error) {
	if looksLikePEM(s) {
		return []byte(s), nil
	}
	// 兼容相对路径
	b, err := os.ReadFile(filepath.Clean(s))
	if err != nil {
		return nil, err
	}
	return b, nil
}

func looksLikePEM(s string) bool {
	// 简单判断：包含 PEM 起始头即可
	return strings.Contains(s, "-----BEGIN ")
}

// 解析逗号分隔的域名/通配符；空串 => 禁用
func ParseGuardList(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.ToLower(strings.TrimSpace(p))
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// 支持通配符 "*.example.com"；其余精确匹配（大小写不敏感）
func MatchAnyHostPattern(host string, patterns []string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	for _, pat := range patterns {
		if wildcardMatch(host, pat) {
			return true
		}
	}
	return false
}

func wildcardMatch(host, pattern string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	if pattern == "" {
		return false
	}
	// 精确
	if !strings.Contains(pattern, "*") {
		return host == pattern
	}
	// 仅支持前缀通配形式：*.example.com
	if strings.HasPrefix(pattern, "*.") {
		suffix := strings.TrimPrefix(pattern, "*.")
		// host 必须是 suffix 的子域，且多一段以上
		return host == suffix || strings.HasSuffix(host, "."+suffix)
	}
	// 其它复杂通配不支持，退化为相等
	return host == pattern
}

func CloseWriteIfTCP(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}
}

func Nudge(c net.Conn) {
	_ = c.SetReadDeadline(time.Now())  // 让阻塞读立刻返回
	_ = c.SetWriteDeadline(time.Now()) // 让阻塞写立刻返回
}

// 从 net.Conn 取远端 IP（适配 TCP / “已连接”的 UDP）
func RemoteIPFromConn(c net.Conn) string {
	if c == nil {
		return ""
	}
	return RemoteIPFromAddr(c.RemoteAddr())
}

// 从 net.Addr 取远端 IP（适配 UDP 的 ReadFrom/ReadFromUDP 返回的 raddr）
func RemoteIPFromAddr(a net.Addr) string {
	if a == nil {
		return ""
	}

	switch v := a.(type) {
	case *net.TCPAddr:
		return normalizeIP(v.IP.String())
	case *net.UDPAddr:
		return normalizeIP(v.IP.String())
	default:
		// 兜底：从 "ip:port" 或 "[v6]:port" 里切出 ip
		// 先试 netip.ParseAddrPort
		if ap, err := netip.ParseAddrPort(a.String()); err == nil {
			return normalizeIP(ap.Addr().String())
		}
		// 再试只解析 Addr（有些实现没有端口）
		if ad, err := netip.ParseAddr(a.String()); err == nil {
			return normalizeIP(ad.String())
		}
		// 最后简单拆分
		s := a.String()
		s = strings.TrimPrefix(s, "[")
		if i := strings.IndexByte(s, ']'); i >= 0 {
			return normalizeIP(s[:i])
		}
		if i := strings.LastIndexByte(s, ':'); i > 0 {
			return normalizeIP(s[:i])
		}
		return normalizeIP(s)
	}
}

// 归一化：去掉空串、去掉多余空格；IPv6 直接返回无中括号形式
func normalizeIP(s string) string {
	return strings.TrimSpace(s)
}

func IsDesktop() bool { // Win/macOS 视为“开发机”
	return runtime.GOOS == "windows" || runtime.GOOS == "darwin"
}

// 解析 host:port；没有端口时返回默认端口
func SplitHostPortDefault(hostport string, def int) (host string, port int) {
	if strings.Contains(hostport, ":") {
		h, pStr, err := net.SplitHostPort(hostport)
		if err == nil {
			if n, e := strconv.Atoi(pStr); e == nil {
				return h, n
			}
		}
	}
	return hostport, def
}

// StableMachineID 返回“尽可能不会变”的设备标识：
// Linux 取 /sys/class/dmi/id/product_uuid
// macOS 取 IOPlatformUUID
// Windows 取注册表 HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid
// 拿不到就直接返回 error；不做兜底、不做缓存。
func StableMachineID() (string, error) {
	norm := func(s string) string {
		s = strings.TrimSpace(s)
		s = strings.Trim(s, "{}")
		s = strings.ReplaceAll(s, "-", "")
		s = strings.ReplaceAll(s, ":", "")
		return strings.ToUpper(s)
	}

	switch runtime.GOOS {
	case "linux":
		// 硬件级 UUID（主板 SMBIOS）
		paths := []string{
			"/sys/class/dmi/id/product_uuid",
			"/sys/devices/virtual/dmi/id/product_uuid",
		}
		for _, p := range paths {
			if b, err := os.ReadFile(p); err == nil {
				v := strings.TrimSpace(string(b))
				if v != "" && v != "unknown" && v != "None" {
					return norm(v), nil
				}
			}
		}
		return "", fmt.Errorf("no product_uuid")

	case "darwin":
		// macOS: IOPlatformUUID
		out, err := exec.Command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output()
		if err != nil {
			return "", fmt.Errorf("ioreg: %w", err)
		}
		re := regexp.MustCompile(`"IOPlatformUUID"\s*=\s*"([^"]+)"`)
		m := re.FindSubmatch(out)
		if len(m) != 2 {
			return "", fmt.Errorf("IOPlatformUUID not found")
		}
		return norm(string(m[1])), nil

	case "windows":
		// Windows: 注册表 MachineGuid
		out, err := exec.Command("reg", "query", `HKLM\SOFTWARE\Microsoft\Cryptography`, "/v", "MachineGuid").Output()
		if err != nil {
			return "", fmt.Errorf("reg query: %w", err)
		}
		re := regexp.MustCompile(`MachineGuid\s+REG_SZ\s+([A-Fa-f0-9-]+)`)
		m := re.FindSubmatch(out)
		if len(m) != 2 {
			return "", fmt.Errorf("MachineGuid not found")
		}
		return norm(string(m[1])), nil

	default:
		return "", fmt.Errorf("unsupported os: %s", runtime.GOOS)
	}
}

// —— 工具结构 —— //
type diskParsed struct {
	Store   string // local / local-lvm ...
	Vol     string // vm-100-disk-0 / subvol-...
	SizeGB  int
	HasSize bool
}

// 解析 scsi0/sata0/virtio0 值: "local-lvm:vm-100-disk-0,discard=on,size=20G"
func ParseDiskConf(s string) diskParsed {
	s = strings.TrimSpace(s)
	if s == "" {
		return diskParsed{}
	}
	// 先拆逗号
	parts := strings.Split(s, ",")
	// 第一个是 store:vol 或 store:size
	st := parts[0]
	stKV := strings.SplitN(st, ":", 2)
	if len(stKV) != 2 {
		return diskParsed{}
	}
	out := diskParsed{}
	out.Store = strings.TrimSpace(stKV[0])
	right := strings.TrimSpace(stKV[1])

	// 尝试匹配 size=XXG
	for _, p := range parts[1:] {
		p = strings.TrimSpace(p)
		if strings.HasPrefix(p, "size=") {
			v := strings.TrimPrefix(p, "size=")
			v = strings.TrimSpace(strings.ToUpper(v)) // "20G"
			if strings.HasSuffix(v, "G") {
				if n, err := strconv.Atoi(strings.TrimSuffix(v, "G")); err == nil && n > 0 {
					out.SizeGB = n
					out.HasSize = true
				}
			}
		}
	}

	// right 可能是 "vm-100-disk-0"（已有卷） 或 "32"（表示新建）
	if n, err := strconv.Atoi(right); err == nil && n > 0 {
		out.SizeGB = n
		out.HasSize = true
		// 新建场景没有 Vol
	} else {
		out.Vol = right
	}
	return out
}

var reFmtMissing = regexp.MustCompile(`%!\w+\(MISSING(?:=[^)]*)?\)`)

func AnyToString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case []byte:
		return string(x)
	default:
		s := fmt.Sprint(v)
		s = reFmtMissing.ReplaceAllString(s, "")
		s = strings.TrimSpace(strings.Trim(s, `"'`))
		if s != "" {
			s = strings.Join(strings.Fields(s), " ")
		}
		return s
	}
}
