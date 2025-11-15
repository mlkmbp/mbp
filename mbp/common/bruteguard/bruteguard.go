package bruteguard

import (
	"mlkmbp/mbp/common/logx"
	"strings"
	"sync"
	"time"
)

/********** 配置 **********/
type Config struct {
	// 失败计数的时间窗；超出后“软清零” fails（不影响已生效的锁）
	Window time.Duration

	// 达阈值直接封禁；未达阈值走指数退避
	MaxFails    int
	Cooldown    time.Duration
	BaseBackoff time.Duration
	MaxBackoff  time.Duration

	// 内存清理
	GCInterval time.Duration
	AliveFor   time.Duration
}

func defaultConfig() Config {
	return Config{
		Window:      15 * time.Minute,
		MaxFails:    10,
		Cooldown:    15 * time.Minute,
		BaseBackoff: 2 * time.Second,
		MaxBackoff:  30 * time.Second,
		GCInterval:  time.Minute,
		AliveFor:    24 * time.Hour,
	}
}

/********** 运行时结构 **********/
type entry struct {
	fails       int
	lastFail    time.Time
	lockedUntil time.Time
	lastSeen    time.Time
}

type Guard struct {
	cfg Config

	mu     sync.Mutex
	store  map[string]*entry
	lastGC time.Time
	now    func() time.Time

	clearIPOnSuccess bool
	log              *logx.Logger
}

func New(cfg Config) *Guard {
	def := defaultConfig()
	if cfg.Window <= 0 {
		cfg.Window = def.Window
	}
	if cfg.MaxFails <= 0 {
		cfg.MaxFails = def.MaxFails
	}
	if cfg.Cooldown <= 0 {
		cfg.Cooldown = def.Cooldown
	}
	if cfg.BaseBackoff <= 0 {
		cfg.BaseBackoff = def.BaseBackoff
	}
	if cfg.MaxBackoff <= 0 {
		cfg.MaxBackoff = def.MaxBackoff
	}
	if cfg.GCInterval <= 0 {
		cfg.GCInterval = def.GCInterval
	}
	if cfg.AliveFor <= 0 {
		cfg.AliveFor = def.AliveFor
	}

	g := &Guard{
		cfg:   cfg,
		store: make(map[string]*entry, 1024),
		now:   time.Now,
		log:   logx.New(logx.WithPrefix("bruteguard")), // 默认用全局等级+该前缀
	}
	return g
}

/********** 主流程 **********/

// Allow：认证前调用，返回是否允许继续和需要等待多久
func (g *Guard) Allow(ip, user string) (ok bool, retryAfter time.Duration) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.gcIfNeeded()

	now := g.now()
	keys := keys(ip, user)
	var next time.Time
	for _, k := range keys {
		if e := g.get(k, now); e != nil {
			if e.lockedUntil.After(next) {
				next = e.lockedUntil
			}
		}
	}
	if next.After(now) {
		wait := next.Sub(now)
		g.log.Debugf("BLOCK ip=%q user=%q until=%s wait=%s", ip, user, next.Format(time.RFC3339), wait)
		return false, wait
	}
	return true, 0
}

// Fail：一次失败后调用（用户名不存在/密码错误都视为失败）
func (g *Guard) Fail(ip, user string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.gcIfNeeded()

	now := g.now()
	for _, k := range keys(ip, user) {
		e := g.getOrCreate(k, now)
		e.fails++
		e.lastFail = now
		e.lastSeen = now

		// 达到阈值：直接封禁
		if g.cfg.MaxFails > 0 && e.fails >= g.cfg.MaxFails {
			e.lockedUntil = now.Add(g.cfg.Cooldown)
			g.log.Debugf("COOL-DOWN key=%s fails=%d until=%s", k, e.fails, e.lockedUntil.Format(time.RFC3339))
			continue
		}
		// 指数退避（饱和到 MaxBackoff）
		backoff := g.cfg.BaseBackoff
		for i := 1; i < e.fails; i++ {
			backoff *= 2
			if backoff >= g.cfg.MaxBackoff {
				backoff = g.cfg.MaxBackoff
				break
			}
		}
		until := now.Add(backoff)
		if until.After(e.lockedUntil) {
			e.lockedUntil = until
		}
		g.log.Debugf("FAIL key=%s fails=%d backoff=%s until=%s", k, e.fails, backoff, e.lockedUntil.Format(time.RFC3339))
	}
}

// Success：一次成功后调用（默认清 user 与 ip|user；可选也清 ip）
func (g *Guard) Success(ip, user string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.gcIfNeeded()

	now := g.now()
	trimIP := strings.TrimSpace(ip)
	trimUser := strings.TrimSpace(user)

	keysToClear := make([]string, 0, 3)
	if trimUser != "" {
		keysToClear = append(keysToClear, "user:"+trimUser)
	}
	if trimIP != "" && trimUser != "" {
		keysToClear = append(keysToClear, "ipuser:"+trimIP+"|"+trimUser)
	}
	if g.clearIPOnSuccess && trimIP != "" && trimUser != "" {
		keysToClear = append(keysToClear, "ip:"+trimIP)
	}

	for _, k := range keysToClear {
		if e := g.get(k, now); e != nil {
			e.fails = 0
			e.lockedUntil = time.Time{}
			e.lastSeen = now
			g.log.Debugf("SUCCESS clear key=%s", k)
		}
	}
}

/********** 可选工具 **********/
type Snapshot struct {
	Fails       int
	LockedUntil time.Time
}

func (g *Guard) Peek(ip, user string) Snapshot {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()

	var s Snapshot
	for _, k := range keys(ip, user) {
		if e := g.get(k, now); e != nil {
			if e.fails > s.Fails {
				s.Fails = e.fails
			}
			if e.lockedUntil.After(s.LockedUntil) {
				s.LockedUntil = e.lockedUntil
			}
		}
	}
	return s
}

func (g *Guard) Stats() (keys int, blocked int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.gcIfNeeded()
	now := g.now()
	for _, e := range g.store {
		keys++
		if e.lockedUntil.After(now) {
			blocked++
		}
	}
	return
}

func (g *Guard) Clear(ip, user string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	for _, k := range keys(ip, user) {
		if e := g.get(k, now); e != nil {
			e.fails = 0
			e.lockedUntil = time.Time{}
			e.lastSeen = now
			g.log.Debugf("CLEAR key=%s", k)
		}
	}
}

/********** 内部：存取/GC/Key 计算 **********/
func (g *Guard) get(k string, now time.Time) *entry {
	e := g.store[k]
	if e == nil {
		return nil
	}
	// 软清零 fails；不动 lockedUntil（避免 Window<Cooldown 时提前解封）
	if g.cfg.Window > 0 && !e.lastFail.IsZero() && now.Sub(e.lastFail) > g.cfg.Window {
		e.fails = 0
	}
	e.lastSeen = now
	return e
}

func (g *Guard) getOrCreate(k string, now time.Time) *entry {
	if e := g.get(k, now); e != nil {
		return e
	}
	e := &entry{lastSeen: now}
	g.store[k] = e
	return e
}

func (g *Guard) gcIfNeeded() {
	now := g.now()
	if now.Sub(g.lastGC) < g.cfg.GCInterval {
		return
	}
	g.lastGC = now
	alive := g.cfg.AliveFor
	for k, e := range g.store {
		if now.Sub(e.lastSeen) > alive {
			delete(g.store, k)
			g.log.Debugf("GC drop key=%s", k)
		}
	}
}

func keys(ip, user string) []string {
	ip = strings.TrimSpace(ip)
	user = strings.TrimSpace(user)
	switch {
	case ip != "" && user != "":
		return []string{"ip:" + ip, "user:" + user, "ipuser:" + ip + "|" + user}
	case ip != "":
		return []string{"ip:" + ip}
	case user != "":
		return []string{"user:" + user}
	default:
		return nil
	}
}
