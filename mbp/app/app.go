package app

import (
	"context"
	"fmt"
	"mlkmbp/mbp/common"
	"mlkmbp/mbp/common/bruteguard"
	"mlkmbp/mbp/common/config"
	"mlkmbp/mbp/common/logx"
	"mlkmbp/mbp/core/listener"
	"mlkmbp/mbp/db"
	"mlkmbp/mbp/db/dao"
	"mlkmbp/mbp/model"
	"sync"
	"time"
)

type App struct {
	Cfg      *config.Config
	CfgPath  string
	MasterDB *db.DB
	LogDB    *db.DB

	UserAggregator       *dao.UserAggregator
	TrafficLogAggregator *dao.TrafficLogAggregator

	Guard *bruteguard.Guard
	Day   string

	// 运行态：RuleId -> RunningRule（含 lm、fingerprint、enabled）
	RrMu sync.RWMutex
	Rr   map[int64]*RunningRule

	// per-rule 互斥，确保同一 rule 的生命周期操作串行化
	Rlm *RuleLockMap

	Ctx    context.Context
	Cancel context.CancelFunc

	// ★ 组件级日志
	Log *logx.Logger
}

type RunningRule struct {
	Flm         *listener.ListenerMgr
	Fingerprint string
	Enabled     bool
}

type RuleLockMap struct {
	mu sync.Mutex
	m  map[int64]*sync.Mutex
}

func NewRuleLockMap() *RuleLockMap {
	return &RuleLockMap{m: make(map[int64]*sync.Mutex)}
}
func (rl *RuleLockMap) Lock(id int64) func() {
	rl.mu.Lock()
	lk, ok := rl.m[id]
	if !ok {
		lk = &sync.Mutex{}
		rl.m[id] = lk
	}
	rl.mu.Unlock()
	lk.Lock()
	return func() { lk.Unlock() }
}

var log = logx.New(logx.WithPrefix("app"))

func New(cfgPath string) (*App, error) {
	cfg, cfgP, err := config.Load(cfgPath)
	if err != nil {
		return nil, err
	}
	a := &App{
		Cfg:     cfg,
		CfgPath: cfgP,
		Rr:      make(map[int64]*RunningRule),
		Rlm:     NewRuleLockMap(),
		Log:     log, // ★ 组件 logger（等级跟随全局）
	}
	logx.SetLevelString(a.Cfg.Logging.Level)
	a.Log.Infof("config loaded from %s", cfgPath)

	// master 库
	master := cfg.DB.Master
	a.Log.Debugf("opening master db: driver=%s", master.Driver)
	masterDB, err := db.OpenGorm(master.Driver, master.DSN, master.Pool)
	if err != nil {
		return nil, fmt.Errorf("open master db: %w", err)
	}
	if err := db.MigrateMasterSQL(masterDB.GormDataSource, masterDB.Driver); err != nil {
		return nil, fmt.Errorf("auto-migrate master: %w", err)
	}

	a.MasterDB = masterDB
	a.Log.Infof("master db connected (driver=%s)", master.Driver)

	a.UserAggregator = dao.NewUserAggregator(a.MasterDB.GormDataSource, a.MasterDB.Driver, 500*time.Millisecond, 1500)
	a.UserAggregator.Start()
	a.Log.Infof("user aggregator started (batch=1500, flush=500ms)")

	// 日志库
	if cfg.DB.Log.Enable {
		logCfg := cfg.DB.Log
		a.Log.Debugf("opening log db: driver=%s", logCfg.Driver)
		logDB, err := db.OpenGorm(logCfg.Driver, logCfg.DSN, logCfg.Pool)
		if err != nil {
			return nil, fmt.Errorf("open log db: %w", err)
		}
		day := time.Now().Format("20060102")
		if err := db.EnsureTrafficLogTable(logDB, day); err != nil {
			return nil, fmt.Errorf("ensure log table for %s: %w", day, err)
		}
		a.Day = day
		a.LogDB = logDB
		a.TrafficLogAggregator = dao.NewTrafficLogAggregator(
			a.LogDB.GormDataSource,
			a.LogDB.Driver,
			model.TrafficTable,
			func(d string) error { return db.EnsureTrafficLogTable(a.LogDB, d) },
			1*time.Second,
			1000,
		)
		a.TrafficLogAggregator.Start()
		a.Log.Infof("log db connected (driver=%s), traffic aggregator started (batch=1000, flush=1s, day=%s)", logCfg.Driver, day)
	} else {
		a.Log.Infof("log db disabled")
	}

	// 暴力防护
	a.Guard = bruteguard.New(bruteguard.Config{
		Window:      10 * time.Minute,
		MaxFails:    5,
		Cooldown:    30 * time.Minute,
		BaseBackoff: 3 * time.Second,
		MaxBackoff:  1 * time.Minute,
		GCInterval:  1 * time.Minute,
		AliveFor:    12 * time.Hour,
	})
	a.Log.Infof("bruteguard ready (maxFails=%d, cooldown=%s, baseBackoff=%s, maxBackoff=%s)", 5, 30*time.Minute, 3*time.Second, 1*time.Minute)

	return a, nil
}

/* -------------------- 启动 & 热更新 -------------------- */

func (a *App) Start() error {
	a.Ctx, a.Cancel = context.WithCancel(context.Background())
	go a.watchAndHotReload(60 * time.Second)
	a.Log.Infof("hot-reload watcher started (interval=30s)")
	return nil
}

func (a *App) watchAndHotReload(interval time.Duration) {
	tk := time.NewTicker(interval)
	defer tk.Stop()

	last, err := dao.SnapshotEnabledRule(a.Cfg.License, a.MasterDB.GormDataSource)
	if err != nil {
		a.Log.Errorf("hot-reload initial snapshot failed: %v", err)
		last = map[int64]dao.RuleNap{}
	}
	// 补起应该跑的
	for id, s := range last {
		if s.Enabled {
			_ = a.startOneRuleAtomic(id, s.Fingerprint)
		} else {
			a.stopOneRuleAtomic(id)
		}
	}

	for {
		select {
		case <-a.Ctx.Done():
			a.Log.Debugf("hot-reload watcher exit")
			return
		case <-tk.C:
			cur, err := dao.SnapshotEnabledRule(a.Cfg.License, a.MasterDB.GormDataSource)
			if err != nil {
				a.Log.Errorf("hot-reload snapshot failed: %v", err)
				continue
			}

			// 新增/启用/指纹变更 => 先停后起
			for id, s := range cur {
				if !s.Enabled {
					continue
				}
				prev, existed := last[id]
				if !existed {
					a.Log.Debugf("[rule %d] new+enabled -> start", id)
					_ = a.startOneRuleAtomic(id, s.Fingerprint)
					continue
				}
				if prev.Fingerprint != s.Fingerprint {
					a.Log.Debugf("[rule %d] fingerprint changed -> restart", id)
					a.stopOneRuleAtomic(id)
					_ = a.startOneRuleAtomic(id, s.Fingerprint)
				}
			}

			// 被禁用或删除 => 停
			for id, prev := range last {
				s, ok := cur[id]
				if !ok || !s.Enabled {
					if prev.Enabled {
						a.Log.Debugf("[rule %d] disabled/removed -> stop", id)
						a.stopOneRuleAtomic(id)
					}
				}
			}

			last = cur
		}
	}
}

/* -------------------- 单条规则：原子替换/串行化 -------------------- */

// 单条规则：原子重启/启动 —— 永远先停旧再起新
func (a *App) startOneRuleAtomic(RuleId int64, expectedFP string) error {
	unlock := a.Rlm.Lock(RuleId)
	defer unlock()

	// 看看旧的在不在
	a.RrMu.RLock()
	old := a.Rr[RuleId]
	already := (old != nil && old.Enabled && old.Flm != nil && old.Fingerprint == expectedFP)
	a.RrMu.RUnlock()
	if already {
		a.Log.Debugf("[rule %d] already running with same fingerprint, skip", RuleId)
		return nil
	}

	// —— 先停旧（防止端口占用）——
	if old != nil && old.Flm != nil {
		old.Flm.Stop()
		a.Log.Infof("[rule %d] stopped old runtime", RuleId)
	}

	// —— 构建 & 启动新 runtime（会真正 listen）——
	rt, lmNew, err := a.buildAndStartRuntime(RuleId)
	if err != nil {
		return fmt.Errorf("start rule %d failed after stop-old: %w", RuleId, err)
	}

	// 原子替换
	a.RrMu.Lock()
	a.Rr[RuleId] = &RunningRule{
		Flm:         lmNew,
		Fingerprint: expectedFP, // 用快照里的指纹
		Enabled:     true,
	}
	a.RrMu.Unlock()

	a.Log.Infof("[rule %d][%s] started: %s -> %s",
		RuleId, rt.Protocol, rt.ListenAddr, common.SafeShowTarget(rt.TargetAddr))
	return nil
}

func (a *App) stopOneRuleAtomic(RuleId int64) {
	unlock := a.Rlm.Lock(RuleId)
	defer unlock()

	a.RrMu.Lock()
	old := a.Rr[RuleId]
	delete(a.Rr, RuleId)
	a.RrMu.Unlock()

	if old != nil && old.Flm != nil {
		old.Flm.Stop()
		a.Log.Infof("[rule %d] stopped", RuleId)
	}
}

/* -------------------- 关闭 -------------------- */

func (a *App) Stop() error {
	// 逐条安全停
	a.RrMu.Lock()
	olds := a.Rr
	a.Rr = make(map[int64]*RunningRule)
	a.RrMu.Unlock()
	if a.UserAggregator != nil {
		a.UserAggregator.Shutdown()
		a.Log.Infof("user aggregator stopped")
	}
	if a.TrafficLogAggregator != nil {
		a.TrafficLogAggregator.Shutdown()
		a.Log.Infof("traffic aggregator stopped")
	}

	for id, rr := range olds {
		if rr != nil && rr.Flm != nil {
			rr.Flm.Stop()
			a.Log.Infof("[rule %d] stopped", id)
		}
	}
	if a.Cancel != nil {
		a.Cancel()
	}
	a.Log.Infof("app stopped")
	return nil
}
