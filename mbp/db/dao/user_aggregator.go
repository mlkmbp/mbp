package dao

import (
	"context"
	"fmt"
	"mlkmbp/mbp/common/logx"
	"sort"
	"strings"
	"sync"
	"time"

	"gorm.io/gorm"
)

var daoUserAggregatorLog = logx.New(logx.WithPrefix("dao.user_aggregator"))

type UserAggregator struct {
	db          *gorm.DB
	driver      string
	tableMySQL  string // 反引号包裹
	tableSQLite string // 双引号包裹
	flushEvery  time.Duration
	maxBatch    int
	inCh        chan inc

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

type inc struct {
	uid      int64
	up, down int64
}

func NewUserAggregator(db *gorm.DB, driver string, flushEvery time.Duration, maxBatch int) *UserAggregator {
	if flushEvery <= 0 {
		flushEvery = 700 * time.Millisecond
	}
	if maxBatch <= 0 {
		maxBatch = 1000
	}
	ctx, cancel := context.WithCancel(context.Background())
	a := &UserAggregator{
		db:          db,
		driver:      strings.ToLower(driver),
		tableMySQL:  "`user`", // 关键：反引号
		tableSQLite: `"user"`, // 关键：双引号
		flushEvery:  flushEvery,
		maxBatch:    maxBatch,
		inCh:        make(chan inc, maxBatch),
		ctx:         ctx,
		cancel:      cancel,
	}
	daoUserAggregatorLog.Infof("init flushEvery=%v maxBatch=%d driver=%s", a.flushEvery, a.maxBatch, a.driver)
	return a
}

func (a *UserAggregator) Start() {
	a.wg.Add(1)
	go a.worker()
	daoUserAggregatorLog.Infof("started")
}

func (a *UserAggregator) Shutdown() {
	daoUserAggregatorLog.Infof("shutdown begin")
	a.cancel()
	a.wg.Wait()
	daoUserAggregatorLog.Infof("shutdown done")
}

func (a *UserAggregator) AddUserAsync(userID, up, down int64) {
	if userID <= 0 || (up == 0 && down == 0) {
		return
	}
	select {
	case <-a.ctx.Done():
		return
	case a.inCh <- inc{uid: userID, up: up, down: down}:
	}
}

func (a *UserAggregator) worker() {
	defer a.wg.Done()
	ticker := time.NewTicker(a.flushEvery)
	defer ticker.Stop()

	buf := make([]inc, 0, a.maxBatch)

	flush := func() {
		if len(buf) == 0 {
			return
		}
		start := time.Now()

		// 聚合到同 uid
		m := make(map[int64]struct{ up, down int64 }, len(buf))
		for _, it := range buf {
			ag := m[it.uid]
			ag.up += it.up
			ag.down += it.down
			m[it.uid] = ag
		}
		// 稳定顺序（非必须，仅便于排查）
		ids := make([]int64, 0, len(m))
		for id := range m {
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })

		if err := a.flushBatch(ids, m); err != nil {
			// 对 MySQL/SQLite：整批失败——保留 buf 等下轮重试
			// 对 default：逐条模式可能已部分成功，仅记录错误，清空 buf 以免重复累加
			daoUserAggregatorLog.Errorf("flush failed: %v (driver=%s, kept=%d)", err, a.driver, len(buf))
			if a.driver == "mysql" || a.driver == "sqlite" || a.driver == "sqlite3" {
				// 保留 buf，不清空；等待下轮重试
				return
			}
		}

		elapsed := time.Since(start)
		daoUserAggregatorLog.Debugf("flush ok size=%d unique_uid=%d took=%v", len(buf), len(m), elapsed)
		buf = buf[:0]
	}

	for {
		select {
		case <-a.ctx.Done():
			// drain 剩余数据，尽量不丢
			for {
				select {
				case it := <-a.inCh:
					buf = append(buf, it)
					if len(buf) >= a.maxBatch {
						flush()
					}
				default:
					flush()
					return
				}
			}

		case it := <-a.inCh:
			buf = append(buf, it)
			if len(buf) >= a.maxBatch {
				flush()
			}

		case <-ticker.C:
			flush()
		}
	}
}

// 返回 error：
// - MySQL/SQLite：单条批量语句，失败返回错误（整批未生效）
// - 其他驱动：逐条执行，若出现任意错误，仅返回第一个错误（可能部分已成功）
func (a *UserAggregator) flushBatch(ids []int64, m map[int64]struct{ up, down int64 }) error {
	if len(ids) == 0 {
		return nil
	}

	switch a.driver {
	case "mysql":
		var b strings.Builder
		b.WriteString("UPDATE ")
		b.WriteString(a.tableMySQL)
		b.WriteString(" u JOIN (")
		for i, id := range ids {
			ag := m[id]
			if i > 0 {
				b.WriteString(" UNION ALL ")
			}
			fmt.Fprintf(&b, "SELECT %d AS id, %d AS up, %d AS down", id, ag.up, ag.down)
		}
		b.WriteString(") d ON u.id = d.id SET u.`up` = u.`up` + d.up, u.`down` = u.`down` + d.down")
		return a.db.Exec(b.String()).Error

	case "sqlite", "sqlite3":
		var values strings.Builder
		values.WriteString("VALUES ")
		for i, id := range ids {
			ag := m[id]
			if i > 0 {
				values.WriteString(",")
			}
			fmt.Fprintf(&values, "(%d,%d,%d)", id, ag.up, ag.down)
		}
		sql := fmt.Sprintf(`
WITH d(id, up, down) AS (%s)
UPDATE %s
   SET up   = up   + COALESCE((SELECT up   FROM d WHERE d.id = %s.id), 0),
       down = down + COALESCE((SELECT down FROM d WHERE d.id = %s.id), 0)
 WHERE id IN (SELECT id FROM d);`, values.String(), a.tableSQLite, a.tableSQLite, a.tableSQLite)
		return a.db.Exec(sql).Error

	default:
		// 保底：逐条
		var firstErr error
		for _, id := range ids {
			ag := m[id]
			if err := a.db.Exec(`UPDATE "user" SET up = up + ?, down = down + ? WHERE id = ?`, ag.up, ag.down, id).Error; err != nil && firstErr == nil {
				firstErr = err
			}
		}
		return firstErr
	}
}
