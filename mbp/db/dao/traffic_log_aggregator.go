package dao

import (
	"context"
	"mlkmbp/mbp/common/logx"
	"mlkmbp/mbp/model"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
	"gorm.io/gorm"
)

var daoTrafficLogAggregatorLog = logx.New(logx.WithPrefix("dao.traffic_log_aggregator"))

type TrafficLogAggregator struct {
	db         *gorm.DB
	driver     string
	tableFunc  func(day string) string // e.g. model.TrafficTable
	flushEvery time.Duration
	maxBatch   int

	inCh   chan logItem
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// 分表存在性：本地缓存 + singleflight 抑制并发 ensure
	ensuredDays sync.Map // map[string]struct{}
	sf          singleflight.Group

	// 外部注入：确保某个 day 的日志表存在（建表+索引）
	ensure func(day string) error
}

type logItem struct {
	day string
	log model.TrafficLog
}

func NewTrafficLogAggregator(
	db *gorm.DB, driver string,
	tableFunc func(day string) string,
	ensureTable func(day string) error,
	flushEvery time.Duration, maxBatch int,
) *TrafficLogAggregator {
	if flushEvery <= 0 {
		flushEvery = 700 * time.Millisecond
	}
	if maxBatch <= 0 {
		maxBatch = 1000
	}
	ctx, cancel := context.WithCancel(context.Background())
	a := &TrafficLogAggregator{
		db:         db,
		driver:     strings.ToLower(driver),
		tableFunc:  tableFunc,
		ensure:     ensureTable,
		flushEvery: flushEvery,
		maxBatch:   maxBatch,
		inCh:       make(chan logItem, maxBatch),
		ctx:        ctx,
		cancel:     cancel,
	}
	daoTrafficLogAggregatorLog.Infof("init flushEvery=%v maxBatch=%d driver=%s", a.flushEvery, a.maxBatch, a.driver)
	return a
}

func (a *TrafficLogAggregator) Start() {
	a.wg.Add(1)
	go a.worker()
	daoTrafficLogAggregatorLog.Infof("started")
}

func (a *TrafficLogAggregator) Shutdown() {
	daoTrafficLogAggregatorLog.Infof("shutdown begin")
	a.cancel()
	a.wg.Wait()
	daoTrafficLogAggregatorLog.Infof("shutdown done")
}

// Append：严格 FIFO；在入队前先确保当日分表存在（并发去重，失败留给 flush 再试）
func (a *TrafficLogAggregator) AddTrafficLogAsync(day string, log model.TrafficLog) {
	// 预 ensure（失败不阻塞写入，flush 再补一次）
	if err := a.ensureOnce(day); err != nil {
		daoTrafficLogAggregatorLog.Debugf("ensure pre-add failed day=%s err=%v (will retry in flush)", day, err)
	}

	select {
	case <-a.ctx.Done():
		// 丢弃（已关停）
		return
	case a.inCh <- logItem{day: day, log: log}:
	}
}

func (a *TrafficLogAggregator) worker() {
	defer a.wg.Done()
	ticker := time.NewTicker(a.flushEvery)
	defer ticker.Stop()

	buf := make([]logItem, 0, a.maxBatch)

	flush := func() {
		n := len(buf)
		if n == 0 {
			return
		}
		daoTrafficLogAggregatorLog.Debugf("flush begin size=%d", n)

		// 1) 按到达顺序分组，并记录 day 的出现顺序（避免 map 随机顺序）
		byDay := make(map[string][]model.TrafficLog, 8)
		daysOrder := make([]string, 0, 8)
		for _, it := range buf {
			if _, ok := byDay[it.day]; !ok {
				daysOrder = append(daysOrder, it.day)
			}
			byDay[it.day] = append(byDay[it.day], it.log)
		}

		// 2) 逐 day 处理：ensure -> 批量写；失败的进入 next，保留原始顺序
		next := make([]logItem, 0, n)
		totalOK := 0
		for _, day := range daysOrder {
			logs := byDay[day]

			if err := a.ensureOnce(day); err != nil {
				// ensure 失败：该 day 的日志全部回队尾
				daoTrafficLogAggregatorLog.Warnf("ensure failed day=%s err=%v (defer to next flush, count=%d)", day, err, len(logs))
				for _, l := range logs {
					next = append(next, logItem{day: day, log: l})
				}
				continue
			}

			if err := a.batchInsert(day, logs); err != nil {
				daoTrafficLogAggregatorLog.Errorf("batch insert failed day=%s err=%v (defer to next flush, count=%d)", day, err, len(logs))
				for _, l := range logs {
					next = append(next, logItem{day: day, log: l})
				}
				continue
			}

			totalOK += len(logs)
			daoTrafficLogAggregatorLog.Debugf("batch inserted day=%s count=%d", day, len(logs))
		}

		if len(next) > 0 {
			// 有失败/未写成功的，保留到下一轮
			daoTrafficLogAggregatorLog.Warnf("flush partial: ok=%d pending=%d", totalOK, len(next))
			buf = next
		} else {
			// 全部成功，清空
			daoTrafficLogAggregatorLog.Debugf("flush ok: written=%d", totalOK)
			buf = buf[:0]
		}
	}

	for {
		select {
		case <-a.ctx.Done():
			flush()
			if len(buf) > 0 {
				// 还有未写成功的（例如 DB 宕机），此时进程将退出，提示一下
				daoTrafficLogAggregatorLog.Errorf("drop %d pending log(s) on shutdown (DB unavailable?)", len(buf))
			}
			return

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

// ensureOnce：只对同一个 day 做一次建表；并发时 singleflight 抑制重复
func (a *TrafficLogAggregator) ensureOnce(day string) error {
	if _, ok := a.ensuredDays.Load(day); ok {
		return nil
	}
	_, err, _ := a.sf.Do(day, func() (any, error) {
		// double-check
		if _, ok := a.ensuredDays.Load(day); ok {
			return nil, nil
		}
		if err := a.ensure(day); err != nil {
			return nil, err
		}
		a.ensuredDays.Store(day, struct{}{})
		daoTrafficLogAggregatorLog.Debugf("ensure ok day=%s table=%s", day, a.tableFunc(day))
		return nil, nil
	})
	return err
}

// 返回错误，由调用方决定是否回队重试
func (a *TrafficLogAggregator) batchInsert(day string, logs []model.TrafficLog) error {
	if len(logs) == 0 {
		return nil
	}
	tbl := a.tableFunc(day)

	cols := "time,username,direction,listen_addr,listen_port,protocol,up,down,dur,source_addr,source_port,target_addr,target_port"

	switch a.driver {
	case "mysql", "sqlite", "sqlite3":
		var sb strings.Builder
		sb.WriteString("INSERT INTO ")
		if a.driver == "mysql" {
			sb.WriteString("`" + tbl + "`")
		} else {
			sb.WriteString(tbl)
		}
		sb.WriteString(" (")
		sb.WriteString(cols)
		sb.WriteString(") VALUES ")

		args := make([]any, 0, len(logs)*13)
		for i, l := range logs {
			if i > 0 {
				sb.WriteString(",")
			}
			sb.WriteString("(?,?,?,?,?,?,?,?,?,?,?,?,?)")
			args = append(args,
				l.Time, l.Username, l.Direction, l.ListenAddr, l.ListenPort, l.Protocol,
				l.Up, l.Down, l.Dur, l.SourceAddr, l.SourcePort, l.TargetAddr, l.TargetPort,
			)
		}
		return a.db.Exec(sb.String(), args...).Error

	default:
		for _, l := range logs {
			if err := a.db.Table(tbl).Create(&l).Error; err != nil {
				return err
			}
		}
		return nil
	}
}
