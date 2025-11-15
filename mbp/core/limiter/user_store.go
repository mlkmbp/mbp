package limiter

import (
	"math"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// 单个用户的限速条目
type entry struct {
	upLimiter   *rate.Limiter
	downLimiter *rate.Limiter
	upBps       int64 // Bytes/s；<=0 表示不限制
	downBps     int64 // 同上
	lastAccess  time.Time
}

// UserLimiterStore 提供：
//   - GetUp/GetDown：返回对应限速器（可能为 nil）；访问会续期 lastAccess
//   - Set：原子更新某用户上下行限速（相同值不重建）；<=0 表示不限制并删除对应方向的 limiter
//   - Delete：删除一个用户的条目
//   - Close：停止后台清理协程
type UserLimiterStore struct {
	mu      sync.RWMutex
	items   map[int64]*entry
	ttl     time.Duration
	tick    time.Duration
	stopCh  chan struct{}
	stopped bool
}

// NewUserLimiterStore 创建一个带 TTL 清理的存储。
// ttl 是无访问自动淘汰时长（建议 12h）；tick 是清理周期（建议 ttl/4）。
func NewUserLimiterStore(ttl, tick time.Duration) *UserLimiterStore {
	if ttl <= 0 {
		ttl = 12 * time.Hour
	}
	if tick <= 0 {
		tick = ttl / 4
		if tick < time.Minute {
			tick = time.Minute
		}
	}
	s := &UserLimiterStore{
		items:  make(map[int64]*entry),
		ttl:    ttl,
		tick:   tick,
		stopCh: make(chan struct{}),
	}
	go s.janitor()
	return s
}

// 12h TTL，3h 清理一次
var GlobalUserLimiters = NewUserLimiterStore(12*time.Hour, 3*time.Hour)

// -------- Public API --------

func (s *UserLimiterStore) GetUp(uid int64) *rate.Limiter {
	e := s.getAndTouch(uid)
	if e == nil {
		return nil
	}
	return e.upLimiter
}
func (s *UserLimiterStore) GetDown(uid int64) *rate.Limiter {
	e := s.getAndTouch(uid)
	if e == nil {
		return nil
	}
	return e.downLimiter
}

// Set(…): upBytesPerSec/downBytesPerSec <=0 表示该方向不限制。
// 如果速率与当前一致则不重建 limiter，避免抖动。
func (s *UserLimiterStore) Set(uid int64, upBytesPerSec, downBytesPerSec int64) {
	now := time.Now()

	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.items[uid]
	if !ok {
		e = &entry{lastAccess: now}
		s.items[uid] = e
	} else {
		e.lastAccess = now
	}

	// 更新上行
	if upBytesPerSec <= 0 {
		e.upLimiter = nil
		e.upBps = 0
	} else if e.upLimiter == nil || e.upBps != upBytesPerSec {
		e.upLimiter = rate.NewLimiter(rate.Limit(upBytesPerSec), safeBurst(upBytesPerSec))
		e.upBps = upBytesPerSec
	}

	// 更新下行
	if downBytesPerSec <= 0 {
		e.downLimiter = nil
		e.downBps = 0
	} else if e.downLimiter == nil || e.downBps != downBytesPerSec {
		e.downLimiter = rate.NewLimiter(rate.Limit(downBytesPerSec), safeBurst(downBytesPerSec))
		e.downBps = downBytesPerSec
	}

	// 如果上下都不限制，直接回收该用户条目
	if e.upLimiter == nil && e.downLimiter == nil {
		delete(s.items, uid)
	}
}

// Delete 强制删除一个用户条目
func (s *UserLimiterStore) Delete(uid int64) {
	s.mu.Lock()
	delete(s.items, uid)
	s.mu.Unlock()
}

// Close 关闭后台清理协程
func (s *UserLimiterStore) Close() {
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return
	}
	s.stopped = true
	close(s.stopCh)
	s.mu.Unlock()
}

// -------- Internal helpers --------

func (s *UserLimiterStore) getAndTouch(uid int64) *entry {
	now := time.Now()

	// 先读锁拿引用，减少写锁竞争
	s.mu.RLock()
	e := s.items[uid]
	s.mu.RUnlock()
	if e == nil {
		return nil
	}

	// 续期需要写锁
	s.mu.Lock()
	// 可能正好被其他 goroutine 删除了，再次确认
	e = s.items[uid]
	if e != nil {
		e.lastAccess = now
	}
	s.mu.Unlock()
	return e
}

func (s *UserLimiterStore) janitor() {
	t := time.NewTicker(s.tick)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			s.sweep()
		case <-s.stopCh:
			return
		}
	}
}

func (s *UserLimiterStore) sweep() {
	expireBefore := time.Now().Add(-s.ttl)

	s.mu.Lock()
	for uid, e := range s.items {
		// 仅在完全无访问时淘汰；如果某方向不限制但另一方向限制仍保留
		if e.lastAccess.Before(expireBefore) {
			delete(s.items, uid)
		}
	}
	s.mu.Unlock()
}

// safeBurst 将 burst 设为 1 秒配额，但在 int 边界内做保护。
// 也可按需改为更小的 burst（例如 200ms 配额）以减少瞬时突发。
func safeBurst(bps int64) int {
	if bps <= 0 {
		return 0
	}
	maxInt := int64(math.MaxInt32) // 兼容 32 位
	if bps > maxInt {
		return int(maxInt)
	}
	return int(bps)
}
