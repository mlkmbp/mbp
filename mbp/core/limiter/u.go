package limiter

import (
	"mlkmbp/mbp/common"
	"mlkmbp/mbp/core/rule_runtime"
	"net"
	"sync"
	"sync/atomic"
)

// 把“规则+用户”的下行限速挂到这条连接上：
// - PerDownLimiter：按规则/用户的非零最小值做单连接整形（抑制突发/瞬时冲高）
// - UserSharedDownLimiter：用户维度共享限速（兜总量）
func AttachUserDownLimiters(conn net.Conn, ar rule_runtime.AuthResult) {
	cc, ok := conn.(*CountingConn)
	if !ok {
		return
	}

	cc.Opts.UserId = ar.UserId
	cc.Opts.Username = ar.Username

	// 1) 单连接整形：取规则与用户限速的“非零最小值”
	perLimit := common.MinNonZero(ar.UserDownLimit, ar.RuleDownLimit)
	if perLimit > 0 {
		cc.Opts.PerDownLimiter = NewLimiter(perLimit)
	}

	// 2) 用户共享限速：没有就按用户限速创建一把；已有就直接复用
	userDown := GlobalUserLimiters.GetDown(ar.UserId)
	if userDown == nil && ar.UserDownLimit > 0 {
		// Set(UpLimit, DownLimit) —— 这里只需要下行
		GlobalUserLimiters.Set(ar.UserId, 0, ar.UserDownLimit)
		userDown = GlobalUserLimiters.GetDown(ar.UserId)
	}
	cc.Opts.UserSharedDownLimiter = userDown
}

// Unlimited: -1 表示不限量
const Unlimited = int64(-1)

type ConsumeResult struct {
	Allowed   int  // 允许写入/回写的字节数（可能为部分）
	Unlimited bool // 是否处于不限量模式
	Exhausted bool // 是否已经用尽（Allowed==0 且非 Unlimited）
}

type UserQuota struct {
	remain atomic.Int64 // 字节；-1 表示不限量
}

// TryConsumeDetailed 会原子扣减，并返回详细状态
func (q *UserQuota) TryConsumeDetailed(n int) ConsumeResult {
	if n <= 0 {
		return ConsumeResult{Allowed: 0, Unlimited: q.IsUnlimited()}
	}
	if q.IsUnlimited() {
		return ConsumeResult{Allowed: n, Unlimited: true}
	}
	for {
		cur := q.remain.Load()
		if cur <= 0 {
			return ConsumeResult{Allowed: 0, Exhausted: true}
		}
		w := int64(n)
		if w > cur {
			w = cur
		}
		if q.remain.CompareAndSwap(cur, cur-w) {
			return ConsumeResult{Allowed: int(w)}
		}
	}
}

// 向后兼容：老签名（ok, allow）
func (q *UserQuota) TryConsume(n int) (bool, int) {
	cr := q.TryConsumeDetailed(n)
	return cr.Allowed > 0, cr.Allowed
}

func (q *UserQuota) IsUnlimited() bool { return q.remain.Load() == Unlimited }

// RefreshFromAuthz：用 Authz 的“当前剩余”刷新内存镜像（**无损**）
//
// 规则：
// - newRemain == Unlimited  -> 设为 Unlimited（升级为不限量）
// - 当前 Unlimited 且 newRemain >= 0 -> 降级成 newRemain（支持从不限量切回限量）
// - 其余情况：remain = min(cur, newRemain)  // 只下降，不回涨（避免覆盖并发会话已扣的量）
//
// 若后台需要“充值/回涨”，请调用 SetHard 或 TopUp（见下）。
func (q *UserQuota) RefreshFromAuthz(newRemain int64) {
	cur := q.remain.Load()
	switch {
	case newRemain == Unlimited:
		q.remain.Store(Unlimited)
	case cur == Unlimited && newRemain >= 0:
		q.remain.Store(newRemain)
	case newRemain >= 0:
		for {
			cur = q.remain.Load()
			if cur == Unlimited {
				// 上面分支已处理，这里只是兜底
				if q.remain.CompareAndSwap(cur, newRemain) {
					return
				}
				continue
			}
			// 只下降，不回涨
			if newRemain < cur {
				if q.remain.CompareAndSwap(cur, newRemain) {
					return
				}
				continue
			}
			// newRemain >= cur：保持现状，避免覆盖其他并发扣减
			return
		}
	}
}

// SetHard：把剩余强制设为指定值（**会覆盖**并发扣减；仅用于后台“人工重置/充值”场景）
func (q *UserQuota) SetHard(remain int64) { q.remain.Store(remain) }

// TopUp：叠加充值（Unlimited 不变；若为负/零则设为增量）
func (q *UserQuota) TopUp(delta int64) {
	if delta == 0 || q.IsUnlimited() {
		return
	}
	for {
		cur := q.remain.Load()
		nv := cur + delta
		if nv < 0 {
			nv = 0
		}
		if q.remain.CompareAndSwap(cur, nv) {
			return
		}
	}
}

type quotaStore struct {
	mu sync.RWMutex
	m  map[int64]*UserQuota // user_id -> quota
}

var GlobalUserQuotas = &quotaStore{m: make(map[int64]*UserQuota)}

func (s *quotaStore) Get(userID int64) *UserQuota {
	s.mu.RLock()
	q := s.m[userID]
	s.mu.RUnlock()
	if q != nil {
		return q
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if q = s.m[userID]; q == nil {
		q = &UserQuota{}
		q.remain.Store(Unlimited) // 默认不限量，避免未初始化挡流
		s.m[userID] = q
	}
	return q
}

// Refresh：获取并执行无损刷新
func (s *quotaStore) Refresh(userID int64, newRemain int64) *UserQuota {
	q := s.Get(userID)
	q.RefreshFromAuthz(newRemain)
	return q
}

// SetHard：管理端重置/充值用
func (s *quotaStore) SetHard(userID int64, remain int64) {
	q := s.Get(userID)
	q.SetHard(remain)
}
