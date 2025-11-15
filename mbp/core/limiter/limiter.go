package limiter

import (
	"context"
	"time"

	"golang.org/x/time/rate"
)

/********** 单连接 ByteLimiter **********/

type ByteLimiter struct {
	// 每秒字节数；<=0 表示不限
	bps int64

	last time.Time
	acc  int64
}

func NewLimiter(bps int64) *ByteLimiter {
	if bps <= 0 {
		return nil
	}
	return &ByteLimiter{bps: bps}
}

// 需要等待多久才能写 n 字节；<=0 表示无需等待
func (bl *ByteLimiter) NeedWait(n int) time.Duration {
	if bl == nil || bl.bps <= 0 || n <= 0 {
		return 0
	}
	now := time.Now()
	if bl.last.IsZero() {
		bl.last = now
		return 0
	}
	elapsed := now.Sub(bl.last)
	// 释放额度
	bl.acc -= int64(float64(bl.bps) * elapsed.Seconds())
	if bl.acc < 0 {
		bl.acc = 0
	}
	// 新占用
	bl.acc += int64(n)
	bl.last = now

	if bl.acc <= bl.bps {
		return 0
	}
	overflow := bl.acc - bl.bps
	sec := float64(overflow) / float64(bl.bps)
	wait := time.Duration(sec * float64(time.Second))

	return wait
}

/********** 等待函数：单连接 + 多把共享 limiter **********/

// WaitBeforeWrite：
// - perConn: 单连接限速（可为 nil）
// - shareds: 任意多把共享 limiter（规则级、用户级、全局级……都可传进来，nil 会被忽略）
// 逻辑：
// 1) 先按 per-conn 算一次等待并睡一次；
// 2) 对每把共享 limiter 做 ReserveN，找出“最大等待”，只睡一次；
// 3) 若 ctx 取消，会 Cancel 之前的所有 Reservation。
func WaitBeforeWrite(ctx context.Context, n int, perConn *ByteLimiter, shareds ...*rate.Limiter) error {
	if n <= 0 {
		return nil
	}
	cnt := 0
	for _, s := range shareds {
		if s != nil {
			cnt++
		}
	}

	// A. 单连接等待
	if perConn != nil {
		if d := perConn.NeedWait(n); d > 0 {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-t.C:
			}
		}
	}

	// B. 共享等待（一次性最大等待）
	type resv struct {
		r rate.Reservation // 值类型
	}
	now := time.Now()
	reservations := make([]resv, 0, len(shareds))
	maxDelay := time.Duration(0)

	for _, lim := range shareds {
		if lim == nil {
			continue
		}
		r := lim.ReserveN(now, n)
		if !r.OK() {
			// 取消之前的预定
			for _, rv := range reservations {
				rv.r.CancelAt(now)
			}
			return context.DeadlineExceeded
		}
		d := r.DelayFrom(now)
		if d > maxDelay {
			maxDelay = d
		}
		reservations = append(reservations, resv{r: *r})
	}

	if maxDelay > 0 {
		t := time.NewTimer(maxDelay)
		defer t.Stop()
		select {
		case <-ctx.Done():
			for _, rv := range reservations {
				rv.r.CancelAt(now)
			}
			return ctx.Err()
		case <-t.C:
		}
	}
	return nil
}
