package forward

import (
	"context"
	"errors"
	"fmt"
	"mlkmbp/mbp/common"
	"mlkmbp/mbp/common/logx"
	"mlkmbp/mbp/core/iface"
	"mlkmbp/mbp/core/limiter"
	"mlkmbp/mbp/core/rule_runtime"
	"mlkmbp/mbp/model"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

/************** 组件日志 **************/
var forwardUdpLog = logx.New(logx.WithPrefix("forward.udp"))

/************** 行为开关 **************/
const (
	sendFinish          = true // 是否通过 OnFinish 上报增量
	maxUDPPacket        = 64 * 1024
	defaultUDPIdleTTL   = 120 * time.Second // 建议 60–120s，兼容 QUIC
	incrementFlushEvery = 1 * time.Second
	incrementFlushBurst = 64 * 1024
	readPoll            = 200 * time.Millisecond
)

type udpAssoc struct {
	src     net.Addr
	dst     *net.UDPConn
	cancel  context.CancelFunc
	release func() // 许可释放（修复之前可能丢失的 release）

	lastSeen atomic.Int64 // UnixMilli

	// 限速（组合：单连接整形 + 用户共享 + 规则共享）
	upLimiter   common.MultiLimiter
	downLimiter common.MultiLimiter

	// 共享配额（单池，整包语义）
	uQuota *limiter.UserQuota

	// 会话统计（总量）
	upRead, upWritten     atomic.Int64 // C->P 已读 / P->T 已写
	downRead, downWritten atomic.Int64 // T->P 已读 / P->C 已写
	startAt               time.Time

	// 增量缓存（定期落库）
	flushMu                     sync.Mutex
	incUpRead, incUpWritten     int64
	incDownRead, incDownWritten int64

	// 日志分列
	userID   int64
	username string
	lh       string
	lp       int
	sh       string
	sp       int
	th       string
	tp       int

	flushStop chan struct{}
	closeOnce sync.Once
}

// finalize: 统一“停止 + 释放许可 + 关闭 dst”
func (a *udpAssoc) finalize() {
	a.closeOnce.Do(func() {
		if a.cancel != nil {
			a.cancel()
		}
		if a.dst != nil {
			_ = a.dst.Close()
		}
		if a.release != nil {
			a.release()
		}
		// 汇总日志（一次）
		dur := time.Since(a.startAt)
		ur := a.upRead.Load()
		uw := a.upWritten.Load()
		dr := a.downRead.Load()
		dw := a.downWritten.Load()
		forwardUdpLog.Debugf("assoc close src=%s -> %s dur=%s up(r/w)=%d/%d down(r/w)=%d/%d",
			a.src.String(), net.JoinHostPort(a.th, fmt.Sprint(a.tp)), dur.Truncate(time.Millisecond), ur, uw, dr, dw)
	})
}

// 停止：停止 flusher，做最后一次增量刷，然后 finalize
func (a *udpAssoc) stopAndFlush(rr rule_runtime.RuleRuntime) {
	select {
	case <-a.flushStop:
	default:
		close(a.flushStop)
	}
	a.flushOnce(rr) // 仅刷未落增量
	a.finalize()
}

// 增量计数
func (a *udpAssoc) incAdd(p *int64, delta int64) {
	a.flushMu.Lock()
	*p += delta
	a.flushMu.Unlock()
}

func aCtxDone(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}

func ServeUDP(rc iface.RuntimeCtx, rr rule_runtime.RuleRuntime) error {
	if rr.TargetAddr == rr.ListenAddr {
		forwardUdpLog.Errorf("invalid route: listen==target %s", rr.ListenAddr)
		if rr.OnReject != nil {
			rr.OnReject("invalid_udp_route_same_addr", rr.ListenAddr)
		}
		return fmt.Errorf("invalid_udp_route: %s", rr.ListenAddr)
	}

	pc, err := net.ListenPacket("udp", rr.ListenAddr)
	if err != nil {
		forwardUdpLog.Errorf("listen failed: %s -> %v", rr.ListenAddr, err)
		if rr.OnReject != nil {
			rr.OnReject("listen_udp_failed: "+err.Error(), rr.ListenAddr)
		}
		return err
	}
	if u, ok := pc.(*net.UDPConn); ok {
		_ = u.SetReadBuffer(32 << 20) // 32MB
		_ = u.SetWriteBuffer(32 << 20)
	}
	forwardUdpLog.Debugf("listening on %s -> %s", rr.ListenAddr, rr.TargetAddr)
	defer func() {
		_ = pc.Close()
		forwardUdpLog.Debugf("closed listener %s", rr.ListenAddr)
	}()

	var (
		assocs sync.Map // key = src.String() -> *udpAssoc
		pool   = &sync.Pool{New: func() any { return make([]byte, maxUDPPacket) }}
	)

	// 清理协程（按 idle TTL）
	stopJanitor := make(chan struct{})
	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-rc.Context().Done():
				return
			case <-stopJanitor:
				return
			case <-t.C:
				now := time.Now().UnixMilli()
				assocs.Range(func(key, value any) bool {
					a := value.(*udpAssoc)
					if time.Duration(now-a.lastSeen.Load())*time.Millisecond > defaultUDPIdleTTL {
						a.stopAndFlush(rr)
						assocs.Delete(key)
					}
					return true
				})
			}
		}
	}()
	defer close(stopJanitor)

	defer func() {
		// 退出时收尾全部会话（防泄漏）
		assocs.Range(func(key, value any) bool {
			value.(*udpAssoc).stopAndFlush(rr)
			assocs.Delete(key)
			return true
		})
	}()

	for {
		select {
		case <-rc.Context().Done():
			return nil
		default:
		}

		buf := pool.Get().([]byte)
		_ = pc.SetReadDeadline(time.Now().Add(readPoll))
		n, src, err := pc.ReadFrom(buf)
		if err != nil {
			pool.Put(buf)
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			if rc.Context().Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			forwardUdpLog.Errorf("read client err: %v", err)
			return err
		}
		payload := make([]byte, n)
		copy(payload, buf[:n])
		pool.Put(buf)

		key := src.String()
		val, ok := assocs.Load(key)
		if !ok {
			// 并发许可
			release, allowed := rr.AcquirePermit()
			if !allowed {
				forwardUdpLog.Warnf("reject: too_many_connections src=%s", key)
				if rr.OnReject != nil {
					rr.OnReject("too_many_connections", key)
				}
				continue
			}

			// 鉴权
			res := rr.Auth(common.RemoteIPFromAddr(src), "", "", rr.RuleId, rr.UserId)
			if !res.OK {
				release()
				reason := string(res.Reason)
				if reason == "" {
					reason = "auth_failed"
				}
				forwardUdpLog.Warnf("reject: %s src=%s userId=%d", reason, key, rr.UserId)
				if rr.OnReject != nil {
					rr.OnReject(reason, key)
				}
				continue
			}

			// 无损刷新配额镜像
			q := limiter.GlobalUserQuotas.Refresh(res.UserId, res.Remain)

			// 组合限速
			uUpLimiter := limiter.GlobalUserLimiters.GetUp(res.UserId)
			uDownLimiter := limiter.GlobalUserLimiters.GetDown(res.UserId)

			perUpBps := common.MinNonZero(res.UserUpLimit, rr.UpLimit)
			perUpBps = common.MinNonZero(perUpBps, res.RuleUpLimit)
			perDnBps := common.MinNonZero(res.UserDownLimit, rr.DownLimit)
			perDnBps = common.MinNonZero(perDnBps, res.RuleDownLimit)

			upShaper := common.MkShaper(perUpBps, rr.UpLimit)
			dnShaper := common.MkShaper(perDnBps, rr.DownLimit)
			upML := common.Compose(upShaper, uUpLimiter, rr.RuleSharedUpLimiter)
			downML := common.Compose(dnShaper, uDownLimiter, rr.RuleSharedDownLimiter)

			// 连接目标
			daddr, err := net.ResolveUDPAddr("udp", rr.TargetAddr)
			if err != nil {
				release()
				forwardUdpLog.Errorf("resolve target failed target=%s src=%s err=%v", rr.TargetAddr, key, err)
				if rr.OnReject != nil {
					rr.OnReject(fmt.Sprintf("udp_resolve_err:%v", err), key)
				}
				continue
			}
			dst, err := net.DialUDP("udp", nil, daddr)
			if err != nil {
				release()
				forwardUdpLog.Errorf("dial target failed target=%s src=%s err=%v", rr.TargetAddr, key, err)
				if rr.OnReject != nil {
					rr.OnReject(fmt.Sprintf("udp_dial_err:%v", err), key)
				}
				continue
			}
			_ = dst.SetReadBuffer(32 << 20)
			_ = dst.SetWriteBuffer(32 << 20)
			ctx, cancel := context.WithCancel(rc.Context())

			// 分列地址
			lh, lp, sh, sp, th, tp := common.ParseAddrPorts(rr.ListenAddr, key, rr.TargetAddr)

			a := &udpAssoc{
				src:         src,
				dst:         dst,
				cancel:      cancel,
				release:     release,
				upLimiter:   upML,
				downLimiter: downML,
				uQuota:      q,
				userID:      res.UserId,
				username:    res.Username,
				lh:          lh, lp: lp,
				sh: sh, sp: sp,
				th: th, tp: tp,
				startAt:   time.Now(),
				flushStop: make(chan struct{}),
			}
			a.lastSeen.Store(time.Now().UnixMilli())

			// 先放入 map，避免并发读 miss
			assocs.Store(key, a)

			// 增量刷
			go startPeriodicFlush(rr, a)

			// 连接关闭（跟随 ctx.Done）
			go func(a *udpAssoc, mapKey string) {
				<-ctx.Done()
				a.stopAndFlush(rr)
				assocs.Delete(mapKey)
			}(a, key)

			// 下行循环（目标 -> 客户端）
			go func(a *udpAssoc, mapKey string) {
				reply := make([]byte, maxUDPPacket)
				for {
					// 读目标
					if rr.ReadTimeout > 0 {
						_ = a.dst.SetReadDeadline(time.Now().Add(rr.ReadTimeout))
					} else {
						_ = a.dst.SetReadDeadline(time.Now().Add(readPoll))
					}
					n2, _, err := a.dst.ReadFromUDP(reply)
					if err != nil {
						// 良性关闭：静默退出
						if aCtxDone(ctx) || errors.Is(err, net.ErrClosed) {
							a.stopAndFlush(rr)
							assocs.Delete(mapKey)
							return
						}
						// 超时：继续
						if ne, ok := err.(net.Error); ok && ne.Timeout() {
							if aCtxDone(ctx) {
								a.stopAndFlush(rr)
								assocs.Delete(mapKey)
								return
							}
							continue
						}
						// 其它错误：结束
						forwardUdpLog.Warnf("assoc downlink error src=%s target=%s err=%v", a.src.String(), rr.TargetAddr, err)
						a.stopAndFlush(rr)
						assocs.Delete(mapKey)
						return
					}
					if n2 <= 0 {
						continue
					}

					// 统计：已读
					a.downRead.Add(int64(n2))
					a.incAdd(&a.incDownRead, int64(n2))

					// 下行限速（整包）
					if a.downLimiter != nil {
						if err := a.downLimiter.WaitN(ctx, n2); err != nil {
							a.stopAndFlush(rr)
							assocs.Delete(mapKey)
							return
						}
					}

					// 配额（整包）：不足就丢包（不写，不中断会话）
					cr := a.uQuota.TryConsumeDetailed(n2)
					if !cr.Unlimited && cr.Allowed < n2 {
						continue
					}

					// 回写客户端（整包）
					// 注意：pc 为共享 socket，多协程对它 SetWriteDeadline 会互相踩 -> 不设置写超时
					m, err := pc.WriteTo(reply[:n2], a.src)
					if err != nil {
						if aCtxDone(ctx) || errors.Is(err, net.ErrClosed) {
							a.stopAndFlush(rr)
							assocs.Delete(mapKey)
							return
						}
						forwardUdpLog.Warnf("assoc write-to-client error src=%s err=%v", a.src.String(), err)
						a.stopAndFlush(rr)
						assocs.Delete(mapKey)
						return
					}
					a.downWritten.Add(int64(m))
					a.incAdd(&a.incDownWritten, int64(m))
					a.lastSeen.Store(time.Now().UnixMilli())
				}
			}(a, key)

			forwardUdpLog.Debugf("assoc open src=%s -> %s", key, rr.TargetAddr)
			val = a
		}

		// 上行（客户端 -> 目标）
		a := val.(*udpAssoc)
		a.lastSeen.Store(time.Now().UnixMilli())

		// 统计 已读
		size := len(payload)
		a.upRead.Add(int64(size))
		a.incAdd(&a.incUpRead, int64(size))

		// 上行限速（整包）
		if a.upLimiter != nil {
			if err := a.upLimiter.WaitN(rc.Context(), size); err != nil {
				// 超时/取消：丢包即可
				continue
			}
		}

		// 配额（整包）：不足则丢包（不发送、不关闭）
		cr := a.uQuota.TryConsumeDetailed(size)
		if !cr.Unlimited && cr.Allowed < size {
			continue
		}

		// 写目标（整包）—— 只对私有 dst 设写超时，不触碰共享 pc
		if rr.WriteTimeout > 0 {
			_ = a.dst.SetWriteDeadline(time.Now().Add(rr.WriteTimeout))
		} else {
			_ = a.dst.SetWriteDeadline(time.Now().Add(readPoll))
		}
		nw, err := a.dst.Write(payload)
		if err != nil {
			// 良性关闭：静默
			if errors.Is(err, net.ErrClosed) || rc.Context().Err() != nil {
				a.stopAndFlush(rr)
				assocs.Delete(key)
				continue
			}
			forwardUdpLog.Warnf("assoc write-to-target error src=%s target=%s err=%v", key, rr.TargetAddr, err)
			if rr.OnReject != nil {
				rr.OnReject(fmt.Sprintf("udp_write_target_err:%v", err), key)
			}
			a.stopAndFlush(rr)
			assocs.Delete(key)
			continue
		}
		a.upWritten.Add(int64(nw))
		a.incAdd(&a.incUpWritten, int64(nw))
	}
}

// 定时增量落库（只上报本周期增量）
func startPeriodicFlush(rr rule_runtime.RuleRuntime, a *udpAssoc) {
	t := time.NewTicker(incrementFlushEvery)
	defer t.Stop()
	for {
		select {
		case <-a.flushStop:
			return
		case <-t.C:
			a.flushOnce(rr)
		}
	}
}

func (a *udpAssoc) flushOnce(rr rule_runtime.RuleRuntime) {
	if !sendFinish || rr.OnFinish == nil {
		return
	}
	a.flushMu.Lock()
	ur, uw := a.incUpRead, a.incUpWritten
	dr, dw := a.incDownRead, a.incDownWritten
	need := ur+uw >= incrementFlushBurst || dr+dw >= incrementFlushBurst || ur > 0 || uw > 0 || dr > 0 || dw > 0
	if need {
		a.incUpRead, a.incUpWritten = 0, 0
		a.incDownRead, a.incDownWritten = 0, 0
	}
	a.flushMu.Unlock()
	if !need {
		return
	}

	now := time.Now().UnixMilli()
	dur := time.Since(a.startAt).Milliseconds()

	// 入站（客户端->目标）
	if ur > 0 || uw > 0 {
		rr.OnFinish(a.userID, model.TrafficLog{
			Time:       now,
			Username:   a.username,
			Direction:  "入站",
			ListenAddr: a.lh, ListenPort: a.lp,
			Protocol:   "udp",
			Up:         ur,
			Down:       uw,
			Dur:        dur,
			SourceAddr: a.sh, SourcePort: a.sp,
			TargetAddr: a.th, TargetPort: a.tp,
		})
	}

	// 出站（目标->客户端）
	if dr > 0 || dw > 0 {
		rr.OnFinish(a.userID, model.TrafficLog{
			Time:       now,
			Username:   a.username,
			Direction:  "出站",
			ListenAddr: a.lh, ListenPort: a.lp,
			Protocol:   "udp",
			Up:         dr,
			Down:       dw,
			Dur:        dur,
			SourceAddr: a.sh, SourcePort: a.sp,
			TargetAddr: a.th, TargetPort: a.tp,
		})
	}
}
