package limiter

import (
	"context"
	"golang.org/x/time/rate"
	"mlkmbp/mbp/common"
	"mlkmbp/mbp/core/rule_runtime"
	"mlkmbp/mbp/model"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type CountingOpts struct {
	UserId             int64
	Username, Protocol string
	ListenAddr         string
	ListenPort         int
	SourceAddr         string
	SourcePort         int
	TargetAddr         string
	TargetPort         int
	Ctx                context.Context
	StartTime          int64

	// 方向：true => Write 计上行 / Read 计下行；false => Write 计下行 / Read 计上行
	Direction bool

	// 单连接限速（可选）
	PerUpLimiter   *ByteLimiter
	PerDownLimiter *ByteLimiter

	// 规则共享限速（可选）
	RuleSharedUpLimiter   *rate.Limiter
	RuleSharedDownLimiter *rate.Limiter

	// 用户共享限速（可选）
	UserSharedUpLimiter   *rate.Limiter
	UserSharedDownLimiter *rate.Limiter

	// 读/写超时（可选；0 表示不设置）
	ReadTimeout  time.Duration
	WriteTimeout time.Duration

	// 结束回调（只会调用一次）
	OnFinish func(uid int64, log model.TrafficLog)
}

type CountingConn struct {
	net.Conn
	Opts CountingOpts

	readBytes  int64
	writeBytes int64
	finishOnce sync.Once
}

// NewCountingConn 创建一个带流量统计和限速的 CountingConn
func NewCountingConn(c net.Conn, opts CountingOpts) *CountingConn {
	return &CountingConn{
		Conn: c,
		Opts: opts,
	}
}

func DialTimeout(network, protocol, remote, target string,
	ctx context.Context, startTime int64, ar rule_runtime.AuthResult, rr rule_runtime.RuleRuntime) (*CountingConn, error) {
	var conn net.Conn
	var err error
	if rr.ConnTimeout > 0 {
		conn, err = net.DialTimeout(network, target, rr.ConnTimeout)
	} else {
		conn, err = net.Dial(network, target)
	}
	if err != nil {
		return nil, err
	}

	var perUpLimiter *ByteLimiter
	perLimit := common.MinNonZero(ar.UserUpLimit, ar.RuleUpLimit)
	if perLimit > 0 {
		perUpLimiter = NewLimiter(rr.UpLimit)
	}

	userUp := GlobalUserLimiters.GetUp(ar.UserId)
	if userUp == nil {
		GlobalUserLimiters.Set(ar.UserId, ar.UserUpLimit, 0)
		userUp = GlobalUserLimiters.GetUp(ar.UserId)
	}
	lh, lp, sh, sp, th, tp := common.ParseAddrPorts(rr.ListenAddr, remote, target)
	countingConn := NewCountingConn(conn, CountingOpts{
		UserId:     ar.UserId,   // ✅ 记录真实用户
		Username:   ar.Username, // 如需显示用户名，请在认证时把用户名也传进来
		Protocol:   protocol,
		ListenAddr: lh, ListenPort: lp,
		SourceAddr: sh, SourcePort: sp,
		TargetAddr: th, TargetPort: tp,
		Ctx:                 ctx,
		StartTime:           startTime,
		Direction:           true,                   // 写往目标=上行
		PerUpLimiter:        perUpLimiter,           // 单连接上行（可选）
		RuleSharedUpLimiter: rr.RuleSharedUpLimiter, // 规则共享上行（可选）
		UserSharedUpLimiter: userUp,                 // ✅ 用户共享上行（可选）

		ReadTimeout:  rr.ReadTimeout,
		WriteTimeout: rr.WriteTimeout,
		OnFinish:     rr.OnFinish,
	})
	return countingConn, nil
}

// 可选：在 accept 循环里配合 ctx 退出（给 TCPListener 设置短超时）
func AcceptWithContext(ctx context.Context, ln net.Listener) (net.Conn, error) {
	tcpln, _ := ln.(*net.TCPListener)

	for {
		// 支持取消
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		// Windows 上用 SetDeadline 轮询感知 ctx
		if tcpln != nil {
			_ = tcpln.SetDeadline(time.Now().Add(500 * time.Millisecond))
		}

		c, err := ln.Accept()
		if err != nil {
			// 超时重试以便检查 ctx
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return nil, err
		}
		return c, nil
	}
}

// —— 基础 Read/Write：只做统计（限速放在 Write 前实现）
func (cc *CountingConn) Read(b []byte) (int, error) {
	if cc.Opts.ReadTimeout > 0 {
		_ = cc.Conn.SetReadDeadline(time.Now().Add(cc.Opts.ReadTimeout))
	}
	n, err := cc.Conn.Read(b)
	if n > 0 {
		atomic.AddInt64(&cc.readBytes, int64(n))
	}
	return n, err
}

func (cc *CountingConn) Write(b []byte) (int, error) {
	// 写前限速：根据方向选择 上/下 的限速器
	if !cc.FastpathOK() {
		var per *ByteLimiter
		var ruleShared *rate.Limiter
		var userShared *rate.Limiter
		if cc.Opts.Direction {
			per, ruleShared, userShared = cc.Opts.PerUpLimiter, cc.Opts.RuleSharedUpLimiter, cc.Opts.UserSharedUpLimiter

		} else {
			per, ruleShared, userShared = cc.Opts.PerDownLimiter, cc.Opts.RuleSharedDownLimiter, cc.Opts.UserSharedDownLimiter
		}
		if err := WaitBeforeWrite(cc.Opts.Ctx, len(b), per, ruleShared, userShared); err != nil {
			return 0, err
		}
	}
	if cc.Opts.WriteTimeout > 0 {
		_ = cc.Conn.SetWriteDeadline(time.Now().Add(cc.Opts.WriteTimeout))
	}
	n, err := cc.Conn.Write(b)

	if n > 0 {
		atomic.AddInt64(&cc.writeBytes, int64(n))
	}
	return n, err
}

// 判断是否可以走快路径（没有任何限速/超时）
func (cc *CountingConn) FastpathOK() bool {
	return cc.Opts.PerUpLimiter == nil &&
		cc.Opts.PerDownLimiter == nil &&
		cc.Opts.RuleSharedUpLimiter == nil &&
		cc.Opts.RuleSharedDownLimiter == nil &&
		cc.Opts.UserSharedUpLimiter == nil &&
		cc.Opts.UserSharedDownLimiter == nil
}

// 统计汇总
func (cc *CountingConn) Up() int64 {
	if cc.Opts.Direction {
		return atomic.LoadInt64(&cc.writeBytes)
	}
	return atomic.LoadInt64(&cc.readBytes)
}
func (cc *CountingConn) Down() int64 {
	if cc.Opts.Direction {
		return atomic.LoadInt64(&cc.readBytes)
	}
	return atomic.LoadInt64(&cc.writeBytes)
}

func (cc *CountingConn) Close() error {
	cc.finishOnce.Do(func() {
		if cc.Opts.OnFinish != nil {
			direction := "出站"
			if !cc.Opts.Direction {
				direction = "入站"
			}
			log := model.TrafficLog{
				Time:       time.Now().UnixMilli(),
				Username:   cc.Opts.Username,
				Direction:  direction,
				ListenAddr: cc.Opts.ListenAddr,
				ListenPort: cc.Opts.ListenPort,
				Protocol:   cc.Opts.Protocol,
				Up:         cc.Up(),
				Down:       cc.Down(),
				Dur:        time.Now().UnixMilli() - cc.Opts.StartTime,
				SourceAddr: cc.Opts.SourceAddr,
				SourcePort: cc.Opts.SourcePort,
				TargetAddr: cc.Opts.TargetAddr,
				TargetPort: cc.Opts.TargetPort,
			}
			cc.Opts.OnFinish(cc.Opts.UserId, log)
		}
	})
	return cc.Conn.Close()
}
