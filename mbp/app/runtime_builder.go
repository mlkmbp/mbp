package app

import (
	"fmt"
	"golang.org/x/time/rate"
	"mlkmbp/mbp/common"
	"mlkmbp/mbp/core/listener"
	"mlkmbp/mbp/core/policy"
	"mlkmbp/mbp/core/rule_runtime"
	"mlkmbp/mbp/db/dao"
	"mlkmbp/mbp/model"
	"net"
	"time"
)

func (a *App) buildAndStartRuntime(RuleId int64) (rule_runtime.RuleRuntime, *listener.ListenerMgr, error) {
	// 规则
	r, err := dao.GetRuleById(a.MasterDB.GormDataSource, RuleId)
	if err != nil || r == nil || r.Status != "enabled" {
		return rule_runtime.RuleRuntime{}, nil, fmt.Errorf("rule disabled or expired or not found")
	}

	// owner（仅转发类使用）
	mapping, err := dao.LookupUserIdByRule(a.MasterDB.GormDataSource, r.Id)
	if err != nil {
		return rule_runtime.RuleRuntime{}, nil, fmt.Errorf("lookup user by rule: %w", err)
	}
	owner, err := dao.LoadUserInfo(a.MasterDB.GormDataSource, mapping.UserId)
	if err != nil {
		return rule_runtime.RuleRuntime{}, nil, fmt.Errorf("load owner: %w", err)
	}
	if owner.Status != "enabled" || (owner.ExpiredDateTime != nil && owner.ExpiredDateTime.Time.Before(time.Now())) {
		return rule_runtime.RuleRuntime{}, nil, fmt.Errorf("owner disabled or expired")
	}

	listen := net.JoinHostPort(r.Address, fmt.Sprintf("%d", r.Port))
	target := common.BuildTargetAddr(r)

	rr := rule_runtime.RuleRuntime{
		RuleId:         r.Id,
		Protocol:       r.Protocol,
		RuleName:       r.RuleName,
		InterfaceName:  r.InterfaceName,
		ListenAddr:     listen,
		TargetAddr:     target,
		Socks5BindPort: r.Socks5BindPort,
		Socks5UDPPort:  r.Socks5UDPPort,
		TLSCert:        r.TLSCert,
		TLSKey:         r.TLSKey,
		TLSSNIGuard:    r.TLSSNIGuard,
		SkipCertVerify: r.SkipCertVerify,
		ALPN:           r.ALPN,
		TLSFingerprint: r.TLSFingerprint,
		AuthUsername:   r.AuthUsername,
		AuthPassword:   r.AuthPassword,
		UpLimit:        r.UpLimit,
		DownLimit:      r.DownLimit,
		MaxConnection:  r.MaxConnection,
		ConnTimeout:    time.Duration(r.ConnTimeout) * time.Millisecond,
		ReadTimeout:    time.Duration(r.ReadTimeout) * time.Millisecond,
		WriteTimeout:   time.Duration(r.WriteTimeout) * time.Millisecond,

		OnReject: func(reason, remote string) {
			log.Debugf("[rule %d %s] reject %s from %s", r.Id, r.RuleName, reason, remote)
		},
		Auth: a.makeAuth(),
	}

	// 主规则持有人
	rr.UserId = owner.Id
	rr.Username = owner.Username
	// 记账回调：优先用“连接用户 uid”；如果没有就回落到 owner（转发类）
	rr.OnFinish = func(uid int64, t model.TrafficLog) {
		go func() {
			// 1) 用户用量（严格 FIFO + 批量，阻塞式投递，不丢）
			if t.Up > 0 || t.Down > 0 {
				a.UserAggregator.AddUserAsync(uid, t.Up, t.Down)
				// 2) 日志（严格 FIFO + 批量）
				if a.LogDB != nil && a.Cfg.DB.Log.Enable && a.TrafficLogAggregator != nil {
					day := time.Now().Format("20060102")
					a.TrafficLogAggregator.AddTrafficLogAsync(day, t)
				}
			}

		}()
	}

	// 规则级共享限速器
	if rr.UpLimit > 0 {
		rr.RuleSharedUpLimiter = rate.NewLimiter(rate.Limit(rr.UpLimit), int(common.Max64(1, rr.UpLimit/10)))
	}
	if rr.DownLimit > 0 {
		rr.RuleSharedDownLimiter = rate.NewLimiter(rate.Limit(rr.DownLimit), int(common.Max64(1, rr.DownLimit/10)))
	}

	lm, acquire := listener.NewListenerMgr(rr.MaxConnection)
	rr.AcquirePermit = acquire

	decider := policy.NewDecider(a.Ctx, a.MasterDB)
	rr.Decider = decider

	lm.StartRule(rr)
	return rr, lm, nil
}
