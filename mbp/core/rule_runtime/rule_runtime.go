package rule_runtime

import (
	"golang.org/x/time/rate"
	"mlkmbp/mbp/core/policy"
	"mlkmbp/mbp/model"
	"time"
)

/* —— 统一的鉴权/授权/配额结果 —— */

type AuthReason string

const (
	AuthOK                    AuthReason = "ok"
	AuthMissing               AuthReason = "missing_credentials"
	AuthBadCredentials        AuthReason = "bad_credentials"
	AuthUserDisabledOrExpired AuthReason = "user_disabled_or_expired"
	AuthUserIsVmId            AuthReason = "user_is_vm_id"
	AuthUserHasNotStarted     AuthReason = "user_has_not_started"
	AuthUserExpired           AuthReason = "user_expired"
	AuthNotAuthorizedForRule  AuthReason = "not_authorized_for_rule"
	AuthQuotaExceeded         AuthReason = "quota_exceeded"
	AuthInternalError         AuthReason = "internal_error"
)

type AuthResult struct {
	OK            bool
	Reason        AuthReason
	UserId        int64
	Username      string
	Password      string
	UserUpLimit   int64
	UserDownLimit int64
	RuleUpLimit   int64
	RuleDownLimit int64
	Remain        int64
}

// 一次性完成：鉴权(账号/密码) + 用户状态/过期 + 是否被授权到该规则 + 配额
type AuthenticateAndAuthorize func(ip, user, pass string, RuleId, UserId int64) AuthResult

/* —— 运行态：由 app 构造并注入 handler —— */

type RuleRuntime struct {
	RuleId, UserId                    int64
	RuleName, InterfaceName, Username string
	Protocol                          string
	ListenAddr                        string
	TargetAddr                        string

	Socks5UDPPort, Socks5BindPort int

	Auth AuthenticateAndAuthorize

	// TLS（监听侧）
	TLSCert, TLSKey, TLSSNIGuard string
	SkipCertVerify               bool
	ALPN                         string
	TLSFingerprint               string

	AuthUsername string
	AuthPassword string

	// 限速/并发/超时
	UpLimit, DownLimit int64
	MaxConnection      int
	ConnTimeout        time.Duration
	ReadTimeout        time.Duration
	WriteTimeout       time.Duration

	// 生命周期回调
	OnReject func(reason string, remote string)
	OnFinish func(uid int64, t model.TrafficLog)

	// 注入
	AcquirePermit func() (release func(), ok bool)

	RuleSharedUpLimiter   *rate.Limiter
	RuleSharedDownLimiter *rate.Limiter

	Decider policy.Decider
}
