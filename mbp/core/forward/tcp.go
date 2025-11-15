package forward

import (
	"fmt"
	"mlkmbp/mbp/common"
	"mlkmbp/mbp/core/iface"
	"mlkmbp/mbp/core/limiter"
	"mlkmbp/mbp/core/rule_runtime"
	"mlkmbp/mbp/core/transport"
	"net"
	"time"
)

func HandleTCP(rc iface.RuntimeCtx, rr rule_runtime.RuleRuntime, c net.Conn) {
	startTime := time.Now().UnixMilli()
	remote := c.RemoteAddr().String()
	// 这里是“按 UserId 预校验”的场景：用户名/密码留空字符串即可
	res := rr.Auth(common.RemoteIPFromConn(c), "", "", rr.RuleId, rr.UserId)
	if !res.OK {
		reason := string(res.Reason)
		if reason == "" {
			reason = "auth_failed"
		}
		if rr.OnReject != nil {
			rr.OnReject(reason, remote)
		}
		_ = c.Close()
		return
	}

	limiter.AttachUserDownLimiters(c, res)

	dst, err := limiter.DialTimeout("tcp", "tcp", remote, rr.TargetAddr, rc.Context(), startTime, res, rr)
	if err != nil {
		rr.OnReject(fmt.Sprintf("dial_target_err:%v", err), remote)
		_ = c.Close()
		return
	}
	transport.Pipe(rc.Context(), c, dst)
}
