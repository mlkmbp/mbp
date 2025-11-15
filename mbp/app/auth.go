package app

import (
	"gorm.io/gorm"
	"mlkmbp/mbp/common"
	"mlkmbp/mbp/core/limiter"
	"mlkmbp/mbp/core/rule_runtime"
	"mlkmbp/mbp/db/dao"
	"strings"
	"time"
)

func (a *App) makeAuth() rule_runtime.AuthenticateAndAuthorize {
	now := func() time.Time { return time.Now() }

	build := func(row *dao.AuthRow) rule_runtime.AuthResult {
		if !common.StatusOK(row.Status) {
			return rule_runtime.AuthResult{OK: false, Reason: rule_runtime.AuthUserDisabledOrExpired}
		}
		if row.StartDateTime != nil && row.StartDateTime.Time.After(now()) {
			return rule_runtime.AuthResult{OK: false, Reason: rule_runtime.AuthUserHasNotStarted}
		}
		if row.ExpiredDateTime != nil && row.ExpiredDateTime.Time.Before(now()) {
			return rule_runtime.AuthResult{OK: false, Reason: rule_runtime.AuthUserExpired}
		}
		if !common.QuotaOK(row.Quota, row.Up, row.Down) {
			return rule_runtime.AuthResult{OK: false, Reason: rule_runtime.AuthQuotaExceeded}
		}
		var remain int64
		if row.Quota <= 0 {
			remain = limiter.Unlimited
		} else {
			left := row.Quota - (row.Up + row.Down)
			if left < 0 {
				left = 0
			}
			remain = left
		}
		return rule_runtime.AuthResult{
			OK:            true,
			Reason:        rule_runtime.AuthOK,
			UserId:        row.UserId,
			Username:      row.Username,
			Password:      row.Password,
			UserUpLimit:   row.UserUpLimit,
			UserDownLimit: row.UserDownLimit,
			RuleUpLimit:   row.RuleUpLimit,
			RuleDownLimit: row.RuleDownLimit,
			Remain:        remain,
		}
	}

	return func(ip, user, pass string, RuleId, UserId int64) rule_runtime.AuthResult {
		u := strings.TrimSpace(user)
		p := strings.TrimSpace(pass)
		ip = strings.TrimSpace(ip) // 允许为空

		// 1) 用户名 + 密码
		if u != "" && p != "" {
			// —— 防爆破：传了 ip 就按 (ip,username) 组合限速；没传就只按 username 限速
			if a.Guard != nil {
				ok, _ := a.Guard.Allow(ip, u)
				if !ok {
					// 与口令错误保持一致，避免暴露限流信号
					return rule_runtime.AuthResult{OK: false, Reason: rule_runtime.AuthBadCredentials}
				}
			}

			row, err := dao.FetchAuthRowByUsername(a.MasterDB.GormDataSource, u)
			if err != nil {
				if err == gorm.ErrRecordNotFound {
					if a.Guard != nil {
						a.Guard.Fail(ip, u)
					}
					return rule_runtime.AuthResult{OK: false, Reason: rule_runtime.AuthBadCredentials}
				}
				return rule_runtime.AuthResult{OK: false, Reason: rule_runtime.AuthInternalError}
			}
			if row.VmId > 0 {
				return rule_runtime.AuthResult{OK: false, Reason: rule_runtime.AuthUserIsVmId}
			}
			if !common.PasswordOK(row.Password, row.PasswordSHA256, p) {
				if a.Guard != nil {
					a.Guard.Fail(ip, u)
				}
				return rule_runtime.AuthResult{OK: false, Reason: rule_runtime.AuthBadCredentials}
			}

			if a.Guard != nil {
				a.Guard.Success(ip, u)
			}
			return build(row)
		}

		// 2) 免密（UserId + RuleId）
		if UserId > 0 && RuleId > 0 {
			row, err := dao.FetchAuthRowByUserId(a.MasterDB.GormDataSource, RuleId, UserId)
			if err != nil {
				if err == gorm.ErrRecordNotFound {
					return rule_runtime.AuthResult{OK: false, Reason: rule_runtime.AuthNotAuthorizedForRule}
				}
				return rule_runtime.AuthResult{OK: false, Reason: rule_runtime.AuthInternalError}
			}
			return build(row)
		}

		// 3) 参数不全
		return rule_runtime.AuthResult{OK: false, Reason: rule_runtime.AuthMissing}
	}
}
