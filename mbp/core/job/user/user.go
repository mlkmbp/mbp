package user

import (
	"context"
	"mlkmbp/mbp/common/logx"
	"mlkmbp/mbp/common/ttime"
	"mlkmbp/mbp/db"
	"mlkmbp/mbp/model"
	"time"
)

var log = logx.New(logx.WithPrefix("job.user"))

// ===== 每 60 秒跑一次 =====
func StartUserPeriodTicker(ctx context.Context, masterDB *db.DB) {
	tk := time.NewTicker(10 * time.Second)
	go func() {
		defer tk.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-tk.C:
				if err := runUserPeriodRenewalOnce(ctx, masterDB, now); err != nil {
					log.Errorf("[period-renewal] run error: %v", err)
				}
			}
		}
	}()
}

// ===== 一次执行（仅抓“已过期”的正常数据）=====
func runUserPeriodRenewalOnce(ctx context.Context, masterDB *db.DB, now time.Time) error {
	startTS := time.Now()
	log.Debugf("[period-renewal] tick start at=%s", now.Local().Format(ttime.FORMAT_DATE_TIME))

	// 兜底禁用：已启用 + period_left=0 + 过期>3天
	if err := disableLongExpiredUsers(ctx, masterDB, now, 3*24*time.Hour); err != nil {
		log.Errorf("[period-renewal] disableLongExpiredUsers error: %v", err)
	}

	const batch = 500
	totalScanned := 0
	totalRenewed := 0
	totalConcurrentSkip := 0
	totalErrors := 0

	nowTF := &ttime.TimeFormat{Time: now, Format: ttime.FORMAT_DATE_TIME}

	for {
		var rows []model.User
		// 只抓 “已启用 + 还剩周期(-1/无限 或 >0) + 有周期单位 + 过期时间<=now”的记录
		if err := masterDB.GormDataSource.WithContext(ctx).
			Model(&model.User{}).
			Where("status = 'enabled'").
			Where("(period_left = -1 OR period_left > 0)").
			Where("period_unit <> ''").
			Where("expired_date_time IS NOT NULL").
			Where("expired_date_time <> '' AND expired_date_time <> '0000-00-00 00:00:00'").
			Where("expired_date_time <= ?", nowTF).
			Order("expired_date_time ASC").
			Limit(batch).
			Find(&rows).Error; err != nil {
			return err
		}
		n := len(rows)
		if n == 0 {
			break
		}
		totalScanned += n
		log.Debugf("[period-renewal] batch fetched=%d (scanned=%d)", n, totalScanned)

		for _, u := range rows {
			// 防御：start/expired 任一为空就跳过
			if u.StartDateTime == nil || u.StartDateTime.Time.IsZero() ||
				u.ExpiredDateTime == nil || u.ExpiredDateTime.Time.IsZero() {
				log.Warnf("[period-renewal] skip bad-time id=%d user=%s unit=%s left=%d start=%s expired=%s",
					u.Id, u.Username, u.PeriodUnit, u.PeriodLeft, fmtTF(u.StartDateTime), fmtTF(u.ExpiredDateTime))
				continue
			}

			unit := u.PeriodUnit
			left := u.PeriodLeft
			origStart := u.StartDateTime.Time
			origExp := u.ExpiredDateTime.Time

			// 二次保护
			if origExp.After(now) {
				continue
			}

			newStart, newExp, newLeft, steps := advancePeriods(origStart, origExp, unit, left, now)
			if steps == 0 {
				continue
			}

			log.Debugf("[period-renewal] renewing id=%d user=%s unit=%s left=%d -> left'=%d steps=%d exp:%s => %s",
				u.Id, u.Username, unit, left, newLeft, steps,
				origExp.Local().Format(ttime.FORMAT_DATE_TIME), newExp.Local().Format(ttime.FORMAT_DATE_TIME))

			upd := map[string]any{
				"start_date_time":   &ttime.TimeFormat{Time: newStart, Format: ttime.FORMAT_DATE_TIME},
				"expired_date_time": &ttime.TimeFormat{Time: newExp, Format: ttime.FORMAT_DATE_TIME},
				"up":                0,
				"down":              0,
			}
			if left > 0 { // -1（无限）不动
				upd["period_left"] = newLeft
			}

			// 乐观并发：用 *TimeFormat 精确匹配旧过期时间
			origExpTF := &ttime.TimeFormat{Time: origExp, Format: ttime.FORMAT_DATE_TIME}
			res := masterDB.GormDataSource.WithContext(ctx).
				Model(&model.User{}).
				Where("id = ? AND status = 'enabled' AND (period_left = -1 OR period_left > 0) AND expired_date_time = ?", u.Id, origExpTF).
				Updates(upd)

			if res.Error != nil {
				totalErrors++
				log.Errorf("[period-renewal] id=%d user=%s update error: %v", u.Id, u.Username, res.Error)
				continue
			}
			if res.RowsAffected == 0 {
				totalConcurrentSkip++
				log.Warnf("[period-renewal] id=%d user=%s concurrent-skip (someone updated earlier)", u.Id, u.Username)
				continue
			}
			totalRenewed++
		}

		if n < batch {
			break
		}
	}

	cost := time.Since(startTS)
	log.Debugf("[period-renewal] tick done cost=%s scanned=%d renewed=%d concurrent_skip=%d errors=%d",
		cost, totalScanned, totalRenewed, totalConcurrentSkip, totalErrors)
	return nil
}

// 把区间按「start = old_exp」逐期推进，直到 newExp > now；有限周期会逐期扣减到 0 停止
func advancePeriods(origStart, origExp time.Time, unit model.PeriodUnit, left int64, now time.Time) (time.Time, time.Time, int64, int) {
	switch unit {
	case model.PeriodDay, model.PeriodMonth:
	default:
		return origStart, origExp, left, 0
	}

	steps := 0
	newLeft := left

	// 从“旧过期时间”开始推
	start := origExp
	exp := origExp

	for !exp.After(now) {
		if newLeft == 0 { // 有限周期扣完就停
			break
		}
		// 本次周期：start=当前 exp，exp=按单位+1
		start = exp
		if unit == model.PeriodDay {
			exp = exp.AddDate(0, 0, 1)
		} else {
			exp = exp.AddDate(0, 1, 0)
		}
		steps++
		if newLeft > 0 {
			newLeft--
		}
	}

	if steps == 0 {
		return origStart, origExp, left, 0
	}
	return start, exp, newLeft, steps
}

// 正常改“过期”，超过 grace（例如 72h）改“禁用”
func disableLongExpiredUsers(ctx context.Context, masterDB *db.DB, now time.Time, grace time.Duration) error {
	const batch = 500

	nowTF := &ttime.TimeFormat{Time: now, Format: ttime.FORMAT_DATE_TIME}
	cutoff := now.Add(-grace)
	cutoffTF := &ttime.TimeFormat{Time: cutoff, Format: ttime.FORMAT_DATE_TIME}

	totalExpired := 0
	totalDisabled := 0

	// -------- Step 1: 标记 expired（到期但未超过禁用阈值；且当前仍是 enabled） --------
	{
		lastID := int64(0)
		for {
			var ids []int64
			err := masterDB.GormDataSource.WithContext(ctx).
				Model(&model.User{}).
				Where("status = 'enabled'").
				Where("period_left = 0").
				// 仅“已经到期”
				Where("expired_date_time IS NOT NULL").
				Where("expired_date_time <> '' AND expired_date_time <> '0000-00-00 00:00:00'").
				// 到期时间 <= now
				Where("expired_date_time <= ?", nowTF).
				// 但“未超过禁用阈值”（否则交给 Step 2）
				Where("expired_date_time > ?", cutoffTF).
				Where("id > ?", lastID).
				Order("id ASC").
				Limit(batch).
				Pluck("id", &ids).Error
			if err != nil {
				return err
			}
			if len(ids) == 0 {
				break
			}
			lastID = ids[len(ids)-1]

			res := masterDB.GormDataSource.WithContext(ctx).
				Model(&model.User{}).
				Where("id IN ?", ids).
				Where("status = 'enabled'").
				Where("period_left = 0").
				Where("expired_date_time <= ?", nowTF).
				Where("expired_date_time > ?", cutoffTF).
				Update("status", "expired")
			if res.Error != nil {
				return res.Error
			}
			totalExpired += int(res.RowsAffected)
		}
	}

	// -------- Step 2: 标记 disabled（超过禁用阈值；兼容已是 expired 或仍是 enabled 的用户） --------
	{
		lastID := int64(0)
		for {
			var ids []int64
			err := masterDB.GormDataSource.WithContext(ctx).
				Model(&model.User{}).
				Where("period_left = 0").
				// 仅“已经超过禁用阈值”
				Where("expired_date_time IS NOT NULL").
				Where("expired_date_time <> '' AND expired_date_time <> '0000-00-00 00:00:00'").
				Where("expired_date_time <= ?", cutoffTF).
				// 状态允许从 enabled 或 expired 进入 disabled
				Where("status IN ?", []string{"enabled", "expired"}).
				Where("id > ?", lastID).
				Order("id ASC").
				Limit(batch).
				Pluck("id", &ids).Error
			if err != nil {
				return err
			}
			if len(ids) == 0 {
				break
			}
			lastID = ids[len(ids)-1]

			res := masterDB.GormDataSource.WithContext(ctx).
				Model(&model.User{}).
				Where("id IN ?", ids).
				Where("period_left = 0").
				Where("expired_date_time <= ?", cutoffTF).
				Where("status IN ?", []string{"enabled", "expired"}).
				Update("status", "disabled")
			if res.Error != nil {
				return res.Error
			}
			totalDisabled += int(res.RowsAffected)
		}
	}

	if totalExpired > 0 || totalDisabled > 0 {
		log.Debugf("[period-state] -> expired=%d, -> disabled=%d (now=%s, cutoff=%s)",
			totalExpired, totalDisabled,
			now.Local().Format(ttime.FORMAT_DATE_TIME),
			cutoff.Local().Format(ttime.FORMAT_DATE_TIME))
	}
	return nil
}

// 日志用：把 *TimeFormat 按其 Format 打印；为空/零值打印占位
func fmtTF(tf *ttime.TimeFormat) string {
	if tf == nil || tf.Time.IsZero() {
		return "<nil>"
	}
	layout := tf.Format
	if layout == "" {
		layout = ttime.FORMAT_DATE_TIME
	}
	return tf.Time.Local().Format(layout)
}
