package cmd

import (
	"context"
	"fmt"
	"gorm.io/gorm"
	"mlkmbp/mbp/app"
	"mlkmbp/mbp/common"
	"mlkmbp/mbp/common/logx"
	"mlkmbp/mbp/db"
	"mlkmbp/mbp/model"
	"sort"
	"strings"
	"time"
)

var ops = logx.New(logx.WithPrefix("ops"))

/********** Admin 密码重置 **********/

// ResetAdmin 把配置里的管理员 ID 的密码重置为 newPass。
// 优先从 cfg.Admin.AdminIDs 读取；若没有该字段则回退反射提取。
func ResetAdmin(cfgPath string, newPass string) error {
	if strings.TrimSpace(newPass) == "" {
		return fmt.Errorf("newPass required")
	}
	a, err := app.New(cfgPath)
	if err != nil {
		return fmt.Errorf("init app: %w", err)
	}
	defer a.Stop()

	db := extractGorm(a.MasterDB)
	ids := a.Cfg.Admin.AdminIDs
	if len(ids) == 0 {
		return fmt.Errorf("no admin ids found in config")
	}

	// 10 秒超时
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 同时更新明文与 SHA256（common.HashUP）
	tx := db.WithContext(ctx).
		Model(&model.User{}).
		Where("id IN ?", ids).
		Updates(map[string]any{
			"password":         newPass,
			"password_sha256":  common.HashUP(newPass),
			"update_date_time": time.Now(),
			"status":           "enabled",
		})

	if tx.Error != nil {
		return tx.Error
	}
	if tx.RowsAffected == 0 {
		ops.Infof("[reset-admin] no rows updated (ids=%v)\n", ids)
	} else {
		ops.Infof("[reset-admin] updated %d row(s), ids=%v\n", tx.RowsAffected, ids)
	}
	return nil
}

/********** 日志清理（按天表） **********/

// PurgeLogs 按日期清理日志表（使用 model.TrafficTable(day) 动态表名）。
// dateSpec 支持：
//
//	"20250906-20251006"   范围（闭区间）
//	"20250906,20250907"   列表（逗号分隔）
func PurgeLogs(cfgPath string, dateSpec string) error {
	if strings.TrimSpace(dateSpec) == "" {
		return fmt.Errorf("dateSpec required")
	}
	a, err := app.New(cfgPath)
	if err != nil {
		return fmt.Errorf("init app: %w", err)
	}
	defer a.Stop()
	db := extractGorm(a.LogDB)

	dates, err := expandDateSpec(dateSpec)
	if err != nil {
		return err
	}
	if len(dates) == 0 {
		ops.Infof("[purge-log] nothing to do")
		return nil
	}

	for _, d := range dates {
		tbl := model.TrafficTable(d) // e.g. traffic_log_20250906

		// 表不存在：跳过
		if !db.Migrator().HasTable(tbl) {
			ops.Infof("[purge-log] skip (not exists): %s\n", tbl)
			continue
		}

		// 1) TRUNCATE（MySQL 可用；SQLite 不支持）
		if err := execWithTimeout(db, 15*time.Second, fmt.Sprintf("TRUNCATE TABLE `%s`", tbl)); err == nil {
			ops.Infof("[purge-log] truncated: %s\n", tbl)
			continue
		}

		// 2) DELETE 全表
		if err := execWithTimeout(db, 60*time.Second, fmt.Sprintf("DELETE FROM `%s`", tbl)); err == nil {
			ops.Infof("[purge-log] deleted rows: %s\n", tbl)
			continue
		}

		// 3) 兜底：DROP 表（一般不会走到；需要回收空间时可用）
		if err := db.Migrator().DropTable(tbl); err == nil {
			ops.Infof("[purge-log] dropped: %s (fallback)\n", tbl)
			continue
		}

		return fmt.Errorf("purge %s failed: truncate/delete/drop all failed", tbl)
	}
	return nil
}

/********** DB/工具 **********/

// 在指定超时时间内执行原始 SQL
func execWithTimeout(db *gorm.DB, timeout time.Duration, query string) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return db.WithContext(ctx).Exec(query).Error
}

func extractGorm(db *db.DB) *gorm.DB {
	if db != nil {
		return db.GormDataSource
	}
	panic("cannot extract *gorm.DB from data source")
}

/********** 日期展开 **********/

func expandDateSpec(spec string) ([]string, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, nil
	}

	// 范围：YYYYMMDD-YYYYMMDD
	if strings.Contains(spec, "-") {
		ps := strings.Split(spec, "-")
		if len(ps) != 2 {
			return nil, fmt.Errorf("bad range: %s", spec)
		}
		start, err := parseYYYYMMDD(ps[0])
		if err != nil {
			return nil, err
		}
		end, err := parseYYYYMMDD(ps[1])
		if err != nil {
			return nil, err
		}
		if end.Before(start) {
			return nil, fmt.Errorf("end before start")
		}
		var out []string
		for d := start; !d.After(end); d = d.AddDate(0, 0, 1) {
			out = append(out, d.Format("20060102"))
		}
		return out, nil
	}

	// 列表：YYYYMMDD,YYYYMMDD
	ps := strings.Split(spec, ",")
	uniq := make(map[string]struct{}, len(ps))
	for _, p := range ps {
		d, err := parseYYYYMMDD(p)
		if err != nil {
			return nil, err
		}
		uniq[d.Format("20060102")] = struct{}{}
	}
	out := make([]string, 0, len(uniq))
	for k := range uniq {
		out = append(out, k)
	}
	sort.Strings(out)
	return out, nil
}

func parseYYYYMMDD(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if len(s) != 8 {
		return time.Time{}, fmt.Errorf("bad date: %s", s)
	}
	return time.ParseInLocation("20060102", s, time.Local)
}
