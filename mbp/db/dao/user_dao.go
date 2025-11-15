package dao

import (
	"crypto/sha256"
	"encoding/hex"
	"gorm.io/gorm"
	"mlkmbp/mbp/common"
	"mlkmbp/mbp/common/logx"
	"mlkmbp/mbp/common/ttime"
	"mlkmbp/mbp/model"
	"strings"
)

var userDaoLog = logx.New(logx.WithPrefix("user.dao"))

func LoadUserInfo(db *gorm.DB, UserId int64) (*model.User, error) {
	var m model.User
	err := db.
		Model(&model.User{}).
		Where("id = ?", UserId).
		First(&m).Error
	if err != nil {
		return nil, err
	}
	return &m, nil
}

type RuleNap struct {
	Fingerprint string // 用于比对是否变更
	Enabled     bool   // 决定是否应当运行
}

func SnapshotEnabledRule(lp common.LicenseCfg, db *gorm.DB) (map[int64]RuleNap, error) {
	if !lp.Rule {
		userDaoLog.Errorf("rule has no license")
		return make(map[int64]RuleNap), nil
	}
	flag, m := common.TimeAndMachineCode(lp.RunTime, lp.MachineCode)
	if !flag {
		userDaoLog.Errorf(m)
		return make(map[int64]RuleNap), nil
	}
	type row struct {
		RuleId     int64
		RuleUpd    ttime.TimeFormat
		UserId     int64
		Status     string
		RuleStatus string
	}
	var rows []row
	// 取启用规则 + 当前映射 + 用户关键字段
	// 注意：LEFT JOIN 映射/用户，但我们只关心有映射且用户存在的情况；
	// 如果没有映射/用户，最终 Enabled=false。
	err := db.Table("rule AS r").
		Select(`
			r.id AS rule_id, r.update_date_time AS rule_upd,
			u.id AS user_id, u.status,
			r.status AS rule_status`).
		Joins("LEFT JOIN user_rule_map m ON m.rule_id = r.id").
		Joins("LEFT JOIN user u ON u.id = m.user_id").
		Where("r.status = ?", "enabled").
		Scan(&rows).Error
	if err != nil {
		return nil, err
	}

	out := make(map[int64]RuleNap, len(rows))
	for _, x := range rows {
		// 没有映射或没有用户时，不应运行（Enabled=false），但仍产出一项用于“从运行中下线”
		enabled := x.RuleStatus == "enabled" && x.UserId > 0 && x.Status == "enabled"
		uParts := []string{
			x.Status,
		}
		userIg := strings.Join(uParts, "|")

		// 全量指纹：规则更新时间 + 映射更新时间 + 用户关键字段
		h := sha256.New()
		h.Write([]byte(x.RuleUpd.String()))
		h.Write([]byte("|"))
		h.Write([]byte(userIg))
		fp := hex.EncodeToString(h.Sum(nil))

		out[x.RuleId] = RuleNap{
			Fingerprint: fp,
			Enabled:     enabled,
		}
	}
	return out, nil
}

// 只返回做业务判断所需字段（密码带回代码比对；映射用 INNER JOIN 保证存在）
type AuthRow struct {
	UserId          int64             `gorm:"column:id"`
	VmId            int64             `gorm:"column:vm_id"`
	Username        string            `gorm:"column:username"`
	Password        string            `gorm:"column:password"`
	PasswordSHA256  string            `gorm:"column:password_sha256"`
	Quota           int64             `gorm:"column:quota"`
	Up              int64             `gorm:"column:up"`
	Down            int64             `gorm:"column:down"`
	UserUpLimit     int64             `gorm:"column:user_up_limit"`
	UserDownLimit   int64             `gorm:"column:user_down_limit"`
	RuleUpLimit     int64             `gorm:"column:rule_up_limit"`
	RuleDownLimit   int64             `gorm:"column:rule_down_limit"`
	Status          string            `gorm:"column:status"`
	StartDateTime   *ttime.TimeFormat `gorm:"column:start_date_time"`
	ExpiredDateTime *ttime.TimeFormat `gorm:"column:expired_date_time"`
}

// 规则启用 + 必须存在映射（全内关联）。按 username 定位。
func FetchAuthRowByUsername(db *gorm.DB, username string) (*AuthRow, error) {
	sql := `
SELECT u.id, u.vm_id, u.username, u.password, u.password_sha256, u.status, u.start_date_time,
       u.expired_date_time, u.quota, u.up, u.down, u.up_limit AS user_up_limit, u.down_limit AS user_down_limit, r.up_limit AS rule_up_limit, r.down_limit AS rule_down_limit
FROM user u
INNER JOIN user_rule_map m ON m.user_id = u.id
INNER JOIN rule r         ON r.id = m.rule_id AND r.status = 'enabled'
WHERE u.username = ?
LIMIT 1`
	var row AuthRow
	if err := db.Raw(sql, username).Scan(&row).Error; err != nil {
		return nil, err
	}
	if row.UserId == 0 {
		return nil, gorm.ErrRecordNotFound
	}
	return &row, nil
}

// 同上，但按 UserId 定位。
func FetchAuthRowByUserId(db *gorm.DB, RuleId int64, UserId int64) (*AuthRow, error) {
	sql := `
SELECT u.id, u.vm_id, u.username, u.password, u.password_sha256, u.status, u.start_date_time,
       u.expired_date_time, u.quota, u.up, u.down, u.up_limit AS user_up_limit, u.down_limit AS user_down_limit, r.up_limit AS rule_up_limit, r.down_limit AS rule_down_limit
FROM user u
INNER JOIN user_rule_map m ON m.user_id = u.id AND m.rule_id = ?
INNER JOIN rule r         ON r.id = m.rule_id AND r.status = 'enabled'
WHERE u.id = ?
LIMIT 1`
	var row AuthRow
	if err := db.Raw(sql, RuleId, UserId).Scan(&row).Error; err != nil {
		return nil, err
	}
	if row.UserId == 0 {
		return nil, gorm.ErrRecordNotFound
	}
	return &row, nil
}
