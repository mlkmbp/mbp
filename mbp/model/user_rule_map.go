package model

import (
	"mlkmbp/mbp/common/ttime"
)

type UserRuleMap struct {
	Id             int64             `gorm:"column:id"`
	UserId         int64             `gorm:"column:user_id"`
	RuleId         int64             `gorm:"column:rule_id"`
	CreateDateTime *ttime.TimeFormat `gorm:"column:create_date_time"`
	UpdateDateTime *ttime.TimeFormat `gorm:"column:update_date_time"`
}

func (UserRuleMap) TableName() string { return "user_rule_map" }
