package dao

import (
	"gorm.io/gorm"
	"mlkmbp/mbp/model"
)

func LookupUserIdByRule(db *gorm.DB, RuleId int64) (*model.UserRuleMap, error) {
	var m model.UserRuleMap
	err := db.
		Model(&model.UserRuleMap{}).
		Where("rule_id = ?", RuleId).
		First(&m).Error
	if err != nil {
		return nil, err
	}
	return &m, nil
}
