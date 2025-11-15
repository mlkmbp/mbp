package dao

import (
	"gorm.io/gorm"
	"mlkmbp/mbp/model"
)

// GetRuleById：按 ID 取 1 条；不存在返回 (nil, gorm.ErrRecordNotFound)
func GetRuleById(db *gorm.DB, id int64) (*model.Rule, error) {
	var r model.Rule
	err := db.Model(&model.Rule{}).Where("id = ?", id).Take(&r).Error
	if err != nil {
		return nil, err
	}
	return &r, nil
}
