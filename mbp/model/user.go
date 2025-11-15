package model

import (
	"mlkmbp/mbp/common/ttime"
)

type PeriodUnit string

const (
	PeriodDay   PeriodUnit = "day"   // 天
	PeriodMonth PeriodUnit = "month" // 月
)

type User struct {
	Id              int64             `gorm:"column:id"`
	VmId            int64             `gorm:"column:vm_id"`
	Username        string            `gorm:"column:username"`
	Password        string            `gorm:"column:password"`
	PasswordSha256  string            `gorm:"column:password_sha256"`
	Quota           int64             `gorm:"column:quota"`
	Up              int64             `gorm:"column:up"`
	Down            int64             `gorm:"column:down"`
	UpLimit         int64             `gorm:"column:up_limit"`
	DownLimit       int64             `gorm:"column:down_limit"`
	Status          string            `gorm:"column:status"`
	StartDateTime   *ttime.TimeFormat `gorm:"column:start_date_time"`
	ExpiredDateTime *ttime.TimeFormat `gorm:"column:expired_date_time"`
	PeriodUnit      PeriodUnit        `gorm:"column:period_unit"`
	PeriodLeft      int64             `gorm:"column:period_left"`
	CreateDateTime  *ttime.TimeFormat `gorm:"column:create_date_time"`
	UpdateDateTime  *ttime.TimeFormat `gorm:"column:update_date_time"`
}

func (User) TableName() string { return "user" }
