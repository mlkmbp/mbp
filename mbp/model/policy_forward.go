package model

import (
	"mlkmbp/mbp/common/ttime"
)

type PolicyForward struct {
	Id             int64             `gorm:"column:id"`
	UserId         int64             `gorm:"column:user_id"`
	TagName        string            `gorm:"column:tag_name"`
	Protocol       string            `gorm:"column:protocol"`
	TargetAddress  string            `gorm:"column:target_address"`
	TargetPort     int               `gorm:"column:target_port"`
	AuthUsername   string            `gorm:"column:auth_username"`
	AuthPassword   string            `gorm:"column:auth_password"`
	SkipCertVerify bool              `gorm:"column:skip_cert_verify"`
	ALPN           string            `gorm:"column:alpn"`
	TLSFingerprint string            `gorm:"column:tls_fingerprint"`
	TLSSNIGuard    string            `gorm:"column:tls_sni_guard"`
	Status         string            `gorm:"column:status"`
	CreateDateTime *ttime.TimeFormat `gorm:"column:create_date_time"`
	UpdateDateTime *ttime.TimeFormat `gorm:"column:update_date_time"`
}

func (PolicyForward) TableName() string { return "policy_forward" }
