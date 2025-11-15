package dao

import (
	"golang.org/x/net/context"
	"gorm.io/gorm"
	"strings"
)

/******** policy_forward 读取（给引擎/上游拨号用） ********/

type PolicyForwardRow struct {
	Id             int64  `gorm:"column:id"`
	UserId         int64  `gorm:"column:user_id"`
	TagName        string `gorm:"column:tag_name"`       // 必填（API 已要求 binding:"required"）
	Protocol       string `gorm:"column:protocol"`       // http/https/http/s、socks5/ttls-socks5 等
	TargetAddress  string `gorm:"column:target_address"` // 目标 host
	TargetPort     int    `gorm:"column:target_port"`    // 目标 port
	AuthUsername   string `gorm:"column:auth_username"`
	AuthPassword   string `gorm:"column:auth_password"`
	SkipCertVerify bool   `gorm:"column:skip_cert_verify"`
	ALPN           string `gorm:"column:alpn"`
	TLSFingerprint string `gorm:"column:tls_fingerprint"`
	TLSSNIGuard    string `gorm:"column:tls_sni_guard"`
	Status         string `gorm:"column:status"`
}

func GetPolicyForwardById(ctx context.Context, db *gorm.DB, id int64) (*PolicyForwardRow, error) {
	var r PolicyForwardRow
	err := db.WithContext(ctx).
		Table("policy_forward").
		Select(`id, user_id, tag_name, protocol, target_address, target_port,
		        auth_username, auth_password, skip_cert_verify, alpn, tls_fingerprint, tls_sni_guard, status`).
		Where("id = ? AND status = 'enabled'", id).
		Take(&r).Error
	if err != nil {
		return nil, err
	}
	r.Protocol = strings.ToLower(strings.TrimSpace(r.Protocol))
	return &r, nil
}
