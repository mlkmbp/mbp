package model

import (
	"mlkmbp/mbp/common/ttime"
)

type Rule struct {
	Id            int64  `gorm:"column:id"`
	UserId        int64  `gorm:"column:user_id"`
	RuleName      string `gorm:"column:rule_name"`
	InterfaceName string `gorm:"column:interface_name"`
	Protocol      string `gorm:"column:protocol"`
	Address       string `gorm:"column:address"`
	Port          int    `gorm:"column:port"`
	TargetAddress string `gorm:"column:target_address"`
	TargetPort    int    `gorm:"column:target_port"`
	UpLimit       int64  `gorm:"column:up_limit"`
	DownLimit     int64  `gorm:"column:down_limit"`
	Status        string `gorm:"column:status"`
	MaxConnection int    `gorm:"column:max_connection"`
	ConnTimeout   int    `gorm:"column:conn_timeout"`
	ReadTimeout   int    `gorm:"column:read_timeout"`
	WriteTimeout  int    `gorm:"column:write_timeout"`

	AuthUsername string `gorm:"column:auth_username"`
	AuthPassword string `gorm:"column:auth_password"`

	SkipCertVerify bool   `gorm:"column:skip_cert_verify"`
	ALPN           string `gorm:"column:alpn"`
	TLSFingerprint string `gorm:"column:tls_fingerprint"`

	TLSCert     string `gorm:"column:tls_cert"`
	TLSKey      string `gorm:"column:tls_key"`
	TLSSNIGuard string `gorm:"column:tls_sni_guard"`

	Socks5UDPPort  int `gorm:"column:socks5_udp_port"`
	Socks5BindPort int `gorm:"column:socks5_bind_port"`

	CreateDateTime *ttime.TimeFormat `gorm:"column:create_date_time"`
	UpdateDateTime *ttime.TimeFormat `gorm:"column:update_date_time"`
}

func (Rule) TableName() string { return "rule" }
