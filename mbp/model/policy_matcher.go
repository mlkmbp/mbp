package model

import (
	"mlkmbp/mbp/common/ttime"
)

const (
	StatusEnabled  = "enabled"
	StatusDisabled = "disabled"

	KindIp           = "ip"
	KindCidr         = "cidr"
	KindDomainExact  = "domain_exact"
	KindDomainSuffix = "domain_suffix"
)

const (
	ActionDirect  = "direct"
	ActionForward = "forward"
	ActionReject  = "reject"
)

type PolicyMatcher struct {
	Id              int64  `gorm:"column:id"`
	UserId          int64  `gorm:"column:user_id"`
	RuleId          int64  `gorm:"column:rule_id"`
	PolicyForwardId int64  `gorm:"column:policy_forward_id"`
	Kind            string `gorm:"column:kind"`
	Action          string `gorm:"column:action"`

	// 结构化字段（匹配用）
	IpFrom   []byte `gorm:"column:ip_from"` // 16 bytes
	IpTo     []byte `gorm:"column:ip_to"`
	Domain   string `gorm:"column:domain"`
	Reversed string `gorm:"column:reversed"`

	// 回显/审计
	RawValue string `gorm:"column:raw_value"`

	Priority       int               `gorm:"column:priority"`
	Status         string            `gorm:"column:status"`
	CreateDateTime *ttime.TimeFormat `gorm:"column:create_date_time"`
	UpdateDateTime *ttime.TimeFormat `gorm:"column:update_date_time"`
}

func (PolicyMatcher) TableName() string { return "policy_matcher" }
