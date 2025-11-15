package model

import "fmt"

type TrafficLog struct {
	Id         int64  `gorm:"column:id"`
	Time       int64  `gorm:"column:time"`     // 毫秒；单列时间索引用于纯时间范围扫描
	Username   string `gorm:"column:username"` // 去掉 unique
	Direction  string `gorm:"column:direction"`
	ListenAddr string `gorm:"column:listen_addr"`
	ListenPort int    `gorm:"column:listen_port"`
	Protocol   string `gorm:"column:protocol"`
	Up         int64  `gorm:"column:up"`
	Down       int64  `gorm:"column:down"`
	Dur        int64  `gorm:"column:dur"`
	SourceAddr string `gorm:"column:source_addr"`
	SourcePort int    `gorm:"column:source_port"`
	TargetAddr string `gorm:"column:target_addr"`
	TargetPort int    `gorm:"column:target_port"`
}

func TrafficTable(day string) string {
	return fmt.Sprintf("traffic_log_%s", day) // e.g. 20250906
}
