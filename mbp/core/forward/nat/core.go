package nat

import (
	"context"
	"errors"
	"net"
	"time"
)

var ErrUnsupported = errors.New("kernel NAT unsupported on this platform or configuration")

type FlowMeta struct {
	Proto      string
	SrcIP      string
	SrcPort    uint16
	ListenIP   string
	ListenPort uint16
	RuleID     int64 // <<<<<< 改成 int64
}

type FlowStats struct {
	UserID     int64 // <<<<<< 改成 int64
	RuleID     int64 // <<<<<< 改成 int64
	Proto      string
	UpBytes    uint64
	DownBytes  uint64
	When       time.Time
	SourceAddr string
	SourcePort int
	ListenAddr string
	ListenPort int
	TargetAddr string
	TargetPort int
	DurMS      int64
}

type Hooks struct {
	// return (userID int64, allow bool, reason string)
	Auth     func(ctx context.Context, m FlowMeta) (int64, bool, string) // <<<<<< userID -> int64
	OnReject func(reason, remote string)
	OnClose  func(s FlowStats)
}

type Egress struct {
	IfName    string
	External4 net.IP
	External6 net.IP
}

type Kernel interface {
	Install(ctx context.Context, listenTCP, targetTCP *net.TCPAddr,
		listenUDP, targetUDP *net.UDPAddr, ruleID int64, eg *Egress) error // <<<<<< ruleID int64
	Uninstall(ctx context.Context, ruleID int64) error                  // <<<<<<
	StartAuthGate(ctx context.Context, ruleID int64, hooks Hooks) error // <<<<<<
	StartStats(ctx context.Context, ruleID int64, hooks Hooks) error    // <<<<<<
	Close() error
}
