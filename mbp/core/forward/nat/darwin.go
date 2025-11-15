//go:build darwin

package nat

import (
	"context"
	"net"
)

type darwinKernel struct {
	qnum uint16
}

func NewKernel(ruleID int64) Kernel { return &darwinKernel{qnum: qnumFromRule(ruleID)} }

func (d *darwinKernel) Close() error { return nil }

func (d *darwinKernel) Install(
	ctx context.Context,
	lt, tt *net.TCPAddr,
	lu, tu *net.UDPAddr,
	ruleID int64,
	eg *Egress,
) error {
	return ErrUnsupported
}

func (d *darwinKernel) Uninstall(ctx context.Context, ruleID int64) error {
	return nil
}

func (d *darwinKernel) StartAuthGate(ctx context.Context, ruleID int64, hooks Hooks) error {
	return ErrUnsupported
}

func (d *darwinKernel) StartStats(ctx context.Context, ruleID int64, hooks Hooks) error {
	return ErrUnsupported
}

func short16(x int64) uint16 {
	u := uint64(x)
	return uint16(u ^ (u >> 16) ^ (u >> 32) ^ (u >> 48))
}
func qnumFromRule(ruleID int64) uint16 {
	const base = 1024
	const max = 65535
	return uint16(uint64(base) + (uint64(short16(ruleID)) % uint64(max-base)))
}
