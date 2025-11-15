package iface

import (
	"context"
)

type RuntimeCtx interface {
	Context() context.Context                 // 全局 ctx
	AcquirePermit() (release func(), ok bool) // 并发许可（每连接都要）
}
