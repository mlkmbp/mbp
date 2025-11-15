package transport

import (
	"context"
	"io"
	"mlkmbp/mbp/common"
	"net"
	"sync"
	"time"
)

func enableTCPKA(c net.Conn, period time.Duration) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		if period > 0 {
			_ = tc.SetKeepAlivePeriod(period)
		}
		_ = tc.SetNoDelay(true) // 可选
	}
}

// 只在写时加 deadline；不动 Read（避免把长连接读断）
type deadlineWriter struct {
	net.Conn
	idle time.Duration
}

func (d *deadlineWriter) Write(p []byte) (int, error) {
	if d.idle > 0 {
		_ = d.Conn.SetWriteDeadline(time.Now().Add(d.idle))
	}
	return d.Conn.Write(p)
}

func Pipe(ctx context.Context, left, right net.Conn) {
	// 开启 TCP keepalive
	enableTCPKA(left, 30*time.Second)
	enableTCPKA(right, 30*time.Second)

	const writeIdle = 2 * time.Minute
	lw := &deadlineWriter{Conn: left, idle: writeIdle}
	rw := &deadlineWriter{Conn: right, idle: writeIdle}

	var wg sync.WaitGroup
	wg.Add(2)

	done := make(chan struct{})

	// 取消时唤醒，避免 goroutine 永久阻塞
	go func() {
		select {
		case <-ctx.Done():
			common.Nudge(left)
			common.Nudge(right)
			time.AfterFunc(200*time.Millisecond, func() {
				_ = left.Close()
				_ = right.Close()
			})
		case <-done:
		}
	}()

	// left -> right（对 right 的写加 deadline）
	go func() {
		defer wg.Done()
		_, _ = io.Copy(rw, left)
		common.CloseWriteIfTCP(right)
		common.Nudge(right)
	}()

	// right -> left（对 left 的写加 deadline）
	go func() {
		defer wg.Done()
		_, _ = io.Copy(lw, right)
		common.CloseWriteIfTCP(left)
		common.Nudge(left)
	}()

	wg.Wait()
	close(done)
	_ = left.Close()
	_ = right.Close()
}
