package server

import (
	"context"
	"mlkmbp/mbp/api"
	"mlkmbp/mbp/app"
	"mlkmbp/mbp/common/logx"
	"mlkmbp/mbp/core/job/user"
	"os/signal"
	"syscall"
)

func Run(cfgPath string) error {
	// 1) 日志
	ginInfo, ginErr, gormInfo, gormErr, infoF, errF := logx.MustInit()
	defer ginInfo.Close()
	defer ginErr.Close()
	defer gormInfo.Close()
	defer gormErr.Close()
	defer infoF.Close()
	defer errF.Close()
	info := logx.NewStdInfo(infoF)
	errL := logx.NewStdErr(errF)

	a, err := app.New(cfgPath)
	if err != nil {
		return err
	}

	if err := a.Start(); err != nil {
		return err
	}
	info.Println("[boot] started")

	// 用户周期续期
	user.StartUserPeriodTicker(a.Ctx, a.MasterDB)
	
	// 3) Router
	r := api.New(a).Router()

	// 4) 构建单个服务器
	srv, useTLS := buildHTTPServer(a, r, errL)

	// 5) 打可访问 URL 提示
	printListenHints(srv.Addr, useTLS, info)

	// 6) 启动
	startMainAsync(srv, useTLS, errL)

	// 7) 等待退出
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	<-ctx.Done()
	stop()
	info.Println("[boot] stopping...")

	// 8) 优雅关闭
	shutdownAll(srv, a, info, errL)
	info.Println("[boot] bye")
	return nil
}
