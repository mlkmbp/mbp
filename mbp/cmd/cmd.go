package cmd

import (
	"fmt"
	"mlkmbp/mbp/common/logx"
	"mlkmbp/mbp/server"
	"os"
	"strings"
)

var cmd = logx.New(logx.WithPrefix("cmd"))

const (
	defaultConfig = "./config/config.yaml"
)

func Run() {
	// 无参数：直接启动服务
	if len(os.Args) == 1 {
		must(server.Run(defaultConfig))
		return
	}

	switch os.Args[1] {
	case "help", "-h", "--help":
		printHelp()
		return

	case "newpass", "np":
		if len(os.Args) < 3 || strings.TrimSpace(os.Args[2]) == "" {
			_, _ = fmt.Fprintln(os.Stderr, "Usage: mlkmbp newpass <PASS>")
			os.Exit(2)
		}
		pass := os.Args[2]
		must(ResetAdmin(defaultConfig, pass))
		cmd.Infof("admin password updated.")

	case "purge", "pg":
		if len(os.Args) < 3 || strings.TrimSpace(os.Args[2]) == "" {
			_, _ = fmt.Fprintln(os.Stderr, "Usage: mlkmbp purge <DATESPEC>")
			_, _ = fmt.Fprintln(os.Stderr, "  DATESPEC 支持两种：")
			_, _ = fmt.Fprintln(os.Stderr, "    20250906-20251006   (闭区间范围)")
			_, _ = fmt.Fprintln(os.Stderr, "    20250906,20250907   (逗号分隔的日期列表)")
			os.Exit(2)
		}
		spec := os.Args[2]
		must(PurgeLogs(defaultConfig, spec))
		cmd.Infof("purge done.")
	default:
		// 未知参数：按 server 启动（最简体验）
		must(server.Run(defaultConfig))
	}
}

func must(err error) {
	if err != nil {
		cmd.Errorf("%v", err)
		os.Exit(1)
	}
}

func printHelp() {
	fmt.Println(`Usage:
  mlkmbp                    # 启动服务
  mlkmbp newpass <PASS>     # 重置管理员密码
  mlkmbp purge <DATESPEC>   # 清理日志表

DATESPEC:
  20250906-20251006         # 范围，包含起止日
  20250906,20250907         # 列表，逗号分隔

Examples:
  mlkmbp
  mlkmbp newpass www.mlkmbp.com
  mlkmbp purge 20250906-20250920
  mlkmbp purge 20250906,20250907`)
}
