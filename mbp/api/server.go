package api

import (
	"database/sql"
	"fmt"
	"mlkmbp/mbp/app"
	"mlkmbp/mbp/common/bruteguard"

	"strings"
	"time"
)

type Server struct {
	Guard *bruteguard.Guard
	App   *app.App
}

func New(app *app.App) *Server {
	return &Server{App: app}
}

// 根据配置，生成需要查询的表名切片：不分表=单表；分表=按天生成
func (s *Server) collectLogTables(start, end time.Time) []string {

	var ts []string
	for d := start; !d.After(end); d = d.Add(24 * time.Hour) {
		ts = append(ts, fmt.Sprintf("%s_%04d%02d%02d",
			"traffic_logs", d.Year(), int(d.Month()), d.Day()))
	}
	return ts
}

func (s *Server) filterExistingTables(db *sql.DB, tables []string) []string {
	if len(tables) == 0 {
		return nil
	}
	// 去重
	seen := make(map[string]struct{}, len(tables))
	uniq := make([]string, 0, len(tables))
	for _, t := range tables {
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		uniq = append(uniq, t)
	}

	switch s.App.Cfg.DB.Log.Driver { // "sqlite" / "sqlite3" / "mysql"
	case "sqlite", "sqlite3":
		ph := strings.TrimRight(strings.Repeat("?,", len(uniq)), ",")
		sqlStr := "SELECT name FROM sqlite_master WHERE type='table' AND name IN (" + ph + ")"
		args := make([]any, len(uniq))
		for i, t := range uniq {
			args[i] = t
		}
		rows, err := db.Query(sqlStr, args...)
		if err != nil {
			return nil
		}
		defer rows.Close()
		ok := map[string]struct{}{}
		for rows.Next() {
			var n string
			if rows.Scan(&n) == nil {
				ok[n] = struct{}{}
			}
		}
		out := make([]string, 0, len(ok))
		for _, t := range uniq {
			if _, hit := ok[t]; hit {
				out = append(out, t)
			}
		}
		return out

	case "mysql":
		ph := strings.TrimRight(strings.Repeat("?,", len(uniq)), ",")
		sqlStr := "SELECT table_name FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name IN (" + ph + ")"
		args := make([]any, len(uniq))
		for i, t := range uniq {
			args[i] = t
		}
		rows, err := db.Query(sqlStr, args...)
		if err != nil {
			return nil
		}
		defer rows.Close()
		ok := map[string]struct{}{}
		for rows.Next() {
			var n string
			if rows.Scan(&n) == nil {
				ok[n] = struct{}{}
			}
		}
		out := make([]string, 0, len(ok))
		for _, t := range uniq {
			if _, hit := ok[t]; hit {
				out = append(out, t)
			}
		}
		return out

	default:
		// 未知驱动：保守返回原表
		return uniq
	}
}
