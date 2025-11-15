package api

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"mlkmbp/mbp/common"
	"net/http"
	"strconv"
	"strings"
	"time"
)

/******** direction 规范化 ********/
func parseDirection(s string) string {
	v := strings.TrimSpace(strings.ToLower(s))
	switch v {
	case "in", "入", "1", "入站":
		return "入站"
	case "out", "出", "2", "出站":
		return "出站"
	case "nat":
		return "nat"
	default:
		return ""
	}
}

// 支持筛选：username, direction("入站"/"出站"), listen_addr, listen_port, protocol,
// source_addr, source_port, target_addr, target_port,
// start(毫秒), end(毫秒), page, size
// 新增可选快照上界：cap_time(毫秒), cap_id
func (s *Server) listTraffic(c *gin.Context) {
	if !s.App.Cfg.DB.Log.Enable {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "enable log disabled"})
		return
	}

	uid, isAdmin := common.GetAuth(c)

	// --- 页码参数 ---
	page, size := common.GetPage(c)

	// --- 时间范围（毫秒），默认今天；超过 7 天 => 报错 ---
	startMs, _ := strconv.ParseInt(c.DefaultQuery("start", "0"), 10, 64)
	endMs, _ := strconv.ParseInt(c.DefaultQuery("end", "0"), 10, 64)
	if startMs <= 0 || endMs <= 0 || endMs < startMs {
		now := time.Now()
		begin := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.Local)
		startMs = begin.UnixMilli()
		endMs = begin.Add(24*time.Hour - time.Millisecond).UnixMilli()
	}
	start := time.UnixMilli(startMs).In(time.Local)
	end := time.UnixMilli(endMs).In(time.Local)

	const maxRange = 7 * 24 * time.Hour
	if end.Sub(start) > maxRange {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":           "time_range_exceeds_limit",
			"message":         "The time range cannot exceed 7 days",
			"limit_days":      7,
			"requested_start": start.Format("2006-01-02 15:04:05"),
			"requested_end":   end.Format("2006-01-02 15:04:05"),
		})
		return
	}

	// --- 分表集合 ---
	allTables := collectLogTablesByRange(start, end)
	existTables := filterExistingTablesGorm(s.App.LogDB.GormDataSource, allTables)
	if len(existTables) == 0 {
		c.JSON(http.StatusOK, gin.H{
			"list": []any{}, "total": 0, "page": 1, "size": size,
			"sum_up": 0, "sum_down": 0,
		})
		return
	}

	// --- 参数解析 ---
	username := strings.TrimSpace(c.Query("username"))
	dirParam := parseDirection(c.Query("direction")) // "入站"/"出站"/""
	listenAddr := strings.TrimSpace(c.Query("listen_addr"))
	listenPort, _ := strconv.Atoi(strings.TrimSpace(c.Query("listen_port")))
	protocol := strings.TrimSpace(c.Query("protocol"))
	sourceAddr := strings.TrimSpace(c.Query("source_addr"))
	sourcePort, _ := strconv.Atoi(strings.TrimSpace(c.Query("source_port")))
	targetAddr := strings.TrimSpace(c.Query("target_addr"))
	targetPort, _ := strconv.Atoi(strings.TrimSpace(c.Query("target_port")))

	// 可选快照上界（第一页首条建立的锚点）
	capTime, _ := strconv.ParseInt(strings.TrimSpace(c.DefaultQuery("cap_time", "0")), 10, 64)
	capID, _ := strconv.ParseInt(strings.TrimSpace(c.DefaultQuery("cap_id", "0")), 10, 64)
	useCap := capTime > 0 && capID > 0

	// 非管理员：强制自己的 username（精确），忽略前端传来的 username
	if !isAdmin {
		var me struct{ Username string }
		_ = s.App.MasterDB.GormDataSource.
			Table("user").Select("username").
			Where("id = ?", uid).
			Scan(&me).Error
		username = me.Username
	}

	// --- WHERE（每个分表子查询共享） ---
	whereParts := []string{"time BETWEEN ? AND ?"}
	args := []any{start.UnixMilli(), end.UnixMilli()}

	// [FIX] username：管理员支持模糊匹配；非管理员严格等值
	if username != "" {
		if isAdmin {
			whereParts = append(whereParts, "username LIKE ?")
			args = append(args, "%"+username+"%")
		} else {
			whereParts = append(whereParts, "username = ?")
			args = append(args, username)
		}
	}
	if dirParam != "" {
		whereParts = append(whereParts, "direction = ?")
		args = append(args, dirParam)
	}
	if listenAddr != "" {
		whereParts = append(whereParts, "listen_addr LIKE ?")
		args = append(args, "%"+listenAddr+"%")
	}
	if listenPort > 0 {
		whereParts = append(whereParts, "listen_port = ?")
		args = append(args, listenPort)
	}
	if protocol != "" {
		whereParts = append(whereParts, "protocol = ?")
		args = append(args, strings.ToLower(protocol))
	}
	if sourceAddr != "" {
		whereParts = append(whereParts, "source_addr LIKE ?")
		args = append(args, "%"+sourceAddr+"%")
	}
	if sourcePort > 0 {
		whereParts = append(whereParts, "source_port = ?")
		args = append(args, sourcePort)
	}
	if targetAddr != "" {
		whereParts = append(whereParts, "target_addr LIKE ?")
		args = append(args, "%"+targetAddr+"%")
	}
	if targetPort > 0 {
		whereParts = append(whereParts, "target_port = ?")
		args = append(args, targetPort)
	}
	whereSQL := " WHERE " + strings.Join(whereParts, " AND ")

	// --- 统一列 ---
	const selectCols = "id, time, username, direction, listen_addr, listen_port, protocol, up, down, dur, source_addr, source_port, target_addr, target_port"

	// --- UNION ALL（按日分表）---
	unions := make([]string, 0, len(existTables))
	for _, t := range existTables {
		unions = append(unions, fmt.Sprintf(
			"SELECT %s FROM `%s`%s",
			selectCols, t, whereSQL,
		))
	}
	unionSQL := strings.Join(unions, " UNION ALL ")
	unionArgs := replicateArgs(args, len(unions))

	// --- 快照上界过滤（外层），与排序键一致：time DESC, id DESC ---
	// [FIX] cap 语义与排序保持一致：当 time 相等时，按 id 递减确定顺序，cap 用 <= 保证稳定
	outerCapWhere := ""
	outerCapArgs := make([]any, 0, 3)
	if useCap {
		outerCapWhere = " WHERE (time < ? OR (time = ? AND id <= ?))"
		outerCapArgs = append(outerCapArgs, capTime, capTime, capID)
	}

	// --- 统计总数（含 cap 上界）---
	countSQL := fmt.Sprintf("SELECT COUNT(1) AS total FROM ( %s ) AS allrows%s", unionSQL, outerCapWhere)
	var total int64
	if err := s.App.LogDB.GormDataSource.Raw(countSQL, append(unionArgs, outerCapArgs...)...).Scan(&total).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "query_failed",
			"message": err.Error(),
		})
		return
	}

	// --- 汇总（含 cap 上界；与列表一致）---
	sumSQL := fmt.Sprintf(
		"SELECT COALESCE(SUM(up),0) AS sum_up, COALESCE(SUM(down),0) AS sum_down FROM ( %s ) AS allrows%s",
		unionSQL, outerCapWhere,
	)
	var sum struct{ SumUp, SumDown int64 }
	if err := s.App.LogDB.GormDataSource.Raw(sumSQL, append(unionArgs, outerCapArgs...)...).Scan(&sum).Error; err != nil {
		sum.SumUp, sum.SumDown = 0, 0
	}

	// --- total==0：直接返回，page=1 ---
	if total == 0 {
		c.JSON(http.StatusOK, gin.H{
			"list":     []any{},
			"total":    0,
			"page":     1,
			"size":     size,
			"sum_up":   sum.SumUp,
			"sum_down": sum.SumDown,
		})
		return
	}

	// --- 纠正页码，避免越界 ---
	maxPage := int((total + int64(size) - 1) / int64(size))
	if page > maxPage {
		page = maxPage
	}
	offset := (page - 1) * size
	if offset < 0 {
		offset = 0
	}

	// --- 列表：严格使用 time DESC, id DESC 排序（与 cap 对齐）---
	querySQL := fmt.Sprintf(
		"SELECT * FROM ( %s ) AS allrows%s ORDER BY time DESC, id DESC LIMIT ? OFFSET ?",
		unionSQL, outerCapWhere,
	)
	qArgs := append(append(unionArgs, outerCapArgs...), size, offset)

	type row struct {
		ID         int64
		Time       int64
		Username   string
		Direction  string
		ListenAddr string
		ListenPort int
		Protocol   string
		Up         int64
		Down       int64
		Dur        int64
		SourceAddr string
		SourcePort int
		TargetAddr string
		TargetPort int
	}
	var rows []row
	if err := s.App.LogDB.GormDataSource.Raw(querySQL, qArgs...).Scan(&rows).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "query_failed",
			"message": err.Error(),
		})
		return
	}

	type outRow struct {
		ID         int64  `json:"id"`
		Time       int64  `json:"time"`
		Username   string `json:"username"`
		Direction  string `json:"direction"`
		ListenAddr string `json:"listen_addr"`
		ListenPort int    `json:"listen_port"`
		Protocol   string `json:"protocol"`
		Up         int64  `json:"up"`
		Down       int64  `json:"down"`
		Dur        int64  `json:"dur"`
		SourceAddr string `json:"source_addr"`
		SourcePort int    `json:"source_port"`
		TargetAddr string `json:"target_addr"`
		TargetPort int    `json:"target_port"`
	}
	outs := make([]outRow, 0, len(rows))
	for _, r := range rows {
		outs = append(outs, outRow{
			ID:         r.ID,
			Time:       r.Time,
			Username:   r.Username,
			Direction:  r.Direction,
			ListenAddr: r.ListenAddr,
			ListenPort: r.ListenPort,
			Protocol:   r.Protocol,
			Up:         r.Up,
			Down:       r.Down,
			Dur:        r.Dur,
			SourceAddr: r.SourceAddr,
			SourcePort: r.SourcePort,
			TargetAddr: r.TargetAddr,
			TargetPort: r.TargetPort,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"list":     outs,
		"total":    total,
		"page":     page,
		"size":     size,
		"sum_up":   sum.SumUp,
		"sum_down": sum.SumDown,
	})
}

/******** helpers ********/

// 生成 start..end（含）之间每天的表名
func collectLogTablesByRange(start, end time.Time) []string {
	var out []string
	for d := time.Date(start.Year(), start.Month(), start.Day(), 0, 0, 0, 0, start.Location()); !d.After(end); d = d.Add(24 * time.Hour) {
		out = append(out, fmt.Sprintf("traffic_log_%s", d.Format("20060102")))
	}
	return out
}

// 过滤存在的分表（GORM Migrator）
func filterExistingTablesGorm(db *gorm.DB, tables []string) []string {
	var existed []string
	for _, t := range tables {
		if db.Migrator().HasTable(t) {
			existed = append(existed, t)
		}
	}
	return existed
}

// 把一组参数复制 times 次（UNION 的每个子查询要一份相同参数）
func replicateArgs(args []any, times int) []any {
	out := make([]any, 0, len(args)*times)
	for i := 0; i < times; i++ {
		out = append(out, args...)
	}
	return out
}
