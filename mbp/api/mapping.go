package api

import (
	"errors"
	"fmt"
	"mlkmbp/mbp/common"
	"mlkmbp/mbp/model"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

/* ===================== 小工具 ===================== */

func toInt64(s string) int64 {
	var out int64
	fmt.Sscanf(s, "%d", &out)
	return out
}

// 强不变式：只要 ownerID>0，就确保 (ownerID, ruleID) 这条映射存在（幂等 Upsert）
func ensureOwnerMapping(tx *gorm.DB, ruleID, ownerID int64) error {
	if ownerID <= 0 {
		return nil
	}
	rec := model.UserRuleMap{UserId: ownerID, RuleId: ruleID}
	// 依赖 user_rule_map 上 (user_id, rule_id) 唯一约束
	return tx.
		Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "user_id"}, {Name: "rule_id"}},
			DoNothing: true,
		}).
		Create(&rec).Error
}

/* ========== 规则主：列表（含筛选 & 绑定预览） ========== */
// GET /api/rule-binding?protocol=&listen_addr=&listen_port=&target_addr=&target_port=&page=&size=
func (s *Server) listRuleBinding(c *gin.Context) {
	uid, isAdmin := common.GetAuth(c)

	page, size := common.GetPage(c)
	offset := (page - 1) * size

	protocol := strings.TrimSpace(c.Query("protocol"))
	laddr := strings.TrimSpace(c.Query("listen_addr"))
	lport, _ := strconv.Atoi(strings.TrimSpace(c.Query("listen_port")))
	taddr := strings.TrimSpace(c.Query("target_addr"))
	tport, _ := strconv.Atoi(strings.TrimSpace(c.Query("target_port")))

	db := s.App.MasterDB.GormDataSource

	base := db.Table("rule r").
		Select(`r.id, r.protocol, r.address, r.port, r.target_address, r.target_port, r.status, r.user_id AS owner_id, u.username AS owner_name`).
		Joins("LEFT JOIN user u ON u.id = r.user_id")

	// 非管理员：仅可见“自己是 owner 或已绑定”的规则
	if !isAdmin {
		base = base.Where(`r.user_id = ? OR EXISTS (SELECT 1 FROM user_rule_map m WHERE m.rule_id = r.id AND m.user_id = ?)`, uid, uid)
	}

	if protocol != "" {
		base = base.Where("LOWER(r.protocol) = ?", strings.ToLower(protocol))
	}
	if laddr != "" {
		base = base.Where("r.address LIKE ?", "%"+laddr+"%")
	}
	if lport > 0 {
		base = base.Where("r.port = ?", lport)
	}
	if taddr != "" {
		base = base.Where("r.target_address LIKE ?", "%"+taddr+"%")
	}
	if tport > 0 {
		base = base.Where("r.target_port = ?", tport)
	}

	var total int64
	if err := base.Count(&total).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	var rows []struct {
		ID            int64
		Protocol      string
		Address       string
		Port          int
		TargetAddress string
		TargetPort    int
		Status        string
		OwnerID       int64  `gorm:"column:owner_id"`
		OwnerName     string `gorm:"column:owner_name"`
	}
	if err := base.Order("r.id DESC").Limit(size).Offset(offset).Scan(&rows).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if len(rows) == 0 {
		c.JSON(http.StatusOK, gin.H{"list": []any{}, "total": total, "page": page, "size": size})
		return
	}

	// 聚合绑定用户（数量 + 预览前三个），并排除 owner
	ruleIDs := make([]int64, 0, len(rows))
	ownerMap := map[int64]int64{} // rule_id -> owner_id
	for _, r := range rows {
		ruleIDs = append(ruleIDs, r.ID)
		ownerMap[r.ID] = r.OwnerID
	}

	type pair struct {
		RuleId   int64
		UserId   int64
		Username string
	}
	var binds []pair
	_ = db.Table("user_rule_map m").
		Select("m.rule_id, u.id AS user_id, u.username").
		Joins("JOIN user u ON u.id = m.user_id").
		Where("m.rule_id IN ?", ruleIDs).
		Order("u.id").
		Scan(&binds)

	type bindInfo struct {
		Count     int
		Usernames []string
	}
	bmap := map[int64]*bindInfo{}
	for _, b := range binds {
		// 跳过 owner
		if ownerMap[b.RuleId] > 0 && b.UserId == ownerMap[b.RuleId] {
			continue
		}
		if bmap[b.RuleId] == nil {
			bmap[b.RuleId] = &bindInfo{}
		}
		bmap[b.RuleId].Count++
		if len(bmap[b.RuleId].Usernames) < 3 {
			bmap[b.RuleId].Usernames = append(bmap[b.RuleId].Usernames, b.Username)
		}
	}

	type item struct {
		ID         int64  `json:"id"`
		Protocol   string `json:"protocol"`
		ListenAddr string `json:"listen_addr"`
		ListenPort int    `json:"listen_port"`
		TargetAddr string `json:"target_addr"`
		TargetPort int    `json:"target_port"`
		Status     string `json:"status"`
		OwnerID    int64  `json:"owner_id"`
		Owner      string `json:"owner"`
		BindCnt    int    `json:"bind_count"`
		BindPeek   string `json:"bind_peek"`
	}
	out := make([]item, 0, len(rows))
	for _, r := range rows {
		peek := ""
		cnt := 0
		if bi := bmap[r.ID]; bi != nil {
			cnt = bi.Count
			peek = strings.Join(bi.Usernames, ",")
		}
		out = append(out, item{
			ID:         r.ID,
			Protocol:   r.Protocol,
			ListenAddr: r.Address,
			ListenPort: r.Port,
			TargetAddr: r.TargetAddress,
			TargetPort: r.TargetPort,
			Status:     r.Status,
			OwnerID:    r.OwnerID,
			Owner:      r.OwnerName,
			BindCnt:    cnt,
			BindPeek:   peek,
		})
	}

	c.JSON(http.StatusOK, gin.H{"list": out, "total": total, "page": page, "size": size})
}

/* ========== 规则主：获取某规则的绑定用户（含 OWNER） ========== */
// GET /api/rule/:id/binding?q=&page=&size=
func (s *Server) getRuleBinding(c *gin.Context) {
	_, isAdmin := common.GetAuth(c)
	if !isAdmin {
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
		return
	}
	id := c.Param("id")
	page, size := common.GetPage(c)
	offset := (page - 1) * size
	q := strings.TrimSpace(c.DefaultQuery("q", ""))

	db := s.App.MasterDB.GormDataSource

	var rule struct {
		ID       int64
		OwnerID  int64
		Owner    string
		Protocol string
	}
	if err := db.Table("rule r").
		Select("r.id, r.user_id AS owner_id, u.username AS owner, r.protocol").
		Joins("LEFT JOIN user u ON u.id = r.user_id").
		Where("r.id = ?", id).
		Take(&rule).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "rule not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	base := db.Table("user_rule_map m").
		Select("u.id, u.username").
		Joins("JOIN user u ON u.id = m.user_id").
		Where("m.rule_id = ?", id)
	if q != "" {
		base = base.Where("u.username LIKE ?", "%"+q+"%")
	}
	if rule.OwnerID > 0 {
		base = base.Where("u.id <> ?", rule.OwnerID) // 弹窗列表不包含 owner
	}

	var total int64
	if err := base.Count(&total).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	var rows []struct {
		ID       int64  `json:"id"`
		Username string `json:"username"`
	}
	if err := base.Order("u.id").Limit(size).Offset(offset).Scan(&rows).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	ownerIncluded := false
	for _, r := range rows {
		if r.ID == rule.OwnerID && rule.OwnerID > 0 {
			ownerIncluded = true
			break
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"owner":     gin.H{"id": rule.OwnerID, "username": rule.Owner},
		"list":      rows,
		"total":     total,
		"page":      page,
		"size":      size,
		"has_owner": ownerIncluded,
		"protocol":  rule.Protocol,
	})
}

/* ========== 用户搜索（候选列表） ========== */
// GET /api/user/search?q=&page=&size=
func (s *Server) searchUser(c *gin.Context) {
	_, isAdmin := common.GetAuth(c)
	if !isAdmin {
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
		return
	}

	page, size := common.GetPage(c)
	offset := (page - 1) * size
	q := strings.TrimSpace(c.DefaultQuery("q", ""))

	db := s.App.MasterDB.GormDataSource

	base := db.Table("user").Select("id, username").Where("vm_id = 0")
	if q != "" {
		base = base.Where("username LIKE ?", "%"+q+"%")
	}

	var total int64
	if err := base.Count(&total).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	var rows []struct {
		ID       int64  `json:"id"`
		Username string `json:"username"`
	}
	if err := base.Order("id").Limit(size).Offset(offset).Scan(&rows).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"list": rows, "total": total, "page": page, "size": size})
}

/* ========== 规则主：增删改绑定（不动 OWNER） ========== */

// PUT /api/rule/:id/binding   body: { "user_ids": [1,2,3] }
func (s *Server) replaceRuleBinding(c *gin.Context) {
	_, isAdmin := common.GetAuth(c)
	if !isAdmin {
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
		return
	}

	ruleId := c.Param("id")
	var req struct {
		UserIds []int64 `json:"user_ids"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		return
	}

	db := s.App.MasterDB.GormDataSource

	// owner
	var ownerID int64
	if err := db.Table("rule").Select("user_id").Where("id = ?", ruleId).Scan(&ownerID).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 去重 + 排除 owner
	seen := map[int64]struct{}{}
	final := make([]int64, 0, len(req.UserIds))
	for _, id := range req.UserIds {
		if id <= 0 || id == ownerID {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		final = append(final, id)
	}

	err := db.Transaction(func(tx *gorm.DB) error {
		// 只删除“非 owner”的映射
		if err := tx.Where("rule_id = ? AND user_id <> ?", ruleId, ownerID).
			Delete(&model.UserRuleMap{}).Error; err != nil {
			return err
		}

		// 重建非 owner 的映射
		if len(final) > 0 {
			recs := make([]model.UserRuleMap, 0, len(final))
			rid := toInt64(ruleId)
			for _, uid := range final {
				recs = append(recs, model.UserRuleMap{UserId: uid, RuleId: rid})
			}
			if err := tx.Create(&recs).Error; err != nil {
				return err
			}
		}

		// 强不变式：确保 owner 的映射存在
		return ensureOwnerMapping(tx, toInt64(ruleId), ownerID)
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// POST /api/rule/:id/binding   body: { "user_id": 123 }
func (s *Server) addOneBinding(c *gin.Context) {
	_, isAdmin := common.GetAuth(c)
	if !isAdmin {
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
		return
	}
	ruleId := c.Param("id")
	var req struct {
		UserId int64 `json:"user_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.UserId <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		return
	}

	db := s.App.MasterDB.GormDataSource

	var ownerID int64
	if err := db.Table("rule").Select("user_id").Where("id = ?", ruleId).Scan(&ownerID).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if req.UserId == ownerID {
		// 确保 owner 映射存在
		if err := ensureOwnerMapping(db, toInt64(ruleId), ownerID); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true})
		return
	}

	var cnt int64
	_ = db.Table("user_rule_map").Where("rule_id = ? AND user_id = ?", ruleId, req.UserId).Count(&cnt)
	if cnt > 0 {
		c.JSON(http.StatusOK, gin.H{"ok": true})
		return
	}
	rec := model.UserRuleMap{UserId: req.UserId, RuleId: toInt64(ruleId)}
	if err := db.Create(&rec).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// DELETE /api/rule/:id/binding/:user_id
func (s *Server) deleteOneBinding(c *gin.Context) {
	_, isAdmin := common.GetAuth(c)
	if !isAdmin {
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
		return
	}
	ruleId := c.Param("id")
	userId := c.Param("user_id")

	var ownerID int64
	if err := s.App.MasterDB.GormDataSource.Table("rule").Select("user_id").Where("id = ?", ruleId).Scan(&ownerID).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if fmt.Sprintf("%d", ownerID) == userId {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cannot remove owner"})
		return
	}

	if err := s.App.MasterDB.GormDataSource.Where("rule_id = ? AND user_id = ?", ruleId, userId).Delete(&model.UserRuleMap{}).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

/* ========== 用户主：列表（含 bind_count / bind_peek） ========== */
// GET /api/user-binding?q=&page=&size=
func (s *Server) listUserBinding(c *gin.Context) {
	_, isAdmin := common.GetAuth(c)
	if !isAdmin {
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
		return
	}

	page, size := common.GetPage(c)
	offset := (page - 1) * size
	q := strings.TrimSpace(c.DefaultQuery("q", ""))

	db := s.App.MasterDB.GormDataSource

	base := db.Table("user u").Select("u.id, u.username")
	if q != "" {
		base = base.Where("u.username LIKE ?", "%"+q+"%")
	}

	var total int64
	if err := base.Count(&total).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	var rows []struct {
		ID       int64
		Username string
	}
	if err := base.Order("u.id").Limit(size).Offset(offset).Scan(&rows).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if len(rows) == 0 {
		c.JSON(http.StatusOK, gin.H{"list": []any{}, "total": total, "page": page, "size": size})
		return
	}

	ids := make([]int64, 0, len(rows))
	for _, r := range rows {
		ids = append(ids, r.ID)
	}

	// count
	type cntRow struct {
		UserId int64
		Cnt    int64
	}
	var cnts []cntRow
	_ = db.Table("user_rule_map m").
		Select("m.user_id AS user_id, COUNT(1) AS cnt").
		Where("m.user_id IN ?", ids).
		Group("m.user_id").Scan(&cnts)
	cmap := map[int64]int64{}
	for _, x := range cnts {
		cmap[x.UserId] = x.Cnt
	}

	// peek（前三条）
	type peekRow struct {
		UserId  int64
		Proto   string
		Address string
		Port    int
		Taddr   string
		Tport   int
	}
	var ps []peekRow
	_ = db.Table("user_rule_map m").
		Select("m.user_id, r.protocol, r.address, r.port, r.target_address, r.target_port").
		Joins("JOIN rule r ON r.id = m.rule_id").
		Where("m.user_id IN ?", ids).
		Order("m.user_id ASC, r.id ASC").Scan(&ps)

	peekMap := map[int64][]string{}
	for _, p := range ps {
		if len(peekMap[p.UserId]) < 3 {
			peekMap[p.UserId] = append(peekMap[p.UserId], fmt.Sprintf("%s %s:%d→%s:%d", p.Proto, p.Address, p.Port, p.Taddr, p.Tport))
		}
	}

	type item struct {
		ID       int64  `json:"id"`
		Username string `json:"username"`
		BindCnt  int64  `json:"bind_count"`
		BindPeek string `json:"bind_peek"`
	}
	out := make([]item, 0, len(rows))
	for _, r := range rows {
		out = append(out, item{
			ID:       r.ID,
			Username: r.Username,
			BindCnt:  cmap[r.ID],
			BindPeek: strings.Join(peekMap[r.ID], ","),
		})
	}

	c.JSON(http.StatusOK, gin.H{"list": out, "total": total, "page": page, "size": size})
}

/* ========== 用户主：查看某用户的已绑定规则 ========== */
// GET /api/user/:id/rule?page=&size=
func (s *Server) getUserRule(c *gin.Context) {
	_, isAdmin := common.GetAuth(c)
	if !isAdmin {
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
		return
	}
	uidPath := c.Param("id")

	page, size := common.GetPage(c)
	offset := (page - 1) * size

	db := s.App.MasterDB.GormDataSource

	var total int64
	if err := db.Table("user_rule_map").Where("user_id = ?", uidPath).Count(&total).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	var rows []struct {
		ID            int64
		Protocol      string
		Address       string
		Port          int
		TargetAddress string
		TargetPort    int
		Status        string
		OwnerID       int64  `gorm:"column:owner_id"`
		OwnerName     string `gorm:"column:owner_name"`
	}
	if err := db.Table("user_rule_map m").
		Joins("JOIN rule r ON r.id = m.rule_id").
		Joins("LEFT JOIN user u ON u.id = r.user_id").
		Select("r.id, r.protocol, r.address, r.port, r.target_address, r.target_port, r.status, r.user_id AS owner_id, u.username AS owner_name").
		Where("m.user_id = ?", uidPath).
		Order("r.id DESC").Limit(size).Offset(offset).Scan(&rows).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	type item struct {
		ID         int64  `json:"id"`
		Protocol   string `json:"protocol"`
		ListenAddr string `json:"listen_addr"`
		ListenPort int    `json:"listen_port"`
		TargetAddr string `json:"target_addr"`
		TargetPort int    `json:"target_port"`
		Status     string `json:"status"`
		OwnerID    int64  `json:"owner_id"`
		Owner      string `json:"owner"`
	}
	out := make([]item, 0, len(rows))
	for _, r := range rows {
		out = append(out, item{
			ID:         r.ID,
			Protocol:   r.Protocol,
			ListenAddr: r.Address,
			ListenPort: r.Port,
			TargetAddr: r.TargetAddress,
			TargetPort: r.TargetPort,
			Status:     r.Status,
			OwnerID:    r.OwnerID,
			Owner:      r.OwnerName,
		})
	}
	c.JSON(http.StatusOK, gin.H{"list": out, "total": total, "page": page, "size": size})
}

/* ========== 用户主：候选规则搜索（独立字段） ========== */
// GET /api/rule/search?protocol=&listen_addr=&listen_port=&target_addr=&target_port=&page=&size=
func (s *Server) searchRule(c *gin.Context) {
	_, isAdmin := common.GetAuth(c)
	if !isAdmin {
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
		return
	}

	page, size := common.GetPage(c)
	offset := (page - 1) * size

	protocol := strings.TrimSpace(c.Query("protocol"))
	laddr := strings.TrimSpace(c.Query("listen_addr"))
	lport, _ := strconv.Atoi(strings.TrimSpace(c.Query("listen_port")))
	taddr := strings.TrimSpace(c.Query("target_addr"))
	tport, _ := strconv.Atoi(strings.TrimSpace(c.Query("target_port")))

	db := s.App.MasterDB.GormDataSource

	base := db.Table("rule r").
		Select(`r.id, r.protocol, r.address, r.port, r.target_address, r.target_port, r.status, r.user_id AS owner_id, u.username AS owner_name`).
		Joins("LEFT JOIN user u ON u.id = r.user_id").Where("u.vm_id = 0")

	if protocol != "" {
		base = base.Where("LOWER(r.protocol) = ?", strings.ToLower(protocol))
	}
	if laddr != "" {
		base = base.Where("r.address LIKE ?", "%"+laddr+"%")
	}
	if lport > 0 {
		base = base.Where("r.port = ?", lport)
	}
	if taddr != "" {
		base = base.Where("r.target_address LIKE ?", "%"+taddr+"%")
	}
	if tport > 0 {
		base = base.Where("r.target_port = ?", tport)
	}

	var total int64
	if err := base.Count(&total).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	var rows []struct {
		ID            int64
		Protocol      string
		Address       string
		Port          int
		TargetAddress string
		TargetPort    int
		Status        string
		OwnerID       int64
		OwnerName     string
	}
	if err := base.Order("r.id DESC").Limit(size).Offset(offset).Scan(&rows).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	type item struct {
		ID         int64  `json:"id"`
		Protocol   string `json:"protocol"`
		ListenAddr string `json:"listen_addr"`
		ListenPort int    `json:"listen_port"`
		TargetAddr string `json:"target_addr"`
		TargetPort int    `json:"target_port"`
		Status     string `json:"status"`
		OwnerID    int64  `json:"owner_id"`
		Owner      string `json:"owner"`
	}
	out := make([]item, 0, len(rows))
	for _, r := range rows {
		out = append(out, item{
			ID:         r.ID,
			Protocol:   r.Protocol,
			ListenAddr: r.Address,
			ListenPort: r.Port,
			TargetAddr: r.TargetAddress,
			TargetPort: r.TargetPort,
			Status:     r.Status,
			OwnerID:    r.OwnerID,
			Owner:      r.OwnerName,
		})
	}

	c.JSON(http.StatusOK, gin.H{"list": out, "total": total, "page": page, "size": size})
}

/* ========== 用户主：覆盖/增/删绑定 ========== */

// PUT /api/user/:id/rule   body: { "rule_ids": [1,2,3] }
func (s *Server) replaceUserRule(c *gin.Context) {
	_, isAdmin := common.GetAuth(c)
	if !isAdmin {
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
		return
	}
	userId := c.Param("id")

	var req struct {
		RuleIds []int64 `json:"rule_ids"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		return
	}

	// 去重
	seen := map[int64]struct{}{}
	final := make([]int64, 0, len(req.RuleIds))
	for _, id := range req.RuleIds {
		if id <= 0 {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		final = append(final, id)
	}

	db := s.App.MasterDB.GormDataSource

	// 该用户作为 OWNER 的所有规则（⚠️ 全量取，不仅限于 final）
	var ownerOwned []int64
	_ = db.Table("rule").
		Where("user_id = ?", toInt64(userId)).
		Pluck("id", &ownerOwned)

	ownedSet := map[int64]struct{}{}
	for _, id := range ownerOwned {
		ownedSet[id] = struct{}{}
	}

	// 只保留“非 owner”的候选
	filtered := make([]int64, 0, len(final))
	for _, id := range final {
		if _, owned := ownedSet[id]; !owned {
			filtered = append(filtered, id)
		}
	}

	err := db.Transaction(func(tx *gorm.DB) error {
		// 只删除该用户的“非 owner 规则”的映射，保留他作为 owner 的映射
		delQ := tx.Where("user_id = ?", userId)
		if len(ownerOwned) > 0 {
			delQ = delQ.Where("rule_id NOT IN ?", ownerOwned)
		}
		if err := delQ.Delete(&model.UserRuleMap{}).Error; err != nil {
			return err
		}

		// 创建“非 owner”的新映射
		if len(filtered) > 0 {
			recs := make([]model.UserRuleMap, 0, len(filtered))
			uid := toInt64(userId)
			for _, rid := range filtered {
				recs = append(recs, model.UserRuleMap{UserId: uid, RuleId: rid})
			}
			if err := tx.Create(&recs).Error; err != nil {
				return err
			}
		}

		// 为“该用户拥有的规则”确保 owner 映射存在（防御性）
		uid := toInt64(userId)
		for _, rid := range ownerOwned {
			if err := ensureOwnerMapping(tx, rid, uid); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// POST /api/user/:id/rule   body: { "rule_id": 123 }
func (s *Server) addUserRule(c *gin.Context) {
	_, isAdmin := common.GetAuth(c)
	if !isAdmin {
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
		return
	}
	userId := c.Param("id")

	var req struct {
		RuleId int64 `json:"rule_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.RuleId <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		return
	}

	// 是 owner 就确保映射存在并返回
	var ownerID int64
	_ = s.App.MasterDB.GormDataSource.Table("rule").Select("user_id").Where("id = ?", req.RuleId).Scan(&ownerID)
	if ownerID == toInt64(userId) {
		if err := ensureOwnerMapping(s.App.MasterDB.GormDataSource, req.RuleId, ownerID); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true})
		return
	}

	var cnt int64
	_ = s.App.MasterDB.GormDataSource.Table("user_rule_map").
		Where("user_id = ? AND rule_id = ?", userId, req.RuleId).
		Count(&cnt)
	if cnt > 0 {
		c.JSON(http.StatusOK, gin.H{"ok": true})
		return
	}

	rec := model.UserRuleMap{UserId: toInt64(userId), RuleId: req.RuleId}
	if err := s.App.MasterDB.GormDataSource.Create(&rec).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// DELETE /api/user/:id/rule/:rule_id
func (s *Server) deleteUserRule(c *gin.Context) {
	_, isAdmin := common.GetAuth(c)
	if !isAdmin {
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
		return
	}
	userId := c.Param("id")
	ruleId := c.Param("rule_id")

	// 拦截删除 owner 自己的映射
	var ownerID int64
	if err := s.App.MasterDB.GormDataSource.Table("rule").Select("user_id").Where("id = ?", ruleId).Scan(&ownerID).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if ownerID == toInt64(userId) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cannot remove owner mapping"})
		return
	}

	if err := s.App.MasterDB.GormDataSource.Where("user_id = ? AND rule_id = ?", userId, ruleId).Delete(&model.UserRuleMap{}).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}
