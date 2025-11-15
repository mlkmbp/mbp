package api

import (
	"errors"
	"gorm.io/gorm/clause"
	"mlkmbp/mbp/common"
	"mlkmbp/mbp/model"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

/******** DTO（不再包含 rule_*） ********/

type policyForwardDTO struct {
	Id            int64  `json:"id"`
	UserId        int64  `json:"user_id"`
	TagName       string `json:"tag_name"`
	Protocol      string `json:"protocol"`
	TargetAddress string `json:"target_address"`
	TargetPort    int    `json:"target_port"`

	AuthUsername   string `json:"auth_username"`
	AuthPassword   string `json:"auth_password"`
	SkipCertVerify bool   `json:"skip_cert_verify"`
	ALPN           string `json:"alpn"`
	TLSFingerprint string `json:"tls_fingerprint"`
	TLSSNIGuard    string `json:"tls_sni_guard"`
	Status         string `json:"status"`
}

/******** helpers ********/

func pfNorm(s string) string { return strings.ToLower(strings.TrimSpace(s)) }
func pfValidStatus(s string) bool {
	switch pfNorm(s) {
	case model.StatusEnabled, model.StatusDisabled:
		return true
	default:
		return false
	}
}

// 仅校验 user 是否存在
func ensureUserExistsPF(db *gorm.DB, uid int64) error {
	var cnt int64
	if err := db.Table("user").Where("id = ?", uid).Count(&cnt).Error; err != nil {
		return err
	}
	if cnt == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

/******** Handlers ********/

// GET /api/policy/forward?page=&size=&user_id=&tag_name=&status=&protocol=&target_address=
func (s *Server) listPolicyForward(c *gin.Context) {
	page, size := common.GetPage(c)
	offset := (page - 1) * size

	uidStr := strings.TrimSpace(c.Query("user_id"))
	tagName := strings.TrimSpace(c.Query("tag_name"))
	status := pfNorm(c.Query("status"))
	proto := pfNorm(c.Query("protocol"))
	taddr := strings.TrimSpace(c.Query("target_address"))

	base := s.App.MasterDB.GormDataSource.Table("policy_forward AS f")

	// 权限：非 admin 只能看自己的；admin 可以按 user_id 过滤
	uid, isAdmin := common.GetAuth(c)
	if !isAdmin {
		base = base.Where("f.user_id = ?", uid)
	} else if uidStr != "" {
		if v, err := strconv.ParseInt(uidStr, 10, 64); err == nil && v > 0 {
			base = base.Where("f.user_id = ?", v)
		}
	}

	if tagName != "" {
		base = base.Where("f.tag_name LIKE ?", "%"+tagName+"%")
	}
	if status != "" {
		base = base.Where("f.status = ?", status)
	}
	if proto != "" {
		base = base.Where("LOWER(f.protocol) = ?", proto)
	}
	if taddr != "" {
		base = base.Where("f.target_address LIKE ?", "%"+taddr+"%")
	}

	var total int64
	if err := base.Distinct("f.id").Count(&total).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	var rows []policyForwardDTO
	if err := base.
		Select(`
			f.id,
			f.user_id,
			f.tag_name,
			f.protocol,
			f.target_address,
			f.target_port,
			f.auth_username,
			f.auth_password,
			f.skip_cert_verify,
			f.alpn,
			f.tls_fingerprint,
			f.tls_sni_guard,
			f.status`).
		Order("f.id DESC").
		Limit(size).Offset(offset).
		Scan(&rows).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"list": rows, "total": total, "page": page, "size": size,
	})
}

// POST /api/policy/forward
// 非管理员：强制 user_id=自己；管理员可指定 user_id
func (s *Server) createPolicyForward(c *gin.Context) {
	type payload struct {
		UserId         *int64 `json:"user_id"` // 管理员可指定；非管理员忽略
		TagName        string `json:"tag_name"       binding:"required"`
		Protocol       string `json:"protocol"       binding:"required"`
		TargetAddress  string `json:"target_address" binding:"required"`
		TargetPort     int    `json:"target_port"    binding:"required"`
		AuthUsername   string `json:"auth_username"`
		AuthPassword   string `json:"auth_password"`
		SkipCertVerify *bool  `json:"skip_cert_verify"`
		ALPN           string `json:"alpn"`
		TLSFingerprint string `json:"tls_fingerprint"`
		TLSSNIGuard    string `json:"tls_sni_guard"`
		Status         string `json:"status"`
	}
	var in payload
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	in.TagName = strings.TrimSpace(in.TagName)
	in.Protocol = strings.TrimSpace(in.Protocol)
	in.TargetAddress = strings.TrimSpace(in.TargetAddress)
	in.Status = pfNorm(in.Status)

	// 必填项强约束
	if in.TagName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tag_name required"})
		return
	}
	if in.Protocol == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "protocol required"})
		return
	}
	if in.TargetAddress == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "target_address required"})
		return
	}
	if in.TargetPort < 1 || in.TargetPort > 65535 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "target_port must be 1~65535"})
		return
	}
	if in.Status == "" {
		in.Status = model.StatusEnabled
	}
	if !pfValidStatus(in.Status) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid status"})
		return
	}

	uid, isAdmin := common.GetAuth(c)
	owner := uid
	if isAdmin && in.UserId != nil && *in.UserId > 0 {
		owner = *in.UserId
	}

	// 仅普通用户受限；管理员不受限
	if !isAdmin {
		var cnt int64
		if err := s.App.MasterDB.GormDataSource.
			Model(&model.PolicyForward{}).
			Where("user_id = ?", owner).
			Count(&cnt).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if cnt >= 10000 {
			// 429 更符合“配额/限流已达上限”的语义
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "per-user limit reached (10000)"})
			return
		}
	}

	// 校验 user 存在
	if err := ensureUserExistsPF(s.App.MasterDB.GormDataSource, owner); err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusBadRequest, gin.H{"error": "user not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	skip := false
	if in.SkipCertVerify != nil {
		skip = *in.SkipCertVerify
	}

	rec := model.PolicyForward{
		UserId:         owner,
		TagName:        in.TagName,
		Protocol:       in.Protocol,
		TargetAddress:  in.TargetAddress,
		TargetPort:     in.TargetPort,
		AuthUsername:   in.AuthUsername, // 允许为空
		AuthPassword:   in.AuthPassword, // 允许为空
		SkipCertVerify: skip,
		ALPN:           in.ALPN,           // 允许为空
		TLSFingerprint: in.TLSFingerprint, // 允许为空
		TLSSNIGuard:    in.TLSSNIGuard,    // 允许为空
		Status:         in.Status,
	}

	if err := s.App.MasterDB.GormDataSource.Create(&rec).Error; err != nil {
		low := strings.ToLower(err.Error())
		if strings.Contains(low, "duplicate") || strings.Contains(low, "unique") {
			c.JSON(http.StatusConflict, gin.H{"error": "duplicate record"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"id": rec.Id})
}

// PUT /api/policy/forward/:id
// 非管理员只能改自己的；管理员可改 user_id
func (s *Server) updatePolicyForward(c *gin.Context) {
	idStr := c.Param("id")
	if idStr == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing id"})
		return
	}

	type payload struct {
		UserId         *int64  `json:"user_id"` // 仅管理员可改
		TagName        *string `json:"tag_name"`
		Protocol       *string `json:"protocol"`
		TargetAddress  *string `json:"target_address"`
		TargetPort     *int    `json:"target_port"`
		AuthUsername   *string `json:"auth_username"`
		AuthPassword   *string `json:"auth_password"`
		SkipCertVerify *bool   `json:"skip_cert_verify"`
		ALPN           *string `json:"alpn"`
		TLSFingerprint *string `json:"tls_fingerprint"`
		TLSSNIGuard    *string `json:"tls_sni_guard"`
		Status         *string `json:"status"`
	}
	var in payload
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 查归属
	var row struct{ UserId int64 }
	if err := s.App.MasterDB.GormDataSource.
		Table("policy_forward").Select("user_id").
		Where("id = ?", idStr).Take(&row).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	uid, isAdmin := common.GetAuth(c)
	if !isAdmin && row.UserId != uid {
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
		return
	}

	upd := map[string]any{}

	// 管理员可改归属
	if isAdmin && in.UserId != nil {
		if *in.UserId <= 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "user_id must be > 0"})
			return
		}
		if err := ensureUserExistsPF(s.App.MasterDB.GormDataSource, *in.UserId); err != nil {
			if err == gorm.ErrRecordNotFound {
				c.JSON(http.StatusBadRequest, gin.H{"error": "user not found"})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		upd["user_id"] = *in.UserId
	}

	// 必填型字段：如果传了，就必须非空/合法
	if in.TagName != nil {
		t := strings.TrimSpace(*in.TagName)
		if t == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "tag_name cannot be empty"})
			return
		}
		upd["tag_name"] = t
	}
	if in.Protocol != nil {
		p := strings.TrimSpace(*in.Protocol)
		if p == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "protocol cannot be empty"})
			return
		}
		upd["protocol"] = p
	}
	if in.TargetAddress != nil {
		a := strings.TrimSpace(*in.TargetAddress)
		if a == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "target_address cannot be empty"})
			return
		}
		upd["target_address"] = a
	}
	if in.TargetPort != nil {
		if *in.TargetPort < 1 || *in.TargetPort > 65535 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "target_port must be 1~65535"})
			return
		}
		upd["target_port"] = *in.TargetPort
	}

	// 可空字符串：允许置为 ""（只要传了指针，就按值更新）
	if in.AuthUsername != nil {
		upd["auth_username"] = *in.AuthUsername
	}
	if in.AuthPassword != nil {
		upd["auth_password"] = *in.AuthPassword
	}
	if in.ALPN != nil {
		upd["alpn"] = *in.ALPN
	}
	if in.TLSFingerprint != nil {
		upd["tls_fingerprint"] = *in.TLSFingerprint
	}
	if in.TLSSNIGuard != nil {
		upd["tls_sni_guard"] = *in.TLSSNIGuard
	}
	if in.SkipCertVerify != nil {
		upd["skip_cert_verify"] = *in.SkipCertVerify
	}

	// 状态：若传入必须合法
	if in.Status != nil {
		sv := pfNorm(*in.Status)
		if !pfValidStatus(sv) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid status"})
			return
		}
		upd["status"] = sv
	}

	if len(upd) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no fields to update"})
		return
	}

	if err := s.App.MasterDB.GormDataSource.
		Model(&model.PolicyForward{}).
		Where("id = ?", idStr).
		Updates(upd).Error; err != nil {
		low := strings.ToLower(err.Error())
		if strings.Contains(low, "duplicate") || strings.Contains(low, "unique") {
			c.JSON(http.StatusConflict, gin.H{"error": "duplicate record"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// DELETE /api/policy/forward/:id
func (s *Server) deletePolicyForward(c *gin.Context) {
	idStr := c.Param("id")
	rid, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}

	uid, isAdmin := common.GetAuth(c)

	// 自定义错误用于区分 403/404
	var (
		errForbidden = errors.New("forbidden")
		errNotFound  = errors.New("not found")
	)

	err = s.App.MasterDB.GormDataSource.WithContext(c.Request.Context()).Transaction(func(tx *gorm.DB) error {
		// 1) 读取并锁行，避免竞态
		var pf model.PolicyForward
		if err := tx.
			Clauses(clause.Locking{Strength: "UPDATE"}).
			Select("id", "user_id").
			Where("id = ?", rid).
			Take(&pf).Error; err != nil {

			if errors.Is(err, gorm.ErrRecordNotFound) {
				return errNotFound
			}
			return err
		}

		// 2) 鉴权（在事务里）
		if !isAdmin && pf.UserId != uid {
			return errForbidden
		}

		// 3) 先删引用
		if err := tx.Where("policy_forward_id = ?", rid).
			Delete(&model.PolicyMatcher{}).Error; err != nil {
			return err
		}

		// 4) 删自身（可选：非管理员再带 user_id 兜一层）
		q := tx.Where("id = ?", rid)
		if !isAdmin {
			q = q.Where("user_id = ?", uid)
		}
		res := q.Delete(&model.PolicyForward{})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			// 并发下被人先删/变更了
			return errNotFound
		}
		return nil
	})

	switch {
	case errors.Is(err, errForbidden):
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
	case errors.Is(err, errNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
	case err != nil:
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
	default:
		c.JSON(http.StatusOK, gin.H{"ok": true})
	}
}

// DELETE /api/policy_forward/batch
// Body: {"ids":[1,2,3]}
func (s *Server) deletePolicyForwardBatch(c *gin.Context) {
	type reqBody struct {
		IDs []int64 `json:"ids"`
	}
	var req reqBody
	if err := c.ShouldBindJSON(&req); err != nil || len(req.IDs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid ids"})
		return
	}

	// 去重
	uniq := make(map[int64]struct{}, len(req.IDs))
	var ids []int64
	for _, id := range req.IDs {
		if id <= 0 {
			continue
		}
		if _, ok := uniq[id]; !ok {
			uniq[id] = struct{}{}
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid ids"})
		return
	}

	uid, isAdmin := common.GetAuth(c)

	var (
		okIDs        = make([]int64, 0, len(ids))
		forbiddenIDs = make([]int64, 0)
		notFoundIDs  = make([]int64, 0)
		deletedCount int64
	)

	err := s.App.MasterDB.GormDataSource.WithContext(c.Request.Context()).Transaction(func(tx *gorm.DB) error {
		// 1) 锁定目标行（存在性 + 归属）
		type row struct {
			ID     int64 `gorm:"column:id"`
			UserId int64 `gorm:"column:user_id"`
		}
		var rows []row
		if err := tx.Table("policy_forward").
			Select("id", "user_id").
			Where("id IN ?", ids).
			Clauses(clause.Locking{Strength: "UPDATE"}).
			Find(&rows).Error; err != nil {
			return err
		}
		exist := make(map[int64]row, len(rows))
		for _, r := range rows {
			exist[r.ID] = r
		}

		// 2) 计算允许删除的 id 列表（非管理员只允许删自己的）
		toDelete := make([]int64, 0, len(rows))
		for _, id := range ids {
			r, ok := exist[id]
			if !ok {
				notFoundIDs = append(notFoundIDs, id)
				continue
			}
			if !isAdmin && r.UserId != uid {
				forbiddenIDs = append(forbiddenIDs, id)
				continue
			}
			toDelete = append(toDelete, id)
		}
		if len(toDelete) == 0 {
			// 没有可删的，事务直接结束（整体返回 200，结果里体现 forbidden/not_found）
			return nil
		}

		// 3) 先删映射（失败仅记录，不拦截）
		if err := tx.Where("policy_forward_id IN ?", toDelete).
			Delete(&model.PolicyMatcher{}).Error; err != nil {
			// 记录但不中断
			apiRuleLog.Warnf("batch delete policy_matcher for pf %v failed: %v", toDelete, err)
		}

		// 4) 删主表（必须成功；受权约束）
		q := tx.Model(&model.PolicyForward{}).Where("id IN ?", toDelete)
		if !isAdmin {
			q = q.Where("user_id = ?", uid)
		}
		res := q.Delete(&model.PolicyForward{})
		if res.Error != nil {
			return res.Error
		}
		deletedCount = res.RowsAffected

		// 5) 统计 ok/not_found（并发下可能被他处先删）
		if deletedCount > 0 {
			// 查剩余未删的（仍存在的就是并发下没删到）
			var still []int64
			if err := tx.Model(&model.PolicyForward{}).
				Where("id IN ?", toDelete).
				Pluck("id", &still).Error; err == nil && len(still) > 0 {
				stillSet := make(map[int64]struct{}, len(still))
				for _, id := range still {
					stillSet[id] = struct{}{}
				}
				for _, id := range toDelete {
					if _, ok := stillSet[id]; ok {
						// 并发导致未删成功，按 not_found 归类更贴近幂等删除语义
						notFoundIDs = append(notFoundIDs, id)
					} else {
						okIDs = append(okIDs, id)
					}
				}
			} else {
				// 查询失败或没有剩余，默认都成功
				okIDs = append(okIDs, toDelete...)
			}
		}
		return nil
	})

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"ok":            true,
		"deleted_count": deletedCount,
		"total":         len(ids),
		"ok_ids":        okIDs,
		"forbidden_ids": forbiddenIDs,
		"not_found_ids": notFoundIDs,
	})
}

// GET /api/policy/forward/tag?user_id=&status=&q=
func (s *Server) listPolicyForwardTag(c *gin.Context) {
	uid, isAdmin := common.GetAuth(c)

	userIDStr := strings.TrimSpace(c.Query("user_id"))
	status := strings.TrimSpace(c.Query("status"))
	if status == "" {
		status = "enabled"
	}
	q := strings.TrimSpace(c.Query("q")) // 模糊匹配 tag_name

	type row struct {
		Id      int64  `json:"id"`
		TagName string `json:"tag_name"`
	}

	db := s.App.MasterDB.GormDataSource.Table("policy_forward").Select("id, tag_name")

	// 权限限制：非管理员只能看自己的
	if !isAdmin {
		db = db.Where("user_id = ?", uid)
	} else if userIDStr != "" {
		if v, err := strconv.ParseInt(userIDStr, 10, 64); err == nil && v > 0 {
			db = db.Where("user_id = ?", v)
		}
	}

	if q != "" {
		db = db.Where("tag_name LIKE ?", "%"+q+"%")
	}

	var list []row
	if err := db.Order("tag_name ASC, id DESC").Scan(&list).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"list": list})
}
