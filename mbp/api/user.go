package api

import (
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"log"
	"mlkmbp/mbp/common"
	"mlkmbp/mbp/common/ttime"
	"mlkmbp/mbp/model"
	"net/http"
	"strconv"
	"strings"
	"time"
)

/* ---------- DTO ---------- */
type userDTO struct {
	Id              int64             `json:"id"`
	VmId            int64             `json:"vm_id"`
	Username        string            `json:"username"`
	Password        string            `json:"password"`
	PasswordSha256  string            `json:"password_sha256"`
	Quota           int64             `json:"quota"`
	Used            int64             `json:"used"`
	Up              int64             `json:"up"`
	Down            int64             `json:"down"`
	UpLimit         int64             `json:"up_limit"`
	DownLimit       int64             `json:"down_limit"`
	Status          string            `json:"status"`
	StartDateTime   *ttime.TimeFormat `json:"start_date_time"`
	ExpiredDateTime *ttime.TimeFormat `json:"expired_date_time"`
	PeriodUnit      model.PeriodUnit  `json:"period_unit"`
	PeriodLeft      int64             `json:"period_left"`
	CreateDateTime  *ttime.TimeFormat `json:"create_date_time"`
	UpdateDateTime  *ttime.TimeFormat `json:"update_date_time"`
}

func toDTO(u model.User) userDTO {
	return userDTO{
		Id:              u.Id,
		VmId:            u.VmId,
		Username:        u.Username,
		Password:        u.Password,
		PasswordSha256:  u.PasswordSha256,
		Quota:           u.Quota,
		Used:            u.Up + u.Down,
		Up:              u.Up,
		Down:            u.Down,
		UpLimit:         u.UpLimit,
		DownLimit:       u.DownLimit,
		Status:          u.Status,
		StartDateTime:   u.StartDateTime,
		ExpiredDateTime: u.ExpiredDateTime,
		PeriodUnit:      u.PeriodUnit,
		PeriodLeft:      u.PeriodLeft,
		CreateDateTime:  u.CreateDateTime,
		UpdateDateTime:  u.UpdateDateTime,
	}
}

/* ---------- 接口 ---------- */

// GET /user
func (s *Server) listUser(c *gin.Context) {
	// ====== 读取分页 ======
	page, size := common.GetPage(c)
	offset := (page - 1) * size

	// ====== 权限：非管理员只能看自己 ======
	uid, isAdmin := common.GetAuth(c)

	// ====== 读取简单筛选 ======
	username := strings.TrimSpace(c.Query("username"))
	status := strings.ToLower(strings.TrimSpace(c.Query("status")))          // enabled/disabled
	periodUnit := strings.ToLower(strings.TrimSpace(c.Query("period_unit"))) // day/month/""
	vmIDStr := strings.TrimSpace(c.Query("vm_id"))

	// ====== 读取“可比较”筛选（quota/start/expired/left）======
	type numCmp struct {
		op  string
		val int64
	}
	type timeCmp struct {
		op  string
		val time.Time
	}

	parseOp := func(op string) (string, error) {
		op = strings.ToLower(strings.TrimSpace(op))
		switch op {
		case "", "eq", "gt", "lt", "ge", "le":
			return op, nil
		default:
			return "", fmt.Errorf("op must be one of eq/gt/lt/ge/le")
		}
	}
	parseIntCmp := func(valStr, opStr string) (*numCmp, error) {
		op, err := parseOp(opStr)
		if err != nil {
			return nil, err
		}
		if op == "" || valStr == "" {
			return nil, nil
		}
		v, err := strconv.ParseInt(strings.TrimSpace(valStr), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("value must be int64")
		}
		return &numCmp{op: op, val: v}, nil
	}
	parseTimeCmp := func(valStr, opStr string) (*timeCmp, error) {
		op, err := parseOp(opStr)
		if err != nil {
			return nil, err
		}
		if op == "" || strings.TrimSpace(valStr) == "" {
			return nil, nil
		}
		sv := strings.TrimSpace(valStr)
		var t time.Time
		// 支持 YYYY-MM-DD 或 YYYY-MM-DD HH:mm:ss（按本地时区）
		if len(sv) == len(ttime.FORMAT_DATE) && strings.Count(sv, ":") == 0 {
			t, err = time.ParseInLocation(ttime.FORMAT_DATE, sv, time.Local)
		} else {
			t, err = time.ParseInLocation(ttime.FORMAT_DATE_TIME, sv, time.Local)
		}
		if err != nil {
			return nil, fmt.Errorf("invalid time format")
		}
		return &timeCmp{op: op, val: t}, nil
	}

	quotaCmp, err := parseIntCmp(c.Query("quota"), c.Query("quota_op"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "quota_" + err.Error()})
		return
	}
	leftCmp, err := parseIntCmp(c.Query("left"), c.Query("left_op"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "left_" + err.Error()})
		return
	}
	startCmp, err := parseTimeCmp(c.Query("start"), c.Query("start_op"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "start_" + err.Error()})
		return
	}
	expCmp, err := parseTimeCmp(c.Query("expired"), c.Query("expired_op"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "expired_" + err.Error()})
		return
	}

	// ====== 构建查询 ======
	dbq := s.App.MasterDB.GormDataSource.Model(&model.User{})

	// 权限
	if !isAdmin {
		dbq = dbq.Where("id = ?", uid)
	}

	// 基本筛选
	if username != "" {
		dbq = dbq.Where("username LIKE ?", "%"+username+"%")
	}
	if status != "" {
		if status != "enabled" && status != "disabled" && status != "expired" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "status must be enabled/disabled/expired"})
			return
		}
		dbq = dbq.Where("status = ?", status)
	}
	if periodUnit != "" {
		if periodUnit != "day" && periodUnit != "month" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "period_unit must be day/month"})
			return
		}
		dbq = dbq.Where("period_unit = ?", periodUnit)
	}
	if vmIDStr != "" {
		if vmid, e := strconv.ParseInt(vmIDStr, 10, 64); e == nil {
			dbq = dbq.Where("vm_id = ?", vmid)
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"error": "vm_id must be int64"})
			return
		}
	}

	// 比较应用（time 列统一按本地时区字符串比较：YYYY-MM-DD HH:mm:ss）
	applyNum := func(col string, cmp *numCmp) {
		if cmp == nil {
			return
		}
		switch cmp.op {
		case "eq":
			dbq = dbq.Where(col+" = ?", cmp.val)
		case "gt":
			dbq = dbq.Where(col+" > ?", cmp.val)
		case "lt":
			dbq = dbq.Where(col+" < ?", cmp.val)
		case "ge":
			dbq = dbq.Where(col+" >= ?", cmp.val)
		case "le":
			dbq = dbq.Where(col+" <= ?", cmp.val)
		}
	}
	applyTime := func(col string, cmp *timeCmp) {
		if cmp == nil {
			return
		}
		v := cmp.val.In(time.Local).Format(ttime.FORMAT_DATE_TIME)
		switch cmp.op {
		case "eq":
			dbq = dbq.Where(col+" = ?", v)
		case "gt":
			dbq = dbq.Where(col+" > ?", v)
		case "lt":
			dbq = dbq.Where(col+" < ?", v)
		case "ge":
			dbq = dbq.Where(col+" >= ?", v)
		case "le":
			dbq = dbq.Where(col+" <= ?", v)
		}
	}
	applyNum("quota", quotaCmp)
	applyNum("period_left", leftCmp)
	applyTime("start_date_time", startCmp)
	applyTime("expired_date_time", expCmp)

	// ====== 排序 ======
	sort := strings.ToLower(strings.TrimSpace(c.Query("sort")))
	orderExpr := "id DESC"
	switch sort {
	case "id_asc":
		orderExpr = "id ASC"
	case "used_desc":
		orderExpr = "up + down DESC"
	case "used_asc":
		orderExpr = "up + down ASC"
	case "update_desc":
		orderExpr = "update_date_time DESC"
	case "update_asc":
		orderExpr = "update_date_time ASC"
	case "start_asc":
		orderExpr = "start_date_time ASC"
	case "start_desc":
		orderExpr = "start_date_time DESC"
	case "expired_asc":
		orderExpr = "expired_date_time ASC"
	case "expired_desc":
		orderExpr = "expired_date_time DESC"
	case "quota_asc":
		orderExpr = "quota ASC"
	case "quota_desc":
		orderExpr = "quota DESC"
	default:
		orderExpr = "id DESC"
	}

	// ====== 统计 & 查询 ======
	var total int64
	if err := dbq.Count(&total).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	var rows []model.User
	if err := dbq.
		Order(orderExpr).
		Limit(size).
		Offset(offset).
		Find(&rows).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// ====== 输出 DTO ======
	out := make([]userDTO, 0, len(rows))
	for _, u := range rows {
		out = append(out, toDTO(u))
	}
	c.JSON(http.StatusOK, gin.H{
		"list":  out,
		"total": total,
		"page":  page,
		"size":  size,
	})
}

// GET /user/simple
// 管理员返回全部 id/username，普通用户只返回自身
func (s *Server) listUserSimple(c *gin.Context) {
	uid, isAdmin := common.GetAuth(c)

	type row struct {
		Id       int64  `json:"id"`
		Username string `json:"username"`
	}
	var list []row

	if isAdmin {
		var user []model.User
		if err := s.App.MasterDB.GormDataSource.Select("id, username").Order("id DESC").Find(&user).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		for _, u := range user {
			list = append(list, row{Id: u.Id, Username: u.Username})
		}
	} else {
		var u model.User
		if err := s.App.MasterDB.GormDataSource.Select("id, username").Where("id = ?", uid).Take(&u).Error; err == nil {
			list = append(list, row{Id: u.Id, Username: u.Username})
		}
	}
	c.JSON(http.StatusOK, gin.H{"list": list})
}

func (s *Server) createUser(c *gin.Context) {
	type payload struct {
		VmId            *int64            `json:"vm_id,omitempty"`
		Username        string            `json:"username"`
		Password        string            `json:"password"`
		Quota           int64             `json:"quota"`
		UpLimit         int64             `json:"up_limit"`
		DownLimit       int64             `json:"down_limit"`
		Status          string            `json:"status"`
		StartDateTime   *ttime.TimeFormat `json:"start_date_time,omitempty"`
		ExpiredDateTime *ttime.TimeFormat `json:"expired_date_time,omitempty"`
		PeriodUnit      *model.PeriodUnit `json:"period_unit,omitempty"`
		PeriodLeft      *int64            `json:"period_left,omitempty"`
	}
	var p payload
	if err := c.BindJSON(&p); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	p.Username = strings.TrimSpace(p.Username)

	// —— 基础校验（保持原样）——
	if p.Username == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "username required"})
		return
	}
	if p.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "password required"})
		return
	}
	if p.Quota < 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "quota must be >= 0"})
		return
	}
	if p.Status != "enabled" && p.Status != "disabled" && p.Status != "expired" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "status must be enabled/disabled/expired"})
		return
	}
	if p.PeriodUnit != nil {
		pu := strings.ToLower(string(*p.PeriodUnit))
		if pu != "day" && pu != "month" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "period_unit must be day/month"})
			return
		}
	}
	if p.PeriodLeft != nil && *p.PeriodLeft < -1 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "period_left must be -1 or >= 0"})
		return
	}

	err := s.App.MasterDB.GormDataSource.Transaction(func(tx *gorm.DB) error {
		// 用户名查重
		var cnt int64
		if err := tx.Model(&model.User{}).Where("username = ?", p.Username).Count(&cnt).Error; err != nil {
			return err
		}
		if cnt > 0 {
			return errors.New("bad_request:username already exists")
		}

		// vm_id 可用性 & 开关
		if p.VmId != nil && *p.VmId > 0 {
			if true {
				return errors.New("bad_request:enable pve disabled")
			}
			if err := assertVmIdUnique(tx, *p.VmId, nil); err != nil {
				return errors.New("bad_request:vm_id already exists")
			}
		}

		// —— 规则 A：vm_id > 0 必须给齐 start/expired，且 expired>=start —— //
		if p.VmId != nil && *p.VmId > 0 {
			if p.StartDateTime == nil || p.StartDateTime.Time.IsZero() ||
				p.ExpiredDateTime == nil || p.ExpiredDateTime.Time.IsZero() {
				return errors.New("bad_request:start_date_time and expired_date_time are required when vm_id > 0")
			}
			if p.ExpiredDateTime.Time.Before(p.StartDateTime.Time) {
				return errors.New("bad_request:expired_date_time must be >= start_date_time")
			}
		}

		// —— 规则 B：周期强约束（最终入库值必须满足）—— //
		finalUnit := getOrDefaultUnit(p.PeriodUnit, "")
		finalLeft := getOrDefaultInt64(p.PeriodLeft, 0)
		finalStart := p.StartDateTime
		finalExp := p.ExpiredDateTime

		// B1: unit 与 left 必须成对：unit!= "" <=> left>0
		if finalUnit != "" && finalLeft != -1 && finalLeft < 0 {
			return errors.New("bad_request:period_left must be > 0 when period_unit is set")
		}
		if (finalLeft == -1 || finalLeft > 0) && finalUnit == "" {
			return errors.New("bad_request:period_unit required when period_left > 0")
		}

		// B2: 当“周期生效”
		if finalUnit != "" && (finalLeft == -1 || finalLeft > 0) {
			if finalStart == nil || finalStart.Time.IsZero() || finalExp == nil || finalExp.Time.IsZero() {
				return errors.New("bad_request:start_date_time and expired_date_time are required when period is active")
			}
			if finalExp.Time.Before(finalStart.Time) {
				return errors.New("bad_request:expired_date_time must be >= start_date_time")
			}
		}

		u := model.User{
			VmId:            getOrDefaultInt64(p.VmId, 0),
			Username:        p.Username,
			Password:        p.Password,
			PasswordSha256:  common.HashUP(p.Password),
			Quota:           p.Quota,
			Up:              0,
			Down:            0,
			UpLimit:         p.UpLimit,
			DownLimit:       p.DownLimit,
			Status:          p.Status,
			StartDateTime:   finalStart, // 用最终规范化后的值
			ExpiredDateTime: finalExp,
			PeriodUnit:      finalUnit,
			PeriodLeft:      finalLeft,
		}
		if err := tx.Create(&u).Error; err != nil {
			return err
		}
		return nil
	})

	if err != nil {
		low := strings.ToLower(err.Error())
		if strings.HasPrefix(low, "bad_request:") {
			c.JSON(http.StatusBadRequest, gin.H{"error": strings.TrimPrefix(err.Error(), "bad_request:")})
			return
		}
		if strings.Contains(low, "unique") || strings.Contains(low, "duplicate") {
			c.JSON(http.StatusConflict, gin.H{"error": "username already exists"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func getOrDefaultInt64(p *int64, d int64) int64 {
	if p == nil {
		return d
	}
	return *p
}
func getOrDefaultUnit(p *model.PeriodUnit, d model.PeriodUnit) model.PeriodUnit {
	if p == nil {
		return d
	}
	return *p
}

// PUT /user/:id
type userUpdatePayload struct {
	VmId            *int64            `json:"vm_id,omitempty"`
	Username        *string           `json:"username,omitempty"`
	Password        *string           `json:"password,omitempty"`
	Quota           *int64            `json:"quota,omitempty"`
	UpLimit         *int64            `json:"up_limit,omitempty"`
	DownLimit       *int64            `json:"down_limit,omitempty"`
	Status          *string           `json:"status,omitempty"`
	StartDateTime   *ttime.TimeFormat `json:"start_date_time,omitempty"`
	ExpiredDateTime *ttime.TimeFormat `json:"expired_date_time,omitempty"`
	PeriodUnit      *model.PeriodUnit `json:"period_unit,omitempty"`
	PeriodLeft      *int64            `json:"period_left,omitempty"`
}

func (s *Server) updateUser(c *gin.Context) {
	var p userUpdatePayload
	if err := c.BindJSON(&p); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	id := c.Param("id")

	// —— 轻量校验（保持原样）——
	if p.Quota != nil && *p.Quota < 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "quota must be >= 0"})
		return
	}
	if p.Status != nil {
		vs := strings.ToLower(*p.Status)
		if vs != "enabled" && vs != "disabled" && vs != "expired" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "status must be enabled/disabled/expired"})
			return
		}
	}
	if p.PeriodUnit != nil {
		pu := strings.ToLower(string(*p.PeriodUnit))
		if pu != "day" && pu != "month" && pu != "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "period_unit must be day/month"})
			return
		}
	}
	if p.PeriodLeft != nil && *p.PeriodLeft < -1 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "period_left must be -1 or >= 0"})
		return
	}

	err := s.App.MasterDB.GormDataSource.Transaction(func(tx *gorm.DB) error {
		// 读当前
		var cur model.User
		if err := tx.Where("id = ?", id).Take(&cur).Error; err != nil {
			return errors.New("bad_request:user not found")
		}

		updates := map[string]any{}

		// 非时间字段（保持原逻辑）
		if p.VmId != nil {
			if true {
				return errors.New("bad_request:enable pve disabled")
			}
			var uid int64
			if v, err := strconv.ParseInt(id, 10, 64); err == nil {
				uid = v
			}
			if err := assertVmIdUnique(tx, *p.VmId, &uid); err != nil {
				return errors.New("bad_request:vm_id already exists")
			}
			updates["vm_id"] = *p.VmId
		}
		if p.Username != nil {
			var cnt int64
			if err := tx.Model(&model.User{}).Where("username = ?", *p.Username).Count(&cnt).Error; err != nil {
				return err
			}
			if cnt > 0 {
				return errors.New("bad_request:username already exists")
			}
			updates["username"] = *p.Username
		}
		if p.Quota != nil {
			updates["quota"] = *p.Quota
		}
		if p.UpLimit != nil {
			updates["up_limit"] = *p.UpLimit
		}
		if p.DownLimit != nil {
			updates["down_limit"] = *p.DownLimit
		}
		if p.Status != nil {
			updates["status"] = strings.ToLower(*p.Status)
		}
		if p.Password != nil {
			updates["password"] = *p.Password
			updates["password_sha256"] = common.HashUP(*p.Password)
		}

		// 计算最终 vm_id
		finalVmID := cur.VmId
		if p.VmId != nil {
			finalVmID = *p.VmId
		}

		// 拟更新的新时间（可能清空）
		newStart := p.StartDateTime
		newExp := p.ExpiredDateTime

		// 先得到“生效后的最终值”（用于所有后续约束）
		finalStart := cur.StartDateTime
		if newStart != nil {
			if newStart.Time.IsZero() {
				finalStart = &ttime.TimeFormat{} // 将被写成 NULL
			} else {
				if newStart.Format == "" {
					newStart.Format = ttime.FORMAT_DATE_TIME
				}
				finalStart = newStart
			}
		}
		finalExp := cur.ExpiredDateTime
		if newExp != nil {
			if newExp.Time.IsZero() {
				finalExp = &ttime.TimeFormat{}
			} else {
				if newExp.Format == "" {
					newExp.Format = ttime.FORMAT_DATE_TIME
				}
				finalExp = newExp
			}
		}

		// 规则 A：vm_id>0 时，最终 start/expired 必须存在且 expired>=start，禁止被清空
		if finalVmID > 0 {
			if finalStart == nil || finalStart.Time.IsZero() ||
				finalExp == nil || finalExp.Time.IsZero() {
				return errors.New("bad_request:start_date_time and expired_date_time are required when vm_id > 0")
			}
			if finalExp.Time.Before(finalStart.Time) {
				return errors.New("bad_request:expired_date_time must be >= start_date_time")
			}
		}

		// 周期字段（先计算最终值，再统一校验）
		finalUnit := cur.PeriodUnit
		if p.PeriodUnit != nil {
			finalUnit = *p.PeriodUnit
		}
		finalLeft := cur.PeriodLeft
		if p.PeriodLeft != nil {
			finalLeft = *p.PeriodLeft
		}

		// B1: unit 与 left 必须成对：unit!= "" <=> left>0
		if finalUnit != "" && finalLeft != -1 && finalLeft < 0 {
			return errors.New("bad_request:period_left must be > 0 when period_unit is set")
		}
		if (finalLeft == -1 || finalLeft > 0) && finalUnit == "" {
			return errors.New("bad_request:period_unit required when period_left > 0")
		}

		// B2: 当“周期生效”
		if finalUnit != "" && (finalLeft == -1 || finalLeft > 0) {
			if finalStart == nil || finalStart.Time.IsZero() || finalExp == nil || finalExp.Time.IsZero() {
				return errors.New("bad_request:start_date_time and expired_date_time are required when period is active")
			}
			if finalExp.Time.Before(finalStart.Time) {
				return errors.New("bad_request:expired_date_time must be >= start_date_time")
			}
		}

		// 把需要变更的字段装入 updates（时间字段只在传入时写入）
		if p.StartDateTime != nil {
			if p.StartDateTime.Time.IsZero() {
				updates["start_date_time"] = &ttime.TimeFormat{}
			} else {
				updates["start_date_time"] = p.StartDateTime
			}
		}
		if p.ExpiredDateTime != nil {
			if p.ExpiredDateTime.Time.IsZero() {
				updates["expired_date_time"] = &ttime.TimeFormat{}
			} else {
				updates["expired_date_time"] = p.ExpiredDateTime
			}
		}
		if p.PeriodUnit != nil {
			updates["period_unit"] = finalUnit
		}
		if p.PeriodLeft != nil {
			updates["period_left"] = finalLeft
		}

		if len(updates) == 0 {
			return nil
		}
		if err := tx.Model(&model.User{}).Where("id = ?", id).Updates(updates).Error; err != nil {
			return err
		}
		return nil
	})

	if err != nil {
		low := strings.ToLower(err.Error())
		if strings.HasPrefix(low, "bad_request:") {
			c.JSON(http.StatusBadRequest, gin.H{"error": strings.TrimPrefix(err.Error(), "bad_request:")})
			return
		}
		if strings.Contains(low, "unique") || strings.Contains(low, "duplicate") {
			c.JSON(http.StatusConflict, gin.H{"error": "username already exists"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// 校验 vm_id 在 user 表中唯一（忽略 id=excludeID；允许 vmID<=0）
func assertVmIdUnique(db *gorm.DB, vmID int64, excludeID *int64) error {
	if vmID <= 0 {
		return nil // 未绑定，不校验
	}
	q := db.Model(&model.User{}).Where("vm_id = ?", vmID)
	if excludeID != nil {
		q = q.Where("id <> ?", excludeID)
	}
	var cnt int64
	if err := q.Count(&cnt).Error; err != nil {
		return err
	}
	if cnt > 0 {
		return errors.New("vm_id already bound")
	}
	return nil
}

// DELETE /user/:id
func (s *Server) deleteUser(c *gin.Context) {
	id := c.Param("id")

	uid, err2 := strconv.ParseInt(id, 10, 64)
	if err2 != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err2.Error()})
		return
	}
	admin := common.IsAdminID(s.App.Cfg.Admin.AdminIDs, uid)
	if admin {
		c.JSON(http.StatusBadRequest, gin.H{"error": "you can't delete yourself"})
		return
	}
	_, isAdmin := common.GetAuth(c)
	if !isAdmin {
		c.JSON(http.StatusForbidden, gin.H{"error": "you can't delete yourself"})
		return
	}

	// 留存被删用户信息用于 PVE 清理
	var doomed model.User
	_ = s.App.MasterDB.GormDataSource.Where("id = ?", id).Take(&doomed).Error

	err := s.App.MasterDB.GormDataSource.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("user_id = ?", id).Delete(&model.PolicyMatcher{}).Error; err != nil {
			log.Printf("failed to delete user_id %s policy_matcher: %v", id, err)
		}
		if err := tx.Where("user_id = ?", id).Delete(&model.PolicyForward{}).Error; err != nil {
			log.Printf("failed to delete user_id %s policy_forward: %v", id, err)
		}
		if err := tx.Where("user_id = ?", id).Delete(&model.UserRuleMap{}).Error; err != nil {
			log.Printf("failed to delete user_id %s user_rule_map: %v", id, err)
		}
		if err := tx.Where("user_id = ?", id).Delete(&model.Rule{}).Error; err != nil {
			log.Printf("failed to delete user_id %s rule: %v", id, err)
		}
		if err := tx.Where("id = ?", id).Delete(&model.User{}).Error; err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}
