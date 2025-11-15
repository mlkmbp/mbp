package api

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"golang.org/x/net/idna"
	"mlkmbp/mbp/common"
	"mlkmbp/mbp/model"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

/******** helpers: 校验与规范 ********/

func isValidKind(kind string) bool {
	switch strings.ToLower(kind) {
	case model.KindIp, model.KindCidr, model.KindDomainExact, model.KindDomainSuffix, "auto":
		return true
	default:
		return false
	}
}

func isValidAction(a string) bool {
	switch strings.ToLower(a) {
	case model.ActionDirect, model.ActionForward, model.ActionReject:
		return true
	default:
		return false
	}
}

func isValidStatus(s string) bool {
	switch strings.ToLower(s) {
	case model.StatusEnabled, model.StatusDisabled:
		return true
	default:
		return false
	}
}

func normalizeLower(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// 允许 Unicode 域名；转成 ASCII（Punycode），不保留尾点
func normalizeDomain(s string) (string, error) {
	s = strings.TrimSpace(strings.ToLower(strings.TrimSuffix(s, ".")))
	if s == "" {
		return "", nil
	}
	ascii, err := idna.ToASCII(s)
	if err != nil {
		return "", err
	}
	return ascii, nil
}

func reverseLabels(d string) string {
	if d == "" {
		return ""
	}
	ps := strings.Split(d, ".")
	for i, j := 0, len(ps)-1; i < j; i, j = i+1, j-1 {
		ps[i], ps[j] = ps[j], ps[i]
	}
	return strings.Join(ps, ".")
}

func ipTo16(ip net.IP) []byte {
	if ip == nil {
		return nil
	}
	if v4 := ip.To4(); v4 != nil {
		b := make([]byte, 16)
		copy(b[12:], v4)
		return b
	}
	v16 := ip.To16()
	if v16 == nil {
		return nil
	}
	b := make([]byte, 16)
	copy(b, v16)
	return b
}

func cidrToRange(cidr string) (from16, to16 []byte, _ error) {
	ip, ipNet, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil {
		return nil, nil, err
	}
	from := ip.Mask(ipNet.Mask)
	to := make(net.IP, len(from))
	copy(to, from)
	for i := 0; i < len(ipNet.Mask); i++ {
		to[i] = from[i] | ^ipNet.Mask[i]
	}
	return ipTo16(from), ipTo16(to), nil
}

// 基础正则（ASCII），真正校验走 normalizeDomain + 语义检查
var (
	reDomainASCII = regexp.MustCompile(`^(?i)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$`)
	reSuffixASCII = regexp.MustCompile(`^(?i)\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9-]{0,61}[a-z0-9])*$`)
)

// 语义校验（允许 Unicode，按 kind 处理）
func validateMatchValue(kind, val string) bool { // 这里的名字保持内部含义，外部只使用 raw_value
	val = strings.TrimSpace(val)
	if val == "" {
		return false
	}
	switch kind {
	case model.KindIp:
		return net.ParseIP(val) != nil
	case model.KindCidr:
		_, _, err := net.ParseCIDR(val)
		return err == nil
	case model.KindDomainExact:
		if strings.HasPrefix(val, ".") {
			return false
		}
		ascii, err := normalizeDomain(val)
		return err == nil && ascii != "" && reDomainASCII.MatchString(ascii)
	case model.KindDomainSuffix:
		if !strings.HasPrefix(val, ".") {
			return false
		}
		ascii, err := normalizeDomain(strings.TrimPrefix(val, "."))
		return err == nil && ascii != "" && reSuffixASCII.MatchString("."+ascii)
	default:
		return false
	}
}

// 固定类型下去掉可选前缀（允许写 ip:1.2.3.4 等）
func stripOptionalPrefixForKind(kind, s string) string {
	l := strings.ToLower(strings.TrimSpace(s))
	switch kind {
	case model.KindIp:
		if strings.HasPrefix(l, "ip:") {
			return strings.TrimSpace(s[3:])
		}
	case model.KindCidr:
		if strings.HasPrefix(l, "cidr:") {
			return strings.TrimSpace(s[5:])
		}
	case model.KindDomainExact:
		if strings.HasPrefix(l, "exact:") {
			return strings.TrimSpace(s[6:])
		}
	case model.KindDomainSuffix:
		if strings.HasPrefix(l, "suffix:") {
			return strings.TrimSpace(s[7:])
		}
	}
	return strings.TrimSpace(s)
}

// 自动识别一行（auto 模式）
func detectKindAndNormalize(line string) (kind string, value string, ok bool) {
	s := strings.TrimSpace(line)
	if s == "" {
		return "", "", false
	}
	l := strings.ToLower(s)
	// 显式前缀优先
	switch {
	case strings.HasPrefix(l, "ip:"):
		v := strings.TrimSpace(s[3:])
		if validateMatchValue(model.KindIp, v) {
			return model.KindIp, v, true
		}
		return "", "", false
	case strings.HasPrefix(l, "cidr:"):
		v := strings.TrimSpace(s[5:])
		if validateMatchValue(model.KindCidr, v) {
			return model.KindCidr, v, true
		}
		return "", "", false
	case strings.HasPrefix(l, "exact:"):
		v := strings.TrimSpace(s[6:])
		if validateMatchValue(model.KindDomainExact, v) {
			return model.KindDomainExact, v, true
		}
		return "", "", false
	case strings.HasPrefix(l, "suffix:"):
		v := strings.TrimSpace(s[7:])
		if validateMatchValue(model.KindDomainSuffix, v) {
			return model.KindDomainSuffix, v, true
		}
		return "", "", false
	}
	// 无前缀 → 按内容推断
	if net.ParseIP(s) != nil {
		return model.KindIp, s, true
	}
	if _, _, err := net.ParseCIDR(s); err == nil {
		return model.KindCidr, s, true
	}
	if strings.HasPrefix(s, ".") && validateMatchValue(model.KindDomainSuffix, s) {
		return model.KindDomainSuffix, s, true
	}
	if validateMatchValue(model.KindDomainExact, s) {
		return model.KindDomainExact, s, true
	}
	return "", "", false
}

/******** 结构化：把 kind+value → IpFrom/IpTo/Domain/Reversed/RawValue ********/

func buildStructuredFields(kind, value string, pm *model.PolicyMatcher) error {
	pm.RawValue = strings.TrimSpace(value)

	switch kind {
	case model.KindIp:
		b := ipTo16(net.ParseIP(pm.RawValue))
		if b == nil {
			return fmt.Errorf("bad ip: %q", pm.RawValue)
		}
		pm.IpFrom, pm.IpTo = b, b
		pm.Domain, pm.Reversed = "", ""

	case model.KindCidr:
		f, t, err := cidrToRange(pm.RawValue)
		if err != nil {
			return err
		}
		pm.IpFrom, pm.IpTo = f, t
		pm.Domain, pm.Reversed = "", ""

	case model.KindDomainExact:
		d, err := normalizeDomain(pm.RawValue)
		if err != nil || d == "" {
			return fmt.Errorf("bad domain")
		}
		pm.Domain = d
		pm.Reversed = reverseLabels(d)

	case model.KindDomainSuffix:
		v := strings.TrimPrefix(pm.RawValue, ".")
		d, err := normalizeDomain(v)
		if err != nil || d == "" {
			return fmt.Errorf("bad suffix")
		}
		pm.Domain = d
		pm.Reversed = reverseLabels(d)

	default:
		return fmt.Errorf("unknown kind: %s", kind)
	}
	return nil
}

/******** DTO（按表字段输出） ********/

type MatcherDTO struct {
	Id              int64  `json:"id"`
	UserId          int64  `json:"user_id"`
	Username        string `json:"username"`
	PolicyForwardId int64  `json:"policy_forward_id"`

	// 入口规则信息
	RuleId       int64  `json:"rule_id"`
	RuleAddress  string `json:"rule_address"`
	RulePort     int    `json:"rule_port"`
	RuleProtocol string `json:"rule_protocol"`

	TagName  string `json:"tag_name"`
	Kind     string `json:"kind"`
	Action   string `json:"action"`
	RawValue string `json:"raw_value"` // 只保留 raw_value
	Priority int    `json:"priority"`
	Status   string `json:"status"`
}

/******** Handlers ********/

// GET /api/policy/matcher
// 支持：kind, action, raw_value(模糊), status, min_priority, max_priority, policy_forward_id, rule_id, order_by, page, size
// order_by: priority_asc(默认)/priority_desc/time_desc
func (s *Server) listMatcher(c *gin.Context) {
	page, size := common.GetPage(c)
	offset := (page - 1) * size

	kind := normalizeLower(c.Query("kind"))
	action := normalizeLower(c.Query("action"))
	rawValue := strings.TrimSpace(c.Query("raw_value"))
	status := normalizeLower(c.Query("status"))
	orderBy := strings.TrimSpace(c.Query("order_by"))
	minPriStr := strings.TrimSpace(c.Query("min_priority"))
	maxPriStr := strings.TrimSpace(c.Query("max_priority"))
	bindStr := strings.TrimSpace(c.Query("policy_forward_id"))
	ruleStr := strings.TrimSpace(c.Query("rule_id"))

	var minPri, maxPri *int
	if minPriStr != "" {
		if v, err := strconv.Atoi(minPriStr); err == nil {
			minPri = &v
		}
	}
	if maxPriStr != "" {
		if v, err := strconv.Atoi(maxPriStr); err == nil {
			maxPri = &v
		}
	}
	var bindId *int64
	if bindStr != "" {
		if v, err := strconv.ParseInt(bindStr, 10, 64); err == nil {
			bindId = &v
		}
	}
	var ruleId *int64
	if ruleStr != "" {
		if v, err := strconv.ParseInt(ruleStr, 10, 64); err == nil {
			ruleId = &v
		}
	}

	db := s.App.MasterDB.GormDataSource.Table("policy_matcher AS m")

	uid, isAdmin := common.GetAuth(c)
	if !isAdmin {
		db = db.Where("m.user_id = ?", uid)
	}

	if kind != "" {
		db = db.Where("m.kind = ?", kind)
	}
	if action != "" {
		db = db.Where("m.action = ?", action)
	}
	if rawValue != "" {
		db = db.Where("m.raw_value LIKE ?", "%"+rawValue+"%")
	}
	if status != "" {
		db = db.Where("m.status = ?", status)
	}
	if minPri != nil {
		db = db.Where("m.priority >= ?", *minPri)
	}
	if maxPri != nil {
		db = db.Where("m.priority <= ?", *maxPri)
	}
	if bindId != nil {
		db = db.Where("m.policy_forward_id = ?", *bindId)
	}
	if ruleId != nil {
		db = db.Where("m.rule_id = ?", *ruleId)
	}

	var total int64
	if err := db.Distinct("m.id").Count(&total).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	switch orderBy {
	case "priority_desc":
		db = db.Order("m.priority DESC, m.id ASC")
	case "time_desc":
		db = db.Order("m.update_date_time DESC, m.id DESC")
	default:
		db = db.Order("m.priority ASC, m.id ASC")
	}

	rows := []MatcherDTO{}
	if err := db.
		Select(`
			m.id, m.user_id, m.policy_forward_id, m.rule_id,
			m.kind, m.action, m.raw_value, m.priority, m.status,
			u.username,
			pf.tag_name,
			r.address AS rule_address, r.port AS rule_port, r.protocol AS rule_protocol
		`).
		Joins("LEFT JOIN user u ON u.id = m.user_id").
		Joins("LEFT JOIN policy_forward pf ON pf.id = m.policy_forward_id").
		Joins("LEFT JOIN rule r ON r.id = m.rule_id").
		Limit(size).Offset(offset).
		Scan(&rows).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"list": rows, "total": total, "page": page, "size": size})
}

// POST /api/policy/matcher
func (s *Server) createMatcher(c *gin.Context) {
	type payload struct {
		RuleId          int64  `json:"rule_id"     binding:"required"`
		Kind            string `json:"kind"        binding:"required"`
		Action          string `json:"action"      binding:"required"`
		RawValue        string `json:"raw_value"   binding:"required"`
		Priority        int    `json:"priority"`
		Status          string `json:"status"`
		PolicyForwardId int64  `json:"policy_forward_id"`
		UserId          *int64 `json:"user_id"` // 仅管理员可指定；普通用户忽略
	}
	var in payload
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if in.RuleId <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "rule_id required"})
		return
	}

	in.Kind = normalizeLower(in.Kind)
	in.Action = normalizeLower(in.Action)
	in.Status = normalizeLower(in.Status)

	if !isValidKind(in.Kind) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid kind"})
		return
	}
	if !isValidAction(in.Action) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid action"})
		return
	}
	if in.Status == "" {
		in.Status = model.StatusEnabled
	}
	if !isValidStatus(in.Status) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid status"})
		return
	}
	if in.Priority == 0 {
		in.Priority = 100
	}
	if !validateMatchValue(in.Kind, in.RawValue) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "raw_value not valid for kind"})
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
			Model(&model.PolicyMatcher{}).
			Where("user_id = ?", owner).
			Count(&cnt).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if cnt >= 50000 {
			// 429 更符合“配额/限流已达上限”的语义
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "per-user limit reached (50000)"})
			return
		}
	}

	rec := model.PolicyMatcher{
		UserId:          owner,
		RuleId:          in.RuleId,
		PolicyForwardId: in.PolicyForwardId,
		Kind:            in.Kind,
		Action:          in.Action,
		Priority:        in.Priority,
		Status:          in.Status,
	}
	if err := buildStructuredFields(in.Kind, in.RawValue, &rec); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := s.App.MasterDB.GormDataSource.Create(&rec).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"id": rec.Id})
}

// PUT /api/policy/matcher/:id
func (s *Server) updateMatcher(c *gin.Context) {
	idStr := c.Param("id")
	if idStr == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing id"})
		return
	}

	uid, isAdmin := common.GetAuth(c)

	type payload struct {
		RuleId          *int64  `json:"rule_id"`
		Kind            *string `json:"kind"`
		Action          *string `json:"action"`
		RawValue        *string `json:"raw_value"`
		Priority        *int    `json:"priority"`
		Status          *string `json:"status"`
		PolicyForwardId *int64  `json:"policy_forward_id"`
	}
	var in payload
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 读取当前记录（校验权限 & 拿到现值）
	var cur model.PolicyMatcher
	db0 := s.App.MasterDB.GormDataSource.Table("policy_matcher").Where("id = ?", idStr)
	if !isAdmin {
		db0 = db0.Where("user_id = ?", uid)
	}
	if err := db0.Take(&cur).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}

	// 变更字段
	if in.RuleId != nil {
		if *in.RuleId <= 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "rule_id must be > 0"})
			return
		}
		cur.RuleId = *in.RuleId
	}
	if in.Kind != nil {
		k := normalizeLower(*in.Kind)
		if !isValidKind(k) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid kind"})
			return
		}
		cur.Kind = k
	}
	if in.RawValue != nil {
		mv := strings.TrimSpace(*in.RawValue)
		if !validateMatchValue(cur.Kind, mv) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "raw_value not valid for kind"})
			return
		}
		if err := buildStructuredFields(cur.Kind, mv, &cur); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	}
	if in.Action != nil {
		a := normalizeLower(*in.Action)
		if !isValidAction(a) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid action"})
			return
		}
		cur.Action = a
	}
	if in.Priority != nil {
		cur.Priority = *in.Priority
	}
	if in.Status != nil {
		sv := normalizeLower(*in.Status)
		if !isValidStatus(sv) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid status"})
			return
		}
		cur.Status = sv
	}
	if in.PolicyForwardId != nil {
		cur.PolicyForwardId = *in.PolicyForwardId
	}

	// 提交更新（只更可能变化的列）
	if err := s.App.MasterDB.GormDataSource.Model(&model.PolicyMatcher{}).Where("id = ?", idStr).
		Updates(map[string]any{
			"user_id":           cur.UserId, // 一般不改，这里兼容
			"rule_id":           cur.RuleId,
			"kind":              cur.Kind,
			"action":            cur.Action,
			"priority":          cur.Priority,
			"status":            cur.Status,
			"policy_forward_id": cur.PolicyForwardId,
			"raw_value":         cur.RawValue,
			"ip_from":           cur.IpFrom,
			"ip_to":             cur.IpTo,
			"domain":            cur.Domain,
			"reversed":          cur.Reversed,
		}).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// DELETE /api/policy/matcher/:id
func (s *Server) deleteMatcher(c *gin.Context) {
	idStr := c.Param("id")
	if idStr == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing id"})
		return
	}
	uid, isAdmin := common.GetAuth(c)

	db := s.App.MasterDB.GormDataSource.Where("id = ?", idStr)
	if !isAdmin {
		db = db.Where("user_id = ?", uid)
	}
	if err := db.Delete(&model.PolicyMatcher{}).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// DELETE /api/policy/matcher/batch
// 请求体：{ "ids": [1,2,3,...] }
// 响应：{ ok:true, deleted_count: N, forbidden_ids: [...], not_found_ids: [...] }
func (s *Server) deleteMatcherBatch(c *gin.Context) {
	type payload struct {
		IDs []int64 `json:"ids"`
	}
	var p payload
	if err := c.ShouldBindJSON(&p); err != nil || len(p.IDs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing ids"})
		return
	}

	// 去重 + 过滤非法（<=0）id
	ids := make([]int64, 0, len(p.IDs))
	seen := make(map[int64]struct{}, len(p.IDs))
	for _, v := range p.IDs {
		if v <= 0 {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		ids = append(ids, v)
	}
	if len(ids) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no valid ids"})
		return
	}

	uid, isAdmin := common.GetAuth(c)
	db := s.App.MasterDB.GormDataSource.WithContext(c.Request.Context())

	// 查询存在的 id 集合
	var exists []int64
	if err := db.Model(&model.PolicyMatcher{}).
		Where("id IN ?", ids).
		Pluck("id", &exists).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	existSet := make(map[int64]struct{}, len(exists))
	for _, id := range exists {
		existSet[id] = struct{}{}
	}

	// 计算 not found = ids - exists
	notFound := make([]int64, 0)
	for _, id := range ids {
		if _, ok := existSet[id]; !ok {
			notFound = append(notFound, id)
		}
	}

	// 允许删除的 id（owned），和无权限的 id（forbidden）
	var owned []int64
	var forbidden []int64

	if isAdmin {
		// 管理员：所有存在的都允许
		owned = exists
	} else {
		// 普通用户：只能删属于自己的
		var mine []int64
		if err := db.Model(&model.PolicyMatcher{}).
			Where("id IN ?", ids).
			Where("user_id = ?", uid).
			Pluck("id", &mine).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		ownSet := make(map[int64]struct{}, len(mine))
		for _, id := range mine {
			ownSet[id] = struct{}{}
		}

		owned = mine
		// forbidden = (exists - mine)
		for _, id := range exists {
			if _, ok := ownSet[id]; !ok {
				forbidden = append(forbidden, id)
			}
		}
	}

	// 真正删除（按块避免 SQL 占位符过多）
	var deleted int64
	if len(owned) > 0 {
		// 保险起见，非管理员这里再加一层 user_id 约束
		const chunk = 1000
		for i := 0; i < len(owned); i += chunk {
			end := i + chunk
			if end > len(owned) {
				end = len(owned)
			}
			q := db.Where("id IN ?", owned[i:end])
			if !isAdmin {
				q = q.Where("user_id = ?", uid)
			}
			res := q.Delete(&model.PolicyMatcher{})
			if res.Error != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": res.Error.Error()})
				return
			}
			deleted += res.RowsAffected
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"ok":            true,
		"deleted_count": deleted,
		"forbidden_ids": forbidden, // 这些存在但无权限
		"not_found_ids": notFound,  // 这些压根不存在
	})
}

/******** 批量新增（严格校验 & 权限） ********/

// POST /api/policy/matcher/batch
func (s *Server) batchCreateMatcher(c *gin.Context) {
	type payload struct {
		RuleId          int64       `json:"rule_id"     binding:"required"` // 批量必须指定入口规则
		Kind            string      `json:"kind"        binding:"required"` // "auto" | 具体类型
		Action          string      `json:"action"      binding:"required"`
		Status          string      `json:"status"`
		Priority        int         `json:"priority"`
		PolicyForwardId int64       `json:"policy_forward_id"`
		Values          interface{} `json:"values"       binding:"required"` // string 或 []string（每行一个；允许逗号）
		UserId          *int64      `json:"user_id"`                         // 仅管理员可指定
	}
	var in payload
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if in.RuleId <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "rule_id required"})
		return
	}

	in.Kind = normalizeLower(in.Kind)
	in.Action = normalizeLower(in.Action)
	in.Status = normalizeLower(in.Status)
	if !isValidKind(in.Kind) || !isValidAction(in.Action) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid kind/action"})
		return
	}
	if in.Status == "" {
		in.Status = model.StatusEnabled
	}
	if !isValidStatus(in.Status) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid status"})
		return
	}
	if in.Priority == 0 {
		in.Priority = 100
	}

	uid, isAdmin := common.GetAuth(c)
	owner := uid
	if isAdmin && in.UserId != nil && *in.UserId > 0 {
		owner = *in.UserId
	}

	// 拆 values：换行/逗号都可
	values := make([]string, 0, 64)
	switch v := in.Values.(type) {
	case string:
		tmp := strings.ReplaceAll(v, ",", "\n")
		for _, line := range strings.Split(tmp, "\n") {
			s := strings.TrimSpace(line)
			if s != "" {
				values = append(values, s)
			}
		}
	case []any:
		for _, x := range v {
			if s2, ok := x.(string); ok {
				s2 = strings.TrimSpace(s2)
				if s2 != "" {
					values = append(values, s2)
				}
			}
		}
	case []string:
		for _, s2 := range v {
			s2 = strings.TrimSpace(s2)
			if s2 != "" {
				values = append(values, s2)
			}
		}
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "values must be string or string array"})
		return
	}
	if len(values) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no values"})
		return
	}

	// 仅普通用户受限；管理员不受限
	if !isAdmin {
		var cnt int64
		if err := s.App.MasterDB.GormDataSource.
			Model(&model.PolicyMatcher{}).
			Where("user_id = ?", owner).
			Count(&cnt).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if int64(len(values))+cnt >= 50000 {
			// 429 更符合“配额/限流已达上限”的语义
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "per-user limit reached (50000)"})
			return
		}
	}

	type badLine struct {
		Line  int    `json:"line"`
		Value string `json:"value"`
	}
	bads := make([]badLine, 0)
	recs := make([]model.PolicyMatcher, 0, len(values))

	if in.Kind == "auto" {
		// 自动识别
		for i, raw := range values {
			if k, v, ok := detectKindAndNormalize(raw); ok {
				pm := model.PolicyMatcher{
					UserId:          owner,
					RuleId:          in.RuleId,
					PolicyForwardId: in.PolicyForwardId,
					Kind:            k,
					Action:          in.Action,
					Priority:        in.Priority,
					Status:          in.Status,
				}
				if err := buildStructuredFields(k, v, &pm); err != nil {
					bads = append(bads, badLine{Line: i + 1, Value: raw})
					continue
				}
				recs = append(recs, pm)
			} else {
				bads = append(bads, badLine{Line: i + 1, Value: raw})
			}
		}
	} else {
		// 固定类型：允许可选前缀（ip:/cidr:/exact:/suffix:）
		for i, raw := range values {
			v := stripOptionalPrefixForKind(in.Kind, raw)
			if !validateMatchValue(in.Kind, v) {
				bads = append(bads, badLine{Line: i + 1, Value: raw})
				continue
			}
			pm := model.PolicyMatcher{
				UserId:          owner,
				RuleId:          in.RuleId,
				PolicyForwardId: in.PolicyForwardId,
				Kind:            in.Kind,
				Action:          in.Action,
				Priority:        in.Priority,
				Status:          in.Status,
				RawValue:        v, // 先放入；buildStructuredFields 会按规范覆盖
			}
			if err := buildStructuredFields(in.Kind, v, &pm); err != nil {
				bads = append(bads, badLine{Line: i + 1, Value: raw})
				continue
			}
			recs = append(recs, pm)
		}
	}

	if len(bads) > 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":          "some values are invalid",
			"invalid_count":  len(bads),
			"invalid_values": bads,
		})
		return
	}

	batchSize := 1000 // 根据数据库限制适当调整
	tx := s.App.MasterDB.GormDataSource.Begin()
	if tx.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to start transaction"})
		return
	}
	for i := 0; i < len(recs); i += batchSize {
		end := i + batchSize
		if end > len(recs) {
			end = len(recs)
		}
		if err := tx.CreateInBatches(recs[i:end], batchSize).Error; err != nil {
			tx.Rollback()
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}
	if err := tx.Commit().Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to commit transaction"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "count": len(recs)})
}
