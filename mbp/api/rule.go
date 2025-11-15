package api

import (
	"errors"
	"fmt"
	"mlkmbp/mbp/common"
	"mlkmbp/mbp/common/logx"
	"mlkmbp/mbp/model"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

var apiRuleLog = logx.New(logx.WithPrefix("api.rule"))

/******** DTO ********/

type ruleDTO struct {
	ID       int64   `json:"id"`
	UserId   int64   `json:"user_id"`  // 规则拥有者（Rule.UserId）
	Username *string `json:"username"` // 拥有者用户名（左联 user）

	// 新增的非必输显示字段
	RuleName      string `json:"rule_name"`
	InterfaceName string `json:"interface_name"`

	Protocol      string `json:"protocol"`
	Address       string `json:"address"`
	Port          int    `json:"port"`
	TargetAddress string `json:"target_address"`
	TargetPort    int    `json:"target_port"`

	UpLimit       int64  `json:"up_limit"`
	DownLimit     int64  `json:"down_limit"`
	Status        string `json:"status"`
	MaxConnection int    `json:"max_connection"`
	ConnTimeout   int    `json:"conn_timeout"`
	ReadTimeout   int    `json:"read_timeout"`
	WriteTimeout  int    `json:"write_timeout"`

	AuthUsername   string `json:"auth_username"`
	AuthPassword   string `json:"auth_password"`
	SkipCertVerify bool   `json:"skip_cert_verify"`
	ALPN           string `json:"alpn"`
	TLSFingerprint string `json:"tls_fingerprint"`

	TLSCert     string `json:"tls_cert"` // 允许传空 / 路径 / PEM
	TLSKey      string `json:"tls_key"`
	TLSSNIGuard string `json:"tls_sni_guard"` // 逗号分隔域名或通配

	Socks5UDPPort  int `json:"socks5_udp_port"`
	Socks5BindPort int `json:"socks5_bind_port"`
}

/******** helpers ********/

func normProto(p string) string {
	pp := strings.ToLower(strings.TrimSpace(p))
	switch pp {
	case "socket5":
		return "socks5"
	case "tls-socket5":
		return "tls-socks5"
	default:
		return pp
	}
}

func requireTarget(p string) bool {
	switch normProto(p) {
	case "all", "tcp", "udp", "tls-tcp":
		return true
	default:
		return false
	}
}

func needInboundTLSCertKey(p string) bool {
	// 入站握手要证书/私钥的两类：tls-socks5、tls-http/s 也需要
	// - tls-http/s、tls-socks5：TLSCert/TLSKey 必须送
	// - tls-tcp：TLSCert/TLSKey 必须送
	switch normProto(p) {
	case "tls-tcp", "tls-socks5", "tls-http/s":
		return true
	default:
		return false
	}
}

func (s *Server) hasTLSConfigured() bool {
	// 仅检查是否配置了证书和私钥路径/内容
	return s.App.Cfg != nil && s.App.Cfg.TLSConfig.Cert != "" && s.App.Cfg.TLSConfig.Key != ""
}

func between(v, lo, hi int) bool {
	return v >= lo && v <= hi
}

/******** Handlers ********/

func (s *Server) listRule(c *gin.Context) {
	q := strings.TrimSpace(c.Query("q"))
	page, size := common.GetPage(c)
	offset := (page - 1) * size

	db := s.App.MasterDB.GormDataSource

	base := db.Table("rule AS r").
		Joins("LEFT JOIN user u ON u.id = r.user_id")

	// ===== 原有模糊搜索（保留）=====
	if q != "" {
		base = base.Where("(r.address LIKE ? OR r.target_address LIKE ?)", "%"+q+"%", "%"+q+"%")
	}

	// ===== 新增：精确筛选（只改查询）=====
	ruleName := strings.TrimSpace(c.Query("rule_name"))                 // 规则名
	protocol := strings.ToLower(strings.TrimSpace(c.Query("protocol"))) // 协议
	addr := strings.TrimSpace(c.Query("address"))                       // 监听地址
	portStr := strings.TrimSpace(c.Query("port"))                       // 监听端口
	tAddr := strings.TrimSpace(c.Query("target_address"))               // 目标地址
	tPortStr := strings.TrimSpace(c.Query("target_port"))               // 目标端口
	usernameQ := strings.TrimSpace(c.Query("username"))                 // 绑定用户（用户名）
	status := strings.ToLower(strings.TrimSpace(c.Query("status")))     // 状态 enabled/disabled

	if ruleName != "" {
		base = base.Where("r.rule_name LIKE ?", "%"+ruleName+"%")
	}
	if protocol != "" {
		// 与库中值大小写无关
		base = base.Where("LOWER(r.protocol) = ?", protocol)
	}
	if addr != "" {
		base = base.Where("r.address LIKE ?", "%"+addr+"%")
	}
	if portStr != "" {
		if p, err := strconv.ParseInt(portStr, 10, 64); err == nil {
			base = base.Where("r.port = ?", p)
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"error": "port must be int"})
			return
		}
	}
	if tAddr != "" {
		base = base.Where("r.target_address LIKE ?", "%"+tAddr+"%")
	}
	if tPortStr != "" {
		if tp, err := strconv.ParseInt(tPortStr, 10, 64); err == nil {
			base = base.Where("r.target_port = ?", tp)
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"error": "target_port must be int"})
			return
		}
	}
	if usernameQ != "" {
		base = base.Where("u.username LIKE ?", "%"+usernameQ+"%")
	}
	if status != "" {
		if status != "enabled" && status != "disabled" && status != "expired" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "status must be enabled/disabled/expired"})
			return
		}
		base = base.Where("r.status = ?", status)
	}

	// ===== 权限：非管理员只能看自己（保留）=====
	uid, isAdmin := common.GetAuth(c)
	if !isAdmin {
		base = base.Where("user_id = ?", uid)
	}

	var total int64
	if err := base.Distinct("r.id").Count(&total).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	var rows []struct {
		ID            int64
		UserId        int64
		Username      *string
		RuleName      string
		InterfaceName string
		Protocol      string
		Address       string
		Port          int
		TargetAddress string
		TargetPort    int
		UpLimit       int64
		DownLimit     int64
		Status        string
		MaxConnection int
		ConnTimeout   int
		ReadTimeout   int
		WriteTimeout  int

		AuthUsername   string
		AuthPassword   string
		SkipCertVerify bool
		ALPN           string
		TLSFingerprint string

		TLSCert        string
		TLSKey         string
		TLSSNIGuard    string
		Socks5UDPPort  int
		Socks5BindPort int
	}

	if err := base.
		Select(`
			r.id, r.user_id, u.username,
			r.rule_name, r.interface_name,
			r.protocol, r.address, r.port,
			r.target_address, r.target_port,
			r.up_limit, r.down_limit, r.status,
			r.max_connection, r.conn_timeout, r.read_timeout, r.write_timeout,

			r.auth_username, r.auth_password, r.skip_cert_verify, r.alpn, r.tls_fingerprint,

			r.tls_cert, r.tls_key, r.tls_sni_guard,
			r.socks5_udp_port, r.socks5_bind_port`).
		Order("r.id DESC"). // 排序不改
		Limit(size).Offset(offset).
		Scan(&rows).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	out := make([]ruleDTO, 0, len(rows))
	for _, r := range rows {
		out = append(out, ruleDTO{
			ID:            r.ID,
			UserId:        r.UserId,
			Username:      r.Username,
			RuleName:      r.RuleName,
			InterfaceName: r.InterfaceName,
			Protocol:      r.Protocol,
			Address:       r.Address,
			Port:          r.Port,
			TargetAddress: r.TargetAddress,
			TargetPort:    r.TargetPort,
			UpLimit:       r.UpLimit,
			DownLimit:     r.DownLimit,
			Status:        r.Status,
			MaxConnection: r.MaxConnection,
			ConnTimeout:   r.ConnTimeout,
			ReadTimeout:   r.ReadTimeout,
			WriteTimeout:  r.WriteTimeout,

			AuthUsername:   r.AuthUsername,
			AuthPassword:   r.AuthPassword,
			SkipCertVerify: r.SkipCertVerify,
			ALPN:           r.ALPN,
			TLSFingerprint: r.TLSFingerprint,

			TLSCert:     r.TLSCert,
			TLSKey:      r.TLSKey,
			TLSSNIGuard: r.TLSSNIGuard,

			Socks5UDPPort:  r.Socks5UDPPort,
			Socks5BindPort: r.Socks5BindPort,
		})
	}

	c.JSON(http.StatusOK, gin.H{"list": out, "total": total, "page": page, "size": size})
}

// GET /api/rule/simple?user_id=...
func (s *Server) listRuleSimple(c *gin.Context) {
	uid, isAdmin := common.GetAuth(c)
	qUID := strings.TrimSpace(c.Query("user_id"))

	type item struct {
		ID       int64  `json:"id"`
		Address  string `json:"address"`
		Port     int    `json:"port"`
		Protocol string `json:"protocol"`
	}
	var list []item

	db := s.App.MasterDB.GormDataSource

	if isAdmin {
		if qUID != "" {
			// 该用户“拥有的 + 被分享到的”
			if err := db.Raw(`
				SELECT r.id, r.address, r.port, r.protocol
				  FROM rule r
				 WHERE r.user_id = ?
				UNION
				SELECT r.id, r.address, r.port, r.protocol
				  FROM rule r
				  JOIN user_rule_map m ON m.rule_id = r.id
				 WHERE m.user_id = ?
				ORDER BY id DESC
			`, qUID, qUID).Scan(&list).Error; err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
		} else {
			if err := db.Model(&model.Rule{}).
				Select("id, address, port, protocol").
				Order("id").Scan(&list).Error; err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
		}
	} else {
		// 当前用户“拥有的 + 被分享到的”
		if err := db.Raw(`
			SELECT r.id, r.address, r.port, r.protocol
			  FROM rule r
			 WHERE r.user_id = ?
			UNION
			SELECT r.id, r.address, r.port, r.protocol
			  FROM rule r
			  JOIN user_rule_map m ON m.rule_id = r.id
			 WHERE m.user_id = ?
			ORDER BY id DESC
		`, uid, uid).Scan(&list).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{"list": list})
}

/******** create / update / delete ********/

// POST /api/rule
// 只有 admin 可以创建；监听 Address/Port、UserId、Status 必填；其它字段可选。
// 按协议：
// - all/tcp/udp/tls-tcp: 必须提供 TargetAddress/TargetPort；tls-tcp 还必须提供 TLSCert/TLSKey；TLSSNIGuard 可选
// - http/s、socks5: 目标、AuthUsername/AuthPassword/SkipCertVerify/ALPN/TLSFingerprint/TLSCert/TLSKey/TLSSNIGuard/socks5 端口 => 可选
// - tls-http/s、tls-socks5: 同上但 TLSCert/TLSKey 必送
func (s *Server) createRule(c *gin.Context) {
	type payload struct {
		ID *int64 `json:"id"`

		UserId  *int64  `json:"user_id"`
		Status  *string `json:"status"`
		Address *string `json:"address"`
		Port    *int    `json:"port"`

		// 新增的非必输字段
		RuleName      *string `json:"rule_name"`
		InterfaceName *string `json:"interface_name"`

		Protocol      *string `json:"protocol"`
		TargetAddress *string `json:"target_address"`
		TargetPort    *int    `json:"target_port"`

		UpLimit       *int64 `json:"up_limit"`
		DownLimit     *int64 `json:"down_limit"`
		MaxConnection *int   `json:"max_connection"`
		ConnTimeout   *int   `json:"conn_timeout"`
		ReadTimeout   *int   `json:"read_timeout"`
		WriteTimeout  *int   `json:"write_timeout"`

		AuthUsername   *string `json:"auth_username"`
		AuthPassword   *string `json:"auth_password"`
		SkipCertVerify *bool   `json:"skip_cert_verify"`
		ALPN           *string `json:"alpn"`
		TLSFingerprint *string `json:"tls_fingerprint"`

		TLSCert     *string `json:"tls_cert"`
		TLSKey      *string `json:"tls_key"`
		TLSSNIGuard *string `json:"tls_sni_guard"`

		Socks5UDPPort  *int `json:"socks5_udp_port"`
		Socks5BindPort *int `json:"socks5_bind_port"`
	}
	var r payload
	if err := c.BindJSON(&r); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// —— 通用必填 —— //
	if r.UserId == nil || *r.UserId <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_id required"})
		return
	}
	if r.Status == nil || strings.TrimSpace(*r.Status) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "status required"})
		return
	}
	if r.Address == nil || strings.TrimSpace(*r.Address) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "address required"})
		return
	}
	if r.Port == nil || !between(*r.Port, 1, 65535) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "valid port required"})
		return
	}
	if r.Protocol == nil || strings.TrimSpace(*r.Protocol) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "protocol required"})
		return
	}
	proto := normProto(*r.Protocol)

	// —— 协议特定校验 —— //
	if requireTarget(proto) {
		if r.TargetAddress == nil || strings.TrimSpace(*r.TargetAddress) == "" ||
			r.TargetPort == nil || !between(*r.TargetPort, 1, 65535) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "target_address/target_port required for protocol: " + proto})
			return
		}
	}
	if needInboundTLSCertKey(proto) {
		if r.TLSCert == nil || strings.TrimSpace(*r.TLSCert) == "" ||
			r.TLSKey == nil || strings.TrimSpace(*r.TLSKey) == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "tls_cert/tls_key required for protocol: " + proto})
			return
		}
	}

	// —— 可选字段校验（如果传了就校验）—— //
	if r.Socks5UDPPort != nil && !between(*r.Socks5UDPPort, 0, 65535) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid socks5_udp_port"})
		return
	}
	if r.Socks5BindPort != nil && !between(*r.Socks5BindPort, 0, 65535) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid socks5_bind_port"})
		return
	}

	// 构建 model.Rule（仅把有值的字段赋值；其它保持零值）
	md := model.Rule{
		UserId:   *r.UserId,
		Status:   strings.TrimSpace(*r.Status),
		Address:  strings.TrimSpace(*r.Address),
		Port:     *r.Port,
		Protocol: proto,
	}

	// 新增：非必输字段
	if r.RuleName != nil {
		md.RuleName = strings.TrimSpace(*r.RuleName)
	}
	if r.InterfaceName != nil {
		md.InterfaceName = strings.TrimSpace(*r.InterfaceName)
	}

	if r.TargetAddress != nil {
		md.TargetAddress = strings.TrimSpace(*r.TargetAddress)
	}
	if r.TargetPort != nil {
		md.TargetPort = *r.TargetPort
	}
	if r.UpLimit != nil {
		md.UpLimit = *r.UpLimit
	}
	if r.DownLimit != nil {
		md.DownLimit = *r.DownLimit
	}
	if r.MaxConnection != nil {
		md.MaxConnection = *r.MaxConnection
	}
	if r.ConnTimeout != nil {
		md.ConnTimeout = *r.ConnTimeout
	}
	if r.ReadTimeout != nil {
		md.ReadTimeout = *r.ReadTimeout
	}
	if r.WriteTimeout != nil {
		md.WriteTimeout = *r.WriteTimeout
	}

	if r.AuthUsername != nil {
		md.AuthUsername = *r.AuthUsername
	}
	if r.AuthPassword != nil {
		md.AuthPassword = *r.AuthPassword
	}
	if r.SkipCertVerify != nil {
		md.SkipCertVerify = *r.SkipCertVerify
	}
	if r.ALPN != nil {
		md.ALPN = *r.ALPN
	}
	if r.TLSFingerprint != nil {
		md.TLSFingerprint = *r.TLSFingerprint
	}

	if r.TLSCert != nil {
		md.TLSCert = *r.TLSCert
	}
	if r.TLSKey != nil {
		md.TLSKey = *r.TLSKey
	}
	if r.TLSSNIGuard != nil {
		md.TLSSNIGuard = *r.TLSSNIGuard
	}

	if r.Socks5UDPPort != nil {
		md.Socks5UDPPort = *r.Socks5UDPPort
	}
	if r.Socks5BindPort != nil {
		md.Socks5BindPort = *r.Socks5BindPort
	}

	if r.ID != nil && *r.ID > 0 {
		md.Id = *r.ID
	}

	// —— 事务：创建规则 & 确保 user_rule_map 关联存在 —— //
	tx := s.App.MasterDB.GormDataSource.Begin()
	if err := tx.Create(&md).Error; err != nil {
		tx.Rollback()
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			c.JSON(http.StatusConflict, gin.H{"error": "duplicate rule"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	urm := model.UserRuleMap{UserId: md.UserId, RuleId: md.Id}
	if err := tx.Where("user_id = ? AND rule_id = ?", md.UserId, md.Id).
		FirstOrCreate(&urm).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ensure user_rule_map failed: " + err.Error()})
		return
	}

	if err := tx.Commit().Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "id": md.Id})
}

// PUT /api/rule/:id
// 只有 admin 可以更新；未传的字段不会被清空。
// 校验逻辑：读取旧记录 -> 合并入参 -> 依据合并后的“最终数据”做一次全面校验 -> 仅更新非 nil 字段。
func (s *Server) updateRule(c *gin.Context) {
	type payload struct {
		UserId        *int64  `json:"user_id"`
		Status        *string `json:"status"`
		Address       *string `json:"address"`
		Port          *int    `json:"port"`
		Protocol      *string `json:"protocol"`
		TargetAddress *string `json:"target_address"`
		TargetPort    *int    `json:"target_port"`

		// 新增的非必输字段
		RuleName      *string `json:"rule_name"`
		InterfaceName *string `json:"interface_name"`

		UpLimit       *int64 `json:"up_limit"`
		DownLimit     *int64 `json:"down_limit"`
		MaxConnection *int   `json:"max_connection"`
		ConnTimeout   *int   `json:"conn_timeout"`
		ReadTimeout   *int   `json:"read_timeout"`
		WriteTimeout  *int   `json:"write_timeout"`

		AuthUsername   *string `json:"auth_username"`
		AuthPassword   *string `json:"auth_password"`
		SkipCertVerify *bool   `json:"skip_cert_verify"`
		ALPN           *string `json:"alpn"`
		TLSFingerprint *string `json:"tls_fingerprint"`

		TLSCert     *string `json:"tls_cert"`
		TLSKey      *string `json:"tls_key"`
		TLSSNIGuard *string `json:"tls_sni_guard"`

		Socks5UDPPort  *int `json:"socks5_udp_port"`
		Socks5BindPort *int `json:"socks5_bind_port"`
	}
	var r payload
	if err := c.BindJSON(&r); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	id := c.Param("id")

	// 先取旧记录
	var old model.Rule
	if err := s.App.MasterDB.GormDataSource.Where("id = ?", id).First(&old).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "rule not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 合并成 final
	final := old

	if r.UserId != nil {
		final.UserId = *r.UserId
	}
	if r.Status != nil {
		final.Status = strings.TrimSpace(*r.Status)
	}
	if r.Address != nil {
		final.Address = strings.TrimSpace(*r.Address)
	}
	if r.Port != nil {
		final.Port = *r.Port
	}
	if r.Protocol != nil {
		final.Protocol = normProto(*r.Protocol)
	}

	// 新增：非必输字段
	if r.RuleName != nil {
		final.RuleName = strings.TrimSpace(*r.RuleName)
	}
	if r.InterfaceName != nil {
		final.InterfaceName = strings.TrimSpace(*r.InterfaceName)
	}

	if r.TargetAddress != nil {
		final.TargetAddress = strings.TrimSpace(*r.TargetAddress)
	}
	if r.TargetPort != nil {
		final.TargetPort = *r.TargetPort
	}

	if r.UpLimit != nil {
		final.UpLimit = *r.UpLimit
	}
	if r.DownLimit != nil {
		final.DownLimit = *r.DownLimit
	}
	if r.MaxConnection != nil {
		final.MaxConnection = *r.MaxConnection
	}
	if r.ConnTimeout != nil {
		final.ConnTimeout = *r.ConnTimeout
	}
	if r.ReadTimeout != nil {
		final.ReadTimeout = *r.ReadTimeout
	}
	if r.WriteTimeout != nil {
		final.WriteTimeout = *r.WriteTimeout
	}

	if r.AuthUsername != nil {
		final.AuthUsername = *r.AuthUsername
	}
	if r.AuthPassword != nil {
		final.AuthPassword = *r.AuthPassword
	}
	if r.SkipCertVerify != nil {
		final.SkipCertVerify = *r.SkipCertVerify
	}
	if r.ALPN != nil {
		final.ALPN = *r.ALPN
	}
	if r.TLSFingerprint != nil {
		final.TLSFingerprint = *r.TLSFingerprint
	}

	if r.TLSCert != nil {
		final.TLSCert = *r.TLSCert
	}
	if r.TLSKey != nil {
		final.TLSKey = *r.TLSKey
	}
	if r.TLSSNIGuard != nil {
		final.TLSSNIGuard = *r.TLSSNIGuard
	}

	if r.Socks5UDPPort != nil {
		final.Socks5UDPPort = *r.Socks5UDPPort
	}
	if r.Socks5BindPort != nil {
		final.Socks5BindPort = *r.Socks5BindPort
	}

	// —— 合并后做最终校验 —— //
	// 通用必填：UserId, Status, Address, Port
	if final.UserId <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_id required"})
		return
	}
	if strings.TrimSpace(final.Status) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "status required"})
		return
	}
	if strings.TrimSpace(final.Address) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "address required"})
		return
	}
	if !between(final.Port, 1, 65535) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "valid port required"})
		return
	}

	p := normProto(final.Protocol)
	if requireTarget(p) {
		if strings.TrimSpace(final.TargetAddress) == "" || !between(final.TargetPort, 1, 65535) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "target_address/target_port required for protocol: " + p})
			return
		}
	}
	if needInboundTLSCertKey(p) {
		if strings.TrimSpace(final.TLSCert) == "" || strings.TrimSpace(final.TLSKey) == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "tls_cert/tls_key required for protocol: " + p})
			return
		}
	}

	// 范围校验（如果入参里有带这两个字段，或者合并后最终值不为 0 也不影响，只要在范围内即可）
	if final.Socks5UDPPort != 0 && !between(final.Socks5UDPPort, 0, 65535) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid socks5_udp_port"})
		return
	}
	if final.Socks5BindPort != 0 && !between(final.Socks5BindPort, 0, 65535) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid socks5_bind_port"})
		return
	}

	// —— 构建 Updates：仅更新非 nil 字段 —— //
	upd := map[string]any{}
	set := func(k string, v any) { upd[k] = v }

	if r.UserId != nil {
		set("user_id", final.UserId)
	}
	if r.Status != nil {
		set("status", final.Status)
	}
	if r.Address != nil {
		set("address", final.Address)
	}
	if r.Port != nil {
		set("port", final.Port)
	}
	if r.Protocol != nil {
		set("protocol", final.Protocol)
	}

	// 新增：非必输字段
	if r.RuleName != nil {
		set("rule_name", final.RuleName)
	}
	if r.InterfaceName != nil {
		set("interface_name", final.InterfaceName)
	}

	if r.TargetAddress != nil {
		set("target_address", final.TargetAddress)
	}
	if r.TargetPort != nil {
		set("target_port", final.TargetPort)
	}

	if r.UpLimit != nil {
		set("up_limit", final.UpLimit)
	}
	if r.DownLimit != nil {
		set("down_limit", final.DownLimit)
	}
	if r.MaxConnection != nil {
		set("max_connection", final.MaxConnection)
	}
	if r.ConnTimeout != nil {
		set("conn_timeout", final.ConnTimeout)
	}
	if r.ReadTimeout != nil {
		set("read_timeout", final.ReadTimeout)
	}
	if r.WriteTimeout != nil {
		set("write_timeout", final.WriteTimeout)
	}

	if r.AuthUsername != nil {
		set("auth_username", final.AuthUsername)
	}
	if r.AuthPassword != nil {
		set("auth_password", final.AuthPassword)
	}
	if r.SkipCertVerify != nil {
		set("skip_cert_verify", final.SkipCertVerify)
	}
	if r.ALPN != nil {
		set("alpn", final.ALPN)
	}
	if r.TLSFingerprint != nil {
		set("tls_fingerprint", final.TLSFingerprint)
	}

	if r.TLSCert != nil {
		set("tls_cert", final.TLSCert)
	}
	if r.TLSKey != nil {
		set("tls_key", final.TLSKey)
	}
	if r.TLSSNIGuard != nil {
		set("tls_sni_guard", final.TLSSNIGuard)
	}

	if r.Socks5UDPPort != nil {
		set("socks5_udp_port", final.Socks5UDPPort)
	}
	if r.Socks5BindPort != nil {
		set("socks5_bind_port", final.Socks5BindPort)
	}

	// —— 事务：更新规则 & 确保 user_rule_map 关联存在（当 user_id 变化时） —— //
	tx := s.App.MasterDB.GormDataSource.Begin()

	if err := tx.Model(&model.Rule{}).
		Where("id = ?", id).
		Updates(upd).Error; err != nil {
		tx.Rollback()
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			c.JSON(http.StatusConflict, gin.H{"error": "duplicate rule"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 如果 user_id 被修改，确保映射
	if r.UserId != nil {
		ruleId, _ := strconv.ParseInt(id, 10, 64)
		urm := model.UserRuleMap{UserId: final.UserId, RuleId: ruleId}
		if err := tx.Where("user_id = ? AND rule_id = ?", final.UserId, ruleId).
			FirstOrCreate(&urm).Error; err != nil {
			tx.Rollback()
			c.JSON(http.StatusInternalServerError, gin.H{"error": "ensure user_rule_map failed: " + err.Error()})
			return
		}
	}

	if err := tx.Commit().Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// DELETE /api/rule/:id
func (s *Server) deleteRule(c *gin.Context) {
	idStr := c.Param("id")
	rid, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}

	err = s.App.MasterDB.GormDataSource.WithContext(c.Request.Context()).Transaction(func(tx *gorm.DB) error {
		// 1) 取关联 pfIDs（失败记日志，继续）
		var pfIDs []int64
		if err := tx.Model(&model.PolicyMatcher{}).
			Where("rule_id = ?", rid).
			Distinct().Pluck("policy_forward_id", &pfIDs).Error; err != nil {
			apiRuleLog.Warnf("query policy_forward_id for rule=%d failed: %v", rid, err)
			pfIDs = nil
		}

		// 2) 删映射（失败记日志，继续）
		if err := tx.Where("rule_id = ?", rid).Delete(&model.PolicyMatcher{}).Error; err != nil {
			apiRuleLog.Warnf("delete policy_matcher rule=%d failed: %v", rid, err)
		}
		// 如需：删 user_rule_map（失败记日志，继续）
		if err := tx.Where("rule_id = ?", rid).Delete(&model.UserRuleMap{}).Error; err != nil {
			apiRuleLog.Warnf("delete user_rule_map rule=%d failed: %v", rid, err)
		}

		// 3) 删主表 rule（**必须成功**；失败→中断回滚）
		res := tx.Where("id = ?", rid).Delete(&model.Rule{})
		if res.Error != nil {
			return fmt.Errorf("delete rule=%d failed: %w", rid, res.Error)
		}
		if res.RowsAffected == 0 {
			return gorm.ErrRecordNotFound // 也可以选择视为成功幂等
		}

		// 4) 删“孤儿” policy_forward（失败记日志，继续）
		if len(pfIDs) > 0 {
			// 去掉 0 值
			kept := pfIDs[:0]
			for _, id := range pfIDs {
				if id != 0 {
					kept = append(kept, id)
				}
			}
			pfIDs = kept
		}
		if len(pfIDs) > 0 {
			var stillRef []int64
			if err := tx.Model(&model.PolicyMatcher{}).
				Where("policy_forward_id IN ?", pfIDs).
				Distinct().Pluck("policy_forward_id", &stillRef).Error; err != nil {
				apiRuleLog.Warnf("check pf still referenced failed: %v", err)
				return nil // 不中断
			}
			ref := map[int64]struct{}{}
			for _, id := range stillRef {
				ref[id] = struct{}{}
			}
			var toDelete []int64
			for _, id := range pfIDs {
				if _, ok := ref[id]; !ok {
					toDelete = append(toDelete, id)
				}
			}
			if len(toDelete) > 0 {
				if err := tx.Where("id IN ?", toDelete).Delete(&model.PolicyForward{}).Error; err != nil {
					apiRuleLog.Warnf("delete orphan policy_forward %v failed: %v", toDelete, err)
				}
			}
		}
		return nil
	})

	switch {
	case errors.Is(err, gorm.ErrRecordNotFound):
		// 如果希望“幂等删除”，可以改成 200 OK
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
	case err != nil:
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
	default:
		c.JSON(http.StatusOK, gin.H{"ok": true})
	}
}
