package api

import (
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"mlkmbp/mbp/common"
	"mlkmbp/mbp/common/license"
	"mlkmbp/mbp/model"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

/******** JWT / Claims ********/

type Claims struct {
	UserId   int64  `json:"uid"`
	Username string `json:"username"`
	IsAdmin  bool   `json:"is_admin"`
	jwt.RegisteredClaims
}

func (s *Server) makeToken(uid int64, username string, admin bool) (string, error) {
	ttl := s.App.Cfg.Admin.TokenTTL
	if ttl <= 0 {
		ttl = 1440
	}
	now := time.Now()
	claims := Claims{
		UserId:   uid,
		Username: username,
		IsAdmin:  admin,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Duration(ttl) * time.Minute)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.App.Cfg.Admin.JWTSecret))
}

func (s *Server) parseToken(tk string) (*Claims, error) {
	parsed, err := jwt.ParseWithClaims(tk, &Claims{}, func(t *jwt.Token) (any, error) {
		return []byte(s.App.Cfg.Admin.JWTSecret), nil
	})
	if err != nil {
		return nil, err
	}
	c, ok := parsed.Claims.(*Claims)
	if !ok || !parsed.Valid {
		return nil, errors.New("invalid token")
	}
	return c, nil
}

/******** Middlewares ********/

// AuthRequired parses Authorization: Bearer <token>
func (s *Server) AuthRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		auth := c.GetHeader("Authorization")
		if !strings.HasPrefix(strings.ToLower(auth), "bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		tk := strings.TrimSpace(auth[7:])
		claims, err := s.parseToken(tk)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}
		c.Set("uid", claims.UserId)
		c.Set("username", claims.Username)
		c.Set("isAdmin", claims.IsAdmin)
		c.Next()
	}
}

func AdminOnly() gin.HandlerFunc {
	return func(c *gin.Context) {
		v, exists := c.Get("isAdmin")
		if !exists || !v.(bool) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden"})
			return
		}
		c.Next()
	}
}

/******** Handlers: /login /me /me/password ********/

// POST /api/login  {username,password}
func (s *Server) login(c *gin.Context) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		A        string `json:"a"` // ← 新增：必填
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	u := strings.TrimSpace(req.Username)
	p := strings.TrimSpace(req.Password)
	if u == "" || p == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "username/password required"})
		return
	}

	ip := c.ClientIP() // 需要在 gin.Engine 上配置 TrustedProxies
	if s.Guard != nil {
		if ok, retry := s.Guard.Allow(ip, u); !ok {
			// 统一返回 429，不暴露存在与否
			if retry > 0 {
				c.Header("Retry-After", fmt.Sprintf("%.0f", retry.Seconds()))
			}
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "Too many attempts, try later"})
			return
		}
	}

	var m model.User
	if err := s.App.MasterDB.GormDataSource.
		Where("username = ?", u).
		Take(&m).Error; err != nil {
		if s.Guard != nil {
			s.Guard.Fail(ip, u)
		}
		// 模糊错误
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Login failed, please check username and password"})
		return
	}

	// 明文/哈希都支持
	if !common.PasswordOK(m.Password, m.PasswordSha256, p) {
		if s.Guard != nil {
			s.Guard.Fail(ip, u)
		}
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Login failed, please check username and password"})
		return
	}
	if m.Status != "enabled" && m.Status != "expired" {
		if s.Guard != nil {
			s.Guard.Success(ip, u)
		} // 账号存在且密码正确 -> 成功尝试，避免继续被封
		c.JSON(http.StatusForbidden, gin.H{"error": "user disabled"})
		return
	}
	// 是否 admin
	admin := common.IsAdminID(s.App.Cfg.Admin.AdminIDs, m.Id)
	if !s.App.Cfg.License.User {
		ok, msg, lp := license.VerifyLicenseEd25519(req.A)
		if !ok {
			if msg == "" {
				c.JSON(http.StatusForbidden, gin.H{"error": "invalid license a"})
			} else {
				c.JSON(http.StatusForbidden, gin.H{"error": msg})
			}
			return
		}
		// 管理员 => 维护到全局（仅内存）
		if admin {
			s.App.Cfg.License = *lp
		}
	}

	tk, err := s.makeToken(m.Id, m.Username, admin)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if s.Guard != nil {
		s.Guard.Success(ip, u)
	}
	licOK, licMsg := common.TimeAndMachineCode(
		s.App.Cfg.License.RunTime,
		s.App.Cfg.License.MachineCode,
	)

	// license_message 统一返回字符串：有效时为空字符串，无效时给出提示
	licenseMessage := ""
	if !licOK {
		licenseMessage = licMsg
	}

	c.JSON(http.StatusOK, gin.H{
		"token":           tk,
		"user":            gin.H{"id": m.Id, "username": m.Username},
		"is_admin":        admin,
		"license_message": licenseMessage,
	})
}

// GET /api/me
func (s *Server) me(c *gin.Context) {
	uidVal, _ := c.Get("uid")
	nameVal, _ := c.Get("username")
	isAdmin, _ := c.Get("isAdmin")

	// Parse uid
	var uid int64
	switch v := uidVal.(type) {
	case int64:
		uid = v
	case int:
		uid = int64(v)
	case string:
		n, _ := strconv.ParseInt(v, 10, 64)
		uid = n
	}

	var u model.User
	if err := s.App.MasterDB.GormDataSource.
		Where("id = ? AND username = ?", uid, nameVal).
		Take(&u).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "user not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id":                u.Id,
		"vm_id":             u.VmId,
		"username":          u.Username,
		"quota":             u.Quota,
		"up":                u.Up,
		"down":              u.Down,
		"up_limit":          u.UpLimit,
		"down_limit":        u.DownLimit,
		"status":            u.Status,
		"start_date_time":   u.StartDateTime,
		"expired_date_time": u.ExpiredDateTime,
		"period_unit":       u.PeriodUnit,
		"period_left":       u.PeriodLeft,
		"create_date_time":  u.CreateDateTime,
		"update_date_time":  u.UpdateDateTime,
		"is_admin":          isAdmin,
	})
}

// PUT /api/me/password
// Body: { "old_password": "xxx", "new_password": "yyy", "confirm": "yyy" }
func (s *Server) changePassword(c *gin.Context) {
	type req struct {
		Old string `json:"old_password"`
		New string `json:"new_password"`
		Con string `json:"confirm"`
	}
	var r req
	if err := c.BindJSON(&r); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		return
	}
	// Basic validation
	if len(r.Old) == 0 || len(r.New) == 0 || len(r.Con) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Password cannot be empty"})
		return
	}
	if strings.TrimSpace(r.New) != r.New {
		c.JSON(http.StatusBadRequest, gin.H{"error": "New password cannot have leading or trailing spaces"})
		return
	}
	if len(r.New) < 6 || len(r.New) > 64 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "New password length must be between 6 and 64 characters"})
		return
	}
	if r.New != r.Con {
		c.JSON(http.StatusBadRequest, gin.H{"error": "New passwords do not match"})
		return
	}

	uid, _ := common.GetAuth(c)

	// Read current password
	var u model.User
	if err := s.App.MasterDB.GormDataSource.Select("id, username, password").
		Where("id = ?", uid).
		Take(&u).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read user"})
		return
	}
	if u.Password != r.Old {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Incorrect old password"})
		return
	}

	// Update password + password_sha256
	if err := s.App.MasterDB.GormDataSource.Model(&model.User{}).
		Where("id = ?", uid).
		Updates(map[string]any{
			"password":        r.New,
			"password_sha256": common.HashUP(r.New),
		}).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update password"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}
