package api

import (
	"mlkmbp/mbp/common"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

/********** Router **********/
func (s *Server) Router() *gin.Engine {
	r := gin.New()
	// 中间件：Recovery + 日志
	r.Use(gin.Recovery(), gin.Logger())
	
	/********** 业务 API **********/
	api := r.Group("/api")
	{
		api.POST("/login", s.login)

	}

	auth := api.Group("/")
	auth.Use(s.AuthRequired())
	{
		auth.GET("/me", s.me)
		auth.PUT("/me/password", s.changePassword)

		auth.GET("/user/simple", s.listUserSimple)
		auth.GET("/rule/simple", s.listRuleSimple)

		auth.GET("/systemInfo", s.systemInfo)
		auth.GET("/traffic", s.listTraffic)

		auth.GET("/policy/forward", s.listPolicyForward)
		auth.POST("/policy/forward", s.createPolicyForward)
		auth.PUT("/policy/forward/:id", s.updatePolicyForward)
		auth.DELETE("/policy/forward/:id", s.deletePolicyForward)
		auth.DELETE("/policy/forward/batch", s.deletePolicyForwardBatch)
		auth.GET("/policy/forward/tag", s.listPolicyForwardTag)

		auth.GET("/policy/matcher", s.listMatcher)
		auth.POST("/policy/matcher", s.createMatcher)
		auth.PUT("/policy/matcher/:id", s.updateMatcher)
		auth.DELETE("/policy/matcher/:id", s.deleteMatcher)
		auth.DELETE("/policy/matcher/batch", s.deleteMatcherBatch)
		auth.POST("/policy/matcher/batch", s.batchCreateMatcher)

		auth.GET("/user", s.listUser)

		auth.GET("/rule", s.listRule)

	}

	admin := auth.Group("/")
	admin.Use(AdminOnly())
	{

		admin.POST("/user", s.createUser)
		admin.PUT("/user/:id", s.updateUser)
		admin.DELETE("/user/:id", s.deleteUser)

		admin.POST("/rule", s.createRule)
		admin.PUT("/rule/:id", s.updateRule)
		admin.DELETE("/rule/:id", s.deleteRule)

		admin.GET("/rule-binding", s.listRuleBinding)
		admin.GET("/rule/:id/binding", s.getRuleBinding)
		admin.GET("/user/search", s.searchUser)
		admin.PUT("/rule/:id/binding", s.replaceRuleBinding)
		admin.POST("/rule/:id/binding", s.addOneBinding)
		admin.DELETE("/rule/:id/binding/:user_id", s.deleteOneBinding)

		admin.GET("/user-binding", s.listUserBinding)
		admin.GET("/user/:id/rule", s.getUserRule)
		admin.GET("/rule/search", s.searchRule)
		admin.PUT("/user/:id/rule", s.replaceUserRule)
		admin.POST("/user/:id/rule", s.addUserRule)
		admin.DELETE("/user/:id/rule/:rule_id", s.deleteUserRule)

		admin.GET("/config", s.ConfigRead)
		admin.PUT("/config", s.ConfigUpdate)
		admin.POST("/restart", s.ConfigRestart)

	}

	/********** 前端静态资源（Vue dist） **********/
	base := distBase()

	// 一般 Vite/Vue3 的静态资源放在 /assets 下，给它做静态目录映射
	r.Static("/assets", filepath.Join(base, "assets"))
	// 常见静态文件
	r.StaticFile("/favicon.ico", filepath.Join(base, "favicon.ico"))
	r.StaticFile("/robots.txt", filepath.Join(base, "robots.txt"))
	// 可选：如果有 manifest 等
	r.StaticFile("/manifest.webmanifest", filepath.Join(base, "manifest.webmanifest"))

	// 其余非 /api/** 的路径全部回退到 index.html（支持前端路由）
	r.NoRoute(func(c *gin.Context) {
		// 若是 /api 打头但没匹配到具体路由，返回 JSON 404，而不是把 index.html 返回给前端
		if strings.HasPrefix(c.Request.URL.Path, "/api/") || c.Request.URL.Path == "/api" || strings.HasPrefix(c.Request.URL.Path, "/ws/") || c.Request.URL.Path == "/ws" {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found", "time": time.Now().UnixMilli()})
			return
		}
		switch c.Request.Method {
		case http.MethodGet, http.MethodHead:
			c.Header("Cache-Control", "no-cache")
			c.File(filepath.Join(base, "index.html"))
		default:
			c.JSON(http.StatusNotFound, gin.H{"error": "not found", "time": time.Now().UnixMilli()})
		}
	})

	return r
}

func distBase() string {
	if common.IsDesktop() {
		return "./html"
	}
	return "/var/html/mlkmbp"
}
