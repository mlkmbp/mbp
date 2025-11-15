package api

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"
	"io/fs"
	"mlkmbp/mbp/common"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

var cfgMu sync.Mutex

func fileETag(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// -------- 路径解析与兜底 --------

// resolveConfigPath 会尽量把 s.App.CfgPath 解析成一个**存在的文件**路径：
// - 如果是目录，则自动拼上 config.yaml
// - 如果是相对路径，先按 CWD 试，再按可执行文件同目录试
// - 若最终不存在则返回明确错误
func resolveConfigPath(p string) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" {
		p = "config/config.yaml"
	}
	// 1) 如果是目录 → 拼上 config.yaml
	if st, err := os.Stat(p); err == nil && st.IsDir() {
		p = filepath.Join(p, "config.yaml")
	}
	// 2) 先按原样检查
	if f, err := fileIfExists(p); err == nil {
		return f, nil
	}
	// 3) 如果是相对路径，尝试在可执行文件目录下找
	if !filepath.IsAbs(p) {
		if exe, err := os.Executable(); err == nil {
			base := filepath.Dir(exe)
			if f, err2 := fileIfExists(filepath.Join(base, p)); err2 == nil {
				return f, nil
			}
			// 若 p 是目录形式，则再拼一次
			if st, err3 := os.Stat(filepath.Join(base, p)); err3 == nil && st.IsDir() {
				if f, err4 := fileIfExists(filepath.Join(base, p, "config.yaml")); err4 == nil {
					return f, nil
				}
			}
		}
	}
	return "", errors.New("config file not found: " + p)
}

func fileIfExists(p string) (string, error) {
	st, err := os.Stat(p)
	if err != nil {
		return "", err
	}
	if st.IsDir() {
		return "", errors.New("path is a directory: " + p)
	}
	abs, _ := filepath.Abs(p)
	return abs, nil
}

// --------- API：读取 / 修改 / 重启 ---------

// GET /api/config
// 返回: { content: string, etag: string, mtime: string, path: string }
func (s *Server) ConfigRead(c *gin.Context) {
	_, isAdmin := common.GetAuth(c)
	if !isAdmin {
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
		return
	}

	cfgPath, err := resolveConfigPath(s.App.CfgPath)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	b, err := os.ReadFile(cfgPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "read config: " + err.Error()})
		return
	}
	st, _ := os.Stat(cfgPath)
	c.JSON(http.StatusOK, gin.H{
		"content": string(b),
		"etag":    fileETag(b),
		"mtime":   st.ModTime().Format(time.DateTime),
		"path":    cfgPath,
	})
}

type cfgUpdateReq struct {
	Content string `json:"content"`
	ETag    string `json:"etag,omitempty"`   // 可选：防并发覆盖
	Backup  bool   `json:"backup,omitempty"` // 默认 true
}

// PUT /api/config
// 入参: { content, etag?, backup? } -> { ok: true, etag: "...", backup_path?: "..." }
func (s *Server) ConfigUpdate(c *gin.Context) {
	_, isAdmin := common.GetAuth(c)
	if !isAdmin {
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
		return
	}

	var in cfgUpdateReq
	if err := c.BindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad json"})
		return
	}
	if strings.TrimSpace(in.Content) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "content required"})
		return
	}
	// 1) YAML 语法校验
	var tmp any
	if err := yaml.Unmarshal([]byte(in.Content), &tmp); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid yaml: " + err.Error()})
		return
	}

	cfgPath, err := resolveConfigPath(s.App.CfgPath)
	if err != nil {
		// 如果上一步找不到，但给的是目录，也允许在该目录创建 config.yaml
		// 这里保守：只有当配置给的是目录时我们才创建，否则报错
		dir := strings.TrimSpace(s.App.CfgPath)
		if dir == "" {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
			return
		}
		if st, e2 := os.Stat(dir); e2 == nil && st.IsDir() {
			cfgPath = filepath.Join(dir, "config.yaml")
		} else {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
			return
		}
	}

	cfgMu.Lock()
	defer cfgMu.Unlock()

	// 2) 乐观锁（可选）
	if strings.TrimSpace(in.ETag) != "" {
		if old, err := os.ReadFile(cfgPath); err == nil {
			if fileETag(old) != in.ETag {
				c.JSON(http.StatusPreconditionFailed, gin.H{
					"error":    "etag_mismatch",
					"message":  "the config was modified by someone else",
					"current":  string(old),
					"currETag": fileETag(old),
				})
				return
			}
		}
	}

	// 3) 备份
	backupPath := ""
	doBackup := true
	if !in.Backup { // 显式关闭
		doBackup = false
	}
	if doBackup {
		if st, err := os.Stat(cfgPath); err == nil && !st.IsDir() {
			ts := time.Now().Format("2006-01-02 15:04:05")
			dir := filepath.Dir(cfgPath)
			base := filepath.Base(cfgPath)
			backupPath = filepath.Join(dir, "."+base+".bak-"+ts)
			_ = copyFile(cfgPath, backupPath, 0600)
		}
	}

	// 4) 原子写入
	if err := atomicWrite(cfgPath, []byte(in.Content), 0644); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	newETag := fileETag([]byte(in.Content))
	out := gin.H{"ok": true, "etag": newETag}
	if backupPath != "" {
		out["backup_path"] = backupPath
	}
	c.JSON(http.StatusOK, out)
}

func atomicWrite(target string, data []byte, perm fs.FileMode) error {
	tmpFile := target + ".tmp-" + time.Now().Format("150405.000")
	if err := os.WriteFile(tmpFile, data, perm); err != nil {
		return errors.New("write temp: " + err.Error())
	}
	if err := os.Rename(tmpFile, target); err != nil {
		_ = os.Remove(tmpFile)
		return errors.New("atomic replace: " + err.Error())
	}
	return nil
}

func copyFile(src, dst string, perm fs.FileMode) error {
	in, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, in, perm)
}

// POST /api/restart
// Linux：默认 300ms 后退出，交由 systemd/Docker 拉起
// 其它平台：返回 501（“只支持 Linux” 的要求）
func (s *Server) ConfigRestart(c *gin.Context) {
	_, isAdmin := common.GetAuth(c)
	if !isAdmin {
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
		return
	}
	if runtime.GOOS != "linux" {
		c.JSON(http.StatusNotImplemented, gin.H{
			"error":   "restart_not_supported",
			"message": "restart is only supported on linux",
		})
		return
	}
	go func() {
		time.Sleep(300 * time.Millisecond)
		os.Exit(0)
	}()
	c.JSON(http.StatusOK, gin.H{"ok": true})
}
