package config

import (
	"errors"
	"gopkg.in/yaml.v3"
	"mlkmbp/mbp/common"
	"mlkmbp/mbp/common/license"
	"mlkmbp/mbp/common/logx"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

type DBPoolCfg struct {
	MaxOpen        int `yaml:"max_open"`
	MaxIdle        int `yaml:"max_idle"`
	MaxLifetimeSec int `yaml:"max_lifetime_sec"`
}

type DBCfg struct {
	Driver string    `yaml:"driver"`
	DSN    string    `yaml:"dsn"`
	Pool   DBPoolCfg `yaml:"pool"`
	Enable bool      `yaml:"enable"`
}

type DualDBCfg struct {
	Master DBCfg `yaml:"master"`
	Log    DBCfg `yaml:"log"`
}

type AdminAuth struct {
	AdminIDs  []int  `yaml:"admin_ids"`
	JWTSecret string `yaml:"jwt_secret"`
	TokenTTL  int    `yaml:"token_ttl"`
}

type TLSConfig struct {
	Cert     string `yaml:"cert"`
	Key      string `yaml:"key"`
	SniGuard string `yaml:"sniGuard"`
}

type Logging struct {
	Level string `yaml:"level"`
}

type PVEConfig struct {
	BaseURL            string `yaml:"base_url"`
	TokenID            string `yaml:"token_id"`
	Secret             string `yaml:"secret"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
	SSHBaseURL         string `yaml:"ssh_base_url"`
	SSHUser            string `yaml:"ssh_user"`
	SSHPassword        string `yaml:"ssh_password"`
	SSHPrivateKeyPEM   string `yaml:"ssh_private_key_pem"`
	SSHKeyPassphrase   string `yaml:"ssh_key_passphrase"`
}

type InfluxDB2Config struct {
	BaseURL            string `yaml:"base_url"`
	Token              string `yaml:"token"`
	Org                string `yaml:"org"`
	Bucket             string `yaml:"bucket"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
}

type Config struct {
	DB        DualDBCfg `yaml:"db"`
	Admin     AdminAuth `yaml:"admin"`
	TLSConfig TLSConfig `yaml:"tls"`
	Logging   Logging   `yaml:"logging"`
	License   common.LicenseCfg
	A         string `yaml:"a"`
}

// ====== 默认 DSN（当 DSN 为空时才生效） ======
func defaultSQLiteDSNs() (masterDSN, logDSN string) {
	base := "/var/lib/mlkmbp"
	if common.IsDesktop() {
		base = "./lib"
	}

	// === master：4K（v4 默认 cipher_page_size=4096）===
	m := url.Values{}
	m.Set("_pragma_cipher_compatibility", "4")
	m.Set("_pragma_kdf_iter", "256000")
	// 不显式设 cipher_page_size，使用 v4 默认 4096
	m.Set("_pragma_busy_timeout", "5000")
	m.Set("_pragma_journal_mode", "WAL")
	m.Set("_pragma_synchronous", "NORMAL")
	m.Set("_pragma_foreign_keys", "ON")

	// === log：32K 页，顺便把 SQLite page_size 对齐到 32768 ===
	l := url.Values{}
	l.Set("_pragma_cipher_compatibility", "4")
	l.Set("_pragma_kdf_iter", "256000")
	l.Set("_pragma_cipher_page_size", "32768")
	l.Set("_pragma_page_size", "32768")
	l.Set("_pragma_busy_timeout", "5000")
	l.Set("_pragma_journal_mode", "WAL")
	l.Set("_pragma_synchronous", "NORMAL")
	l.Set("_pragma_foreign_keys", "ON")

	master := filepath.ToSlash(filepath.Join(base, "master.db"))
	log := filepath.ToSlash(filepath.Join(base, "log.db"))

	return "file:" + master + "?" + m.Encode(),
		"file:" + log + "?" + l.Encode()
}

// ensureDirForFileDSN 确保 file:DSN 的目录存在（对相对/绝对路径都可）
func ensureDirForFileDSN(dsn string) error {
	if !strings.HasPrefix(dsn, "file:") {
		return nil
	}
	p := strings.TrimPrefix(dsn, "file:")
	if i := strings.IndexByte(p, '?'); i >= 0 {
		p = p[:i] // 去掉查询参数
	}
	dir := filepath.Dir(p)
	return os.MkdirAll(dir, 0o755)
}

var log = logx.New(logx.WithPrefix("config"))

func Load(p string) (*Config, string, error) {
	// 先读指定路径，失败则读 /etc/mlkmbp/config.yaml
	b, err := os.ReadFile(p)
	if err != nil {
		p = "/etc/mlkmbp/config.yaml"
		b, err = os.ReadFile(p)
		if err != nil {
			log.Errorf("open ./config/config.yaml: no such file or directory")
			return nil, p, err
		}
	}

	var c Config
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, p, err
	}

	// 两个库 driver 固定 sqlite，自定义驱动在 db 层指定（DriverName）
	c.DB.Master.Driver = "sqlite"
	c.DB.Log.Driver = "sqlite"
	masterDSN, logDSN := defaultSQLiteDSNs()
	c.DB.Master.DSN = masterDSN
	c.DB.Log.DSN = logDSN

	// 确保目录存在
	if err := ensureDirForFileDSN(c.DB.Master.DSN); err != nil {
		return nil, p, err
	}
	if err := ensureDirForFileDSN(c.DB.Log.DSN); err != nil {
		return nil, p, err
	}

	c.Admin.AdminIDs = []int{1}
	c.Admin.TokenTTL = 60 * 2
	if c.A != "" {
		ed25519, s, cfg := license.VerifyLicenseEd25519(c.A)
		if !ed25519 {
			return nil, p, errors.New("license invalid " + s)
		}
		c.License = *cfg
	}
	return &c, p, nil
}
