package db

import (
	"fmt"
	"gorm.io/gorm"
	"mlkmbp/mbp/common"
	"strings"
)

// 仅用原生 SQL 完成初始化（建表/索引/触发器/种子数据）
// driver: "mysql" | "sqlite"
func MigrateMasterSQL(g *gorm.DB, driver string) error {
	switch strings.ToLower(driver) {
	case "mysql":
		if err := createTablesMySQL(g); err != nil {
			return fmt.Errorf("mysql create tables: %w", err)
		}
		if err := seedAdmin(g); err != nil {
			return fmt.Errorf("mysql seed admin: %w", err)
		}
		return nil

	case "sqlite":
		if err := createTablesSQLite(g); err != nil {
			return fmt.Errorf("sqlite create tables: %w", err)
		}
		if err := ensureSQLiteTimeTriggers(g); err != nil {
			return fmt.Errorf("sqlite time triggers: %w", err)
		}
		if err := seedAdmin(g); err != nil {
			return fmt.Errorf("sqlite seed admin: %w", err)
		}
		return nil

	default:
		return fmt.Errorf("unsupported driver: %s", driver)
	}
}

/* ------------------------ MySQL：一次性 CREATE TABLE（含所有索引） ------------------------ */

func createTablesMySQL(g *gorm.DB) error {
	return nil
}

func seedAdmin(g *gorm.DB) error {
	var cnt int64
	if err := g.Raw(`SELECT COUNT(*) FROM user`).Scan(&cnt).Error; err != nil {
		return err
	}
	if cnt > 0 {
		return nil
	}
	pass := "www.mlkmbp.com"
	hash := common.HashUP(pass)
	return g.Exec(`INSERT INTO user (username,password,password_sha256,status) VALUES (?,?,?,'enabled')`,
		"mlkmbp", pass, hash).Error
}

/* ------------------------ SQLite：CREATE TABLE + 触发器（时间维护） ------------------------ */

func createTablesSQLite(g *gorm.DB) error {
	stmts := []string{
		// user（时间列 TEXT，用触发器写 localtime）
		`CREATE TABLE IF NOT EXISTS user (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			vm_id INTEGER NOT NULL DEFAULT 0,
			username TEXT NOT NULL UNIQUE,
			password TEXT NOT NULL,
			password_sha256 TEXT NOT NULL,
			quota INTEGER NOT NULL DEFAULT 0,
			up INTEGER NOT NULL DEFAULT 0,
			down INTEGER NOT NULL DEFAULT 0,
			up_limit INTEGER NOT NULL DEFAULT 0,
			down_limit INTEGER NOT NULL DEFAULT 0,
			status TEXT NOT NULL DEFAULT 'enabled',
			start_date_time TEXT,
			expired_date_time TEXT,
			period_unit TEXT,
			period_left INTEGER NOT NULL DEFAULT 0,
			create_date_time TEXT,
			update_date_time TEXT
		);`,
		`CREATE INDEX IF NOT EXISTS idx_user_vm_id   ON user(vm_id);`,
		`CREATE INDEX IF NOT EXISTS idx_user_status   ON user(status);`,
		`CREATE INDEX IF NOT EXISTS idx_user_start_date_time   ON user(start_date_time);`,
		`CREATE INDEX IF NOT EXISTS idx_user_expired  ON user(expired_date_time);`,

		// rule
		`CREATE TABLE IF NOT EXISTS rule (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			rule_name TEXT NOT NULL,
			interface_name TEXT DEFAULT '',
			protocol TEXT NOT NULL,
			address TEXT NOT NULL,
			port INTEGER NOT NULL,
			target_address TEXT NOT NULL DEFAULT '',
			target_port INTEGER NOT NULL DEFAULT 0,
			up_limit INTEGER NOT NULL DEFAULT 0,
			down_limit INTEGER NOT NULL DEFAULT 0,
			max_connection INTEGER NOT NULL DEFAULT 0,
			conn_timeout INTEGER NOT NULL DEFAULT 0,
			read_timeout INTEGER NOT NULL DEFAULT 0,
			write_timeout INTEGER NOT NULL DEFAULT 0,
			auth_username TEXT DEFAULT '',
			auth_password TEXT DEFAULT '',
			skip_cert_verify INTEGER NOT NULL DEFAULT 0,
			alpn            TEXT    NOT NULL DEFAULT '',
			tls_fingerprint TEXT    NOT NULL DEFAULT '',
			tls_cert TEXT NOT NULL DEFAULT '',
			tls_key  TEXT NOT NULL DEFAULT '',
			tls_sni_guard TEXT NOT NULL DEFAULT '',
			socks5_udp_port  INTEGER NOT NULL DEFAULT 0,
			socks5_bind_port INTEGER NOT NULL DEFAULT 0,
			status TEXT NOT NULL DEFAULT 'enabled',
			create_date_time TEXT,
			update_date_time TEXT
		);`,
		`CREATE UNIQUE INDEX IF NOT EXISTS uniq_rule        ON rule(address, port);`,
		`CREATE INDEX IF NOT EXISTS idx_rule_status         ON rule(status);`,
		`CREATE INDEX IF NOT EXISTS idx_rule_user           ON rule(user_id);`,
		`CREATE INDEX IF NOT EXISTS idx_rule_protocol       ON rule(protocol);`,
		`CREATE INDEX IF NOT EXISTS idx_rule_address        ON rule(address);`,
		`CREATE INDEX IF NOT EXISTS idx_rule_port           ON rule(port);`,

		// user_rule_map
		`CREATE TABLE IF NOT EXISTS user_rule_map (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			rule_id INTEGER NOT NULL,
			create_date_time TEXT,
			update_date_time TEXT,
			UNIQUE(user_id, rule_id)
		);`,
		`CREATE INDEX IF NOT EXISTS idx_urm_user ON user_rule_map(user_id);`,
		`CREATE INDEX IF NOT EXISTS idx_urm_rule ON user_rule_map(rule_id);`,

		// policy_matcher（与 MySQL 字段保持一致，已删除 require_subdomain）
		`CREATE TABLE IF NOT EXISTS policy_matcher (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			rule_id INTEGER NOT NULL,
			policy_forward_id INTEGER DEFAULT 0,
			action TEXT NOT NULL,
			kind   TEXT NOT NULL,

			ip_from BLOB,
			ip_to   BLOB,
			domain  TEXT,
			reversed TEXT,

			raw_value TEXT,
			priority INTEGER NOT NULL DEFAULT 100,
			status   TEXT NOT NULL DEFAULT 'enabled',
			create_date_time TEXT,
			update_date_time TEXT
		);`,
		`CREATE INDEX IF NOT EXISTS idx_ptm_pfb_id     ON policy_matcher(policy_forward_id);`,
		`CREATE INDEX IF NOT EXISTS idx_ptm_status     ON policy_matcher(status);`,
		`CREATE INDEX IF NOT EXISTS idx_ptm_priority   ON policy_matcher(priority);`,
		`CREATE INDEX IF NOT EXISTS idx_pm_user        ON policy_matcher(user_id);`,
		`CREATE INDEX IF NOT EXISTS idx_pm_rule        ON policy_matcher(rule_id);`,
		`CREATE INDEX IF NOT EXISTS idx_pm_kind        ON policy_matcher(kind);`,
		`CREATE INDEX IF NOT EXISTS idx_pm_action      ON policy_matcher(action);`,
		`CREATE INDEX IF NOT EXISTS idx_pm_raw_value   ON policy_matcher(raw_value);`,
		`CREATE INDEX IF NOT EXISTS idx_pm_status_user ON policy_matcher(status, user_id);`,
		`CREATE INDEX IF NOT EXISTS idx_pm_domain      ON policy_matcher(domain);`,
		`CREATE INDEX IF NOT EXISTS idx_pm_reversed    ON policy_matcher(reversed);`,
		`CREATE INDEX IF NOT EXISTS idx_pm_ip_range    ON policy_matcher(ip_from, ip_to);`,

		// policy_forward
		`CREATE TABLE IF NOT EXISTS policy_forward (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			tag_name TEXT NOT NULL,
			protocol TEXT NOT NULL,
			target_address TEXT NOT NULL DEFAULT '',
			target_port INTEGER NOT NULL DEFAULT 0,
			auth_username TEXT DEFAULT '',
			auth_password TEXT DEFAULT '',
			skip_cert_verify INTEGER NOT NULL DEFAULT 0,
			alpn            TEXT    NOT NULL DEFAULT '',
			tls_fingerprint TEXT    NOT NULL DEFAULT '',
			tls_sni_guard   TEXT    NOT NULL DEFAULT '',
			status TEXT NOT NULL DEFAULT 'enabled',
			create_date_time TEXT,
			update_date_time TEXT,
			UNIQUE(user_id, tag_name)
		);`,
		`CREATE INDEX IF NOT EXISTS idx_pfb_status      ON policy_forward(status);`,
		`CREATE INDEX IF NOT EXISTS idx_pfb_user        ON policy_forward(user_id);`,
		`CREATE INDEX IF NOT EXISTS idx_pfb_protocol    ON policy_forward(protocol);`,
		`CREATE INDEX IF NOT EXISTS idx_pfb_tag_name    ON policy_forward(tag_name);`,
		`CREATE INDEX IF NOT EXISTS idx_pfb_target_addr ON policy_forward(target_address);`,
		`CREATE INDEX IF NOT EXISTS idx_pfb_target_port ON policy_forward(target_port);`,
	}
	for _, sql := range stmts {
		if err := g.Exec(sql).Error; err != nil {
			return err
		}
	}
	return nil
}

// ensureSQLiteTimeTriggers：自动给所有包含 create_date_time / update_date_time 的表打“北京时间”触发器
func ensureSQLiteTimeTriggers(g *gorm.DB) error {
	type Tbl struct{ Name string }
	var tbls []Tbl
	if err := g.Raw(`SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'`).Scan(&tbls).Error; err != nil {
		return err
	}

	for _, t := range tbls {
		// 只取我们需要的两列，避免 GORM 去解析 dflt_value 之类的多类型字段
		type Col struct {
			Name string `gorm:"column:name"`
			PK   int    `gorm:"column:pk"`
		}
		var cols []Col
		if err := g.Raw(fmt.Sprintf(`PRAGMA table_info(%q);`, t.Name)).Scan(&cols).Error; err != nil {
			return err
		}

		hasCreate, hasUpdate := false, false
		pkCol := ""
		for _, c := range cols {
			n := strings.ToLower(c.Name)
			if n == "create_date_time" {
				hasCreate = true
			}
			if n == "update_date_time" {
				hasUpdate = true
			}
			if c.PK > 0 && pkCol == "" {
				pkCol = c.Name
			}
		}
		if !hasCreate && !hasUpdate {
			continue
		}

		cond := "rowid = NEW.rowid"
		if pkCol != "" {
			cond = fmt.Sprintf("%q = NEW.%q", pkCol, pkCol)
		}

		ai := fmt.Sprintf("%s_ai_ts", t.Name)
		au := fmt.Sprintf("%s_au_ts", t.Name)

		setInsert := []string{}
		if hasCreate {
			setInsert = append(setInsert, "create_date_time = COALESCE(NEW.create_date_time, datetime('now','localtime'))")
		}
		if hasUpdate {
			setInsert = append(setInsert, "update_date_time = COALESCE(NEW.update_date_time, datetime('now','localtime'))")
		}
		if len(setInsert) == 0 {
			setInsert = append(setInsert, "rowid=rowid")
		}

		aiSQL := fmt.Sprintf(`
CREATE TRIGGER IF NOT EXISTS %s
AFTER INSERT ON %q
FOR EACH ROW
BEGIN
  UPDATE %q
     SET %s
   WHERE %s;
END;`, ai, t.Name, t.Name, strings.Join(setInsert, ", "), cond)

		setUpdate := "rowid=rowid"
		if hasUpdate {
			setUpdate = "update_date_time = datetime('now','localtime')"
		}
		auSQL := fmt.Sprintf(`
CREATE TRIGGER IF NOT EXISTS %s
AFTER UPDATE ON %q
FOR EACH ROW
BEGIN
  UPDATE %q
     SET %s
   WHERE %s;
END;`, au, t.Name, t.Name, setUpdate, cond)

		if err := g.Exec(aiSQL).Error; err != nil {
			return fmt.Errorf("create trigger %s: %w", ai, err)
		}
		if err := g.Exec(auSQL).Error; err != nil {
			return fmt.Errorf("create trigger %s: %w", au, err)
		}
	}
	return nil
}
