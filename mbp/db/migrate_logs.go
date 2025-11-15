package db

import (
	"fmt"
	"mlkmbp/mbp/model"
)

// EnsureTrafficLogTable：按日创建分表（完全 SQL，一次性建齐索引）
// day 示例："20250911"
func EnsureTrafficLogTable(d *DB, day string) error {
	tbl := model.TrafficTable(day)

	switch d.Driver {
	case "mysql":
		// MySQL：索引在 CREATE TABLE 内一次性写全
		create := fmt.Sprintf(`
CREATE TABLE IF NOT EXISTS %s (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  time BIGINT NOT NULL,
  username VARCHAR(255) NOT NULL,
  direction VARCHAR(8) NOT NULL,
  listen_addr VARCHAR(255),
  listen_port INT,
  protocol VARCHAR(20),
  up BIGINT,
  down BIGINT,
  dur BIGINT,
  source_addr VARCHAR(255),
  source_port INT,
  target_addr VARCHAR(255),
  target_port INT,
  KEY idx_%[1]s_time (time),
  KEY idx_%[1]s_user (username),
  KEY idx_%[1]s_user_time (username, time),
  KEY idx_%[1]s_listen (listen_addr, listen_port),
  KEY idx_%[1]s_listen_time (listen_addr, listen_port, time),
  KEY idx_%[1]s_target (target_addr, target_port),
  KEY idx_%[1]s_target_time (target_addr, target_port, time),
  KEY idx_%[1]s_source (source_addr, source_port),
  KEY idx_%[1]s_source_time (source_addr, source_port, time),
  KEY idx_%[1]s_proto_time (protocol, time),
  KEY idx_%[1]s_dir_time (direction, time),
  KEY idx_%[1]s_user_dir_time (username, direction, time),
  KEY idx_%[1]s_listen_dir_time (listen_addr, listen_port, direction, time),
  KEY idx_%[1]s_target_dir_time (target_addr, target_port, direction, time),
  KEY idx_%[1]s_source_dir_time (source_addr, source_port, direction, time),
  KEY idx_%[1]s_proto_dir_time (protocol, direction, time)
);`, tbl)
		return d.GormDataSource.Exec(create).Error

	case "sqlite", "sqlite3":
		// SQLite：先建表，再用 IF NOT EXISTS 建索引
		create := fmt.Sprintf(`
CREATE TABLE IF NOT EXISTS %s(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  time BIGINT NOT NULL,
  username TEXT NOT NULL,
  direction TEXT NOT NULL,
  listen_addr TEXT,
  listen_port INTEGER,
  protocol TEXT,
  up BIGINT,
  down BIGINT,
  dur BIGINT,
  source_addr TEXT,
  source_port INTEGER,
  target_addr TEXT,
  target_port INTEGER
);`, tbl)
		if err := d.GormDataSource.Exec(create).Error; err != nil {
			return err
		}

		idxes := []struct {
			name string
			cols string
		}{
			{fmt.Sprintf("idx_%s_time", tbl), "time"},
			{fmt.Sprintf("idx_%s_user", tbl), "username"},
			{fmt.Sprintf("idx_%s_user_time", tbl), "username, time"},
			{fmt.Sprintf("idx_%s_listen", tbl), "listen_addr, listen_port"},
			{fmt.Sprintf("idx_%s_listen_time", tbl), "listen_addr, listen_port, time"},
			{fmt.Sprintf("idx_%s_target", tbl), "target_addr, target_port"},
			{fmt.Sprintf("idx_%s_target_time", tbl), "target_addr, target_port, time"},
			{fmt.Sprintf("idx_%s_source", tbl), "source_addr, source_port"},
			{fmt.Sprintf("idx_%s_source_time", tbl), "source_addr, source_port, time"},
			{fmt.Sprintf("idx_%s_proto_time", tbl), "protocol, time"},
			{fmt.Sprintf("idx_%s_dir_time", tbl), "direction, time"},
			{fmt.Sprintf("idx_%s_user_dir_time", tbl), "username, direction, time"},
			{fmt.Sprintf("idx_%s_listen_dir_time", tbl), "listen_addr, listen_port, direction, time"},
			{fmt.Sprintf("idx_%s_target_dir_time", tbl), "target_addr, target_port, direction, time"},
			{fmt.Sprintf("idx_%s_source_dir_time", tbl), "source_addr, source_port, direction, time"},
			{fmt.Sprintf("idx_%s_proto_dir_time", tbl), "protocol, direction, time"},
		}
		for _, ix := range idxes {
			sql := fmt.Sprintf("CREATE INDEX IF NOT EXISTS %s ON %s(%s);", ix.name, tbl, ix.cols)
			if err := d.GormDataSource.Exec(sql).Error; err != nil {
				return err
			}
		}
		return nil

	default:
		return nil
	}
}
