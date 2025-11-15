package dao

import (
	"context"
	"database/sql"
	"mlkmbp/mbp/db"
	"mlkmbp/mbp/model"
)

// 返回最多 3 条候选（IP/CIDR 一条、domain_exact 一条、domain_suffix 一条）
func QueryPolicyCandidates(
	ctx context.Context,
	fwdDB *db.DB,
	uid, gid, ruleId int64,
	ipOK int, ip16 []byte,
	hostOK int, hostNorm, revHost string,
) ([]model.PolicyMatcher, error) {
	var sqlText string
	switch fwdDB.Driver {
	case "mysql":
		sqlText = mysqlUnionSQLWithRule
	default: // sqlite 等
		sqlText = sqliteUnionSQLWithRule

	}

	var rows []model.PolicyMatcher
	err := fwdDB.GormDataSource.WithContext(ctx).Raw(sqlText,
		sql.Named("uid", uid),
		sql.Named("gid", gid),
		sql.Named("rule_id", ruleId),
		sql.Named("ip_ok", ipOK),
		sql.Named("ip16", ip16),
		sql.Named("host_ok", hostOK),
		sql.Named("host_norm", hostNorm),
		sql.Named("rev_host", revHost),
	).Scan(&rows).Error
	return rows, err
}

/* ---------- MySQL：限定 ruleId ---------- */
const mysqlUnionSQLWithRule = `
SELECT * FROM (
  SELECT pm.*
  FROM policy_matcher pm
  WHERE :ip_ok=1
    AND pm.status='enabled'
    AND pm.user_id IN (:uid,:gid)
    AND pm.rule_id = :rule_id
    AND pm.kind IN ('ip','cidr')
    AND pm.ip_from <= :ip16 AND :ip16 <= pm.ip_to
  ORDER BY (pm.user_id=:uid) DESC, pm.priority DESC, pm.id DESC
  LIMIT 1
) AS t_ip
UNION ALL
SELECT * FROM (
  SELECT pm.*
  FROM policy_matcher pm
  WHERE :host_ok=1
    AND pm.status='enabled'
    AND pm.user_id IN (:uid,:gid)
    AND pm.rule_id = :rule_id
    AND pm.kind='domain_exact'
    AND pm.domain=:host_norm
  ORDER BY (pm.user_id=:uid) DESC, pm.priority DESC, pm.id DESC
  LIMIT 1
) AS t_exact
UNION ALL
SELECT * FROM (
  SELECT pm.*
  FROM policy_matcher pm
  WHERE :host_ok=1
    AND pm.status='enabled'
    AND pm.user_id IN (:uid,:gid)
    AND pm.rule_id = :rule_id
    AND pm.kind='domain_suffix'
    AND :rev_host LIKE CONCAT(pm.reversed, '%')
  ORDER BY (pm.user_id=:uid) DESC, pm.priority DESC, pm.id DESC
  LIMIT 1
) AS t_suffix
`

/* ---------- SQLite：限定 ruleId ---------- */
const sqliteUnionSQLWithRule = `
SELECT * FROM (
  SELECT pm.*
  FROM policy_matcher pm
  WHERE :ip_ok=1
    AND pm.status='enabled'
    AND pm.user_id IN (:uid,:gid)
    AND pm.rule_id = :rule_id
    AND pm.kind IN ('ip','cidr')
    AND pm.ip_from <= :ip16 AND :ip16 <= pm.ip_to
  ORDER BY (pm.user_id=:uid) DESC, pm.priority DESC, pm.id DESC
  LIMIT 1
) AS t_ip
UNION ALL
SELECT * FROM (
  SELECT pm.*
  FROM policy_matcher pm
  WHERE :host_ok=1
    AND pm.status='enabled'
    AND pm.user_id IN (:uid,:gid)
    AND pm.rule_id = :rule_id
    AND pm.kind='domain_exact'
    AND pm.domain=:host_norm
  ORDER BY (pm.user_id=:uid) DESC, pm.priority DESC, pm.id DESC
  LIMIT 1
) AS t_exact
UNION ALL
SELECT * FROM (
  SELECT pm.*
  FROM policy_matcher pm
  WHERE :host_ok=1
    AND pm.status='enabled'
    AND pm.user_id IN (:uid,:gid)
    AND pm.rule_id = :rule_id
    AND pm.kind='domain_suffix'
    AND :rev_host LIKE pm.reversed || '%'
  ORDER BY (pm.user_id=:uid) DESC, pm.priority DESC, pm.id DESC
  LIMIT 1
) AS t_suffix
`
