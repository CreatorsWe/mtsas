package dbManager

import (
	"database/sql"
	"fmt"

	. "github.com/mtsas/common"
	_ "modernc.org/sqlite"
)

// DbManager 数据库管理结构体，封装sqlite3操作
type DbManager struct {
	db *sql.DB
}

// NewDbManager 初始化数据库连接并创建表
func NewDbManager(dbPath string) (*DbManager, error) {
	// 打开sqlite3数据库（不存在则自动创建）
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("打开数据库失败: %w", err)
	}

	// 验证连接
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("数据库连接失败: %w", err)
	}

	// 创建表结构（层级化存储UnifiedVulnerability的嵌套字段）
	createTableSQL := `
	CREATE TABLE IF NOT EXISTS db_vulnerabilities (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		hash TEXT,
		scope_offset_id TEXT NOT NULL,
		optimal_scope_start INTEGER NOT NULL,
		optimal_scope_end INTEGER NOT NULL,
		warning_count INTEGER NOT NULL,
		tool TEXT NOT NULL,
		warning_id TEXT NOT NULL,
		category TEXT NOT NULL,
		short_message TEXT NOT NULL,
		cwe_id TEXT,
		file_path TEXT NOT NULL,
		range_start_line INTEGER NOT NULL,
		range_end_line INTEGER NOT NULL,
		range_start_column INTEGER NOT NULL,
		range_end_column INTEGER NOT NULL,
		severity_level TEXT NOT NULL,
		confidence_level TEXT NOT NULL
	);`

	_, err = db.Exec(createTableSQL)
	if err != nil {
		return nil, fmt.Errorf("创建表失败: %w", err)
	}

	return &DbManager{db: db}, nil
}

// Close 关闭数据库连接
func (m *DbManager) Close() error {
	return m.db.Close()
}

// InsertVulnerability 插入漏洞数据
func (m *DbManager) InsertVulnerability(dbVuln DbVulnerability) (int64, error) {
	insertSQL := `
	INSERT INTO db_vulnerabilities (
		hash, scope_offset_id, optimal_scope_start, optimal_scope_end,warning_count,
		tool, warning_id, category, short_message, cwe_id, file_path,
		range_start_line, range_end_line, range_start_column, range_end_column,
		severity_level, confidence_level
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);`

	result, err := m.db.Exec(
		insertSQL,
		dbVuln.Hash,
		dbVuln.ScopeOffsetID,
		dbVuln.OptimalScope.Start,
		dbVuln.OptimalScope.End,
		dbVuln.Vulnerabilities.Tool,
		dbVuln.Vulnerabilities.WarningID,
		dbVuln.Vulnerabilities.Category,
		dbVuln.Vulnerabilities.ShortMessage,
		dbVuln.Vulnerabilities.CWEID,
		dbVuln.Vulnerabilities.FilePath,
		dbVuln.Vulnerabilities.Range.StartLine.Int(),
		dbVuln.Vulnerabilities.Range.EndLine.Int(),
		dbVuln.Vulnerabilities.Range.StartColumn.Int(),
		dbVuln.Vulnerabilities.Range.EndColumn.Int(),
		dbVuln.Vulnerabilities.SeverityLevel,
		dbVuln.Vulnerabilities.ConfidenceLevel,
	)
	if err != nil {
		return 0, fmt.Errorf("插入数据失败: %w", err)
	}

	// 返回自增主键ID
	id, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("获取自增ID失败: %w", err)
	}
	return id, nil
}

// QueryHasNonEmptyHash 查询hash不为空的条目
func (m *DbManager) QueryHasNonEmptyHash() ([]DbVulnerability, error) {
	querySQL := `
	SELECT
		id, hash, scope_offset_id, optimal_scope_start, optimal_scope_end,warning_count,
		tool, warning_id, category, short_message, cwe_id, file_path,
		range_start_line, range_end_line, range_start_column, range_end_column,
		severity_level, confidence_level
	FROM db_vulnerabilities
	WHERE hash IS NOT NULL AND hash != '';`

	rows, err := m.db.Query(querySQL)
	if err != nil {
		return nil, fmt.Errorf("查询hash非空数据失败: %w", err)
	}
	defer rows.Close()

	return scanDbVulnerabilities(rows)
}

// QueryHasEmptyHash 查询hash为空的条目
func (m *DbManager) QueryHasEmptyHash() ([]DbVulnerability, error) {
	querySQL := `
	SELECT
		id, hash, scope_offset_id, optimal_scope_start, optimal_scope_end,warning_count,
		tool, warning_id, category, short_message, cwe_id, file_path,
		range_start_line, range_end_line, range_start_column, range_end_column,
		severity_level, confidence_level
	FROM db_vulnerabilities
	WHERE hash IS NULL OR hash = '';`

	rows, err := m.db.Query(querySQL)
	if err != nil {
		return nil, fmt.Errorf("查询hash为空数据失败: %w", err)
	}
	defer rows.Close()

	return scanDbVulnerabilities(rows)
}

// BatchInsertVulnerabilities 批量插入漏洞数据（高性能版）
// 入参：漏洞切片
// 出参：成功插入的条目数、自增ID切片（按入参顺序）、错误信息
func (m *DbManager) BatchInsertVulnerabilities(vulns []DbVulnerability) (int, []int64, error) {
	// 空切片直接返回
	if len(vulns) == 0 {
		return 0, nil, fmt.Errorf("批量插入的漏洞数据不能为空")
	}

	// 1. 开启事务（核心优化点：批量操作必须在事务中执行）
	tx, err := m.db.Begin()
	if err != nil {
		return 0, nil, fmt.Errorf("开启事务失败: %w", err)
	}
	// 延迟处理事务回滚/提交
	defer func() {
		if r := recover(); r != nil {
			_ = tx.Rollback()
		}
	}()

	// 2. 预处理插入语句（核心优化点：避免重复编译SQL）
	insertSQL := `
	INSERT INTO db_vulnerabilities (
		hash, scope_offset_id, optimal_scope_start, optimal_scope_end,warning_count,
		tool, warning_id, category, short_message, cwe_id, file_path,
		range_start_line, range_end_line, range_start_column, range_end_column,
		severity_level, confidence_level
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);`

	stmt, err := tx.Prepare(insertSQL)
	if err != nil {
		_ = tx.Rollback()
		return 0, nil, fmt.Errorf("预处理SQL失败: %w", err)
	}
	defer stmt.Close()

	// 3. 循环执行批量插入
	insertedCount := 0
	ids := make([]int64, 0, len(vulns)) // 预分配切片容量，减少内存分配
	for _, vuln := range vulns {
		result, err := stmt.Exec(
			vuln.Hash,
			vuln.ScopeOffsetID,
			vuln.OptimalScope.Start,
			vuln.OptimalScope.End,
			vuln.WarningCount,
			vuln.Vulnerabilities.Tool,
			vuln.Vulnerabilities.WarningID,
			vuln.Vulnerabilities.Category,
			vuln.Vulnerabilities.ShortMessage,
			vuln.Vulnerabilities.CWEID,
			vuln.Vulnerabilities.FilePath,
			vuln.Vulnerabilities.Range.StartLine.Int(),
			vuln.Vulnerabilities.Range.EndLine.Int(),
			vuln.Vulnerabilities.Range.StartColumn.Int(),
			vuln.Vulnerabilities.Range.EndColumn.Int(),
			vuln.Vulnerabilities.SeverityLevel,
			vuln.Vulnerabilities.ConfidenceLevel,
		)
		if err != nil {
			_ = tx.Rollback()
			return insertedCount, ids, fmt.Errorf("插入第%d条数据失败: %w", insertedCount+1, err)
		}

		// 获取当前条目的自增ID
		id, err := result.LastInsertId()
		if err != nil {
			_ = tx.Rollback()
			return insertedCount, ids, fmt.Errorf("获取第%d条数据ID失败: %w", insertedCount+1, err)
		}

		insertedCount++
		ids = append(ids, id)
	}

	// 4. 提交事务
	if err := tx.Commit(); err != nil {
		return insertedCount, ids, fmt.Errorf("提交事务失败: %w", err)
	}

	return insertedCount, ids, nil
}

// UpdateCWEIDAndHash 更新指定ID条目的cwe_id和hash值
func (m *DbManager) UpdateCWEIDAndHash(id int64, newCWEID, newHash string) error {
	updateSQL := `
	UPDATE db_vulnerabilities
	SET cwe_id = ?, hash = ?
	WHERE id = ?;`

	result, err := m.db.Exec(updateSQL, newCWEID, newHash, id)
	if err != nil {
		return fmt.Errorf("更新数据失败: %w", err)
	}

	// 检查是否有行被更新
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("检查更新行数失败: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("未找到ID为%d的条目", id)
	}

	return nil
}

// DeleteVulnerability 删除指定ID的条目
func (m *DbManager) DeleteVulnerability(id int64) error {
	deleteSQL := `DELETE FROM db_vulnerabilities WHERE id = ?;`

	result, err := m.db.Exec(deleteSQL, id)
	if err != nil {
		return fmt.Errorf("删除数据失败: %w", err)
	}

	// 检查是否有行被删除
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("检查删除行数失败: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("未找到ID为%d的条目", id)
	}

	return nil
}

// scanDbVulnerabilities 通用行扫描函数，将查询结果转为DbVulnerability切片
func scanDbVulnerabilities(rows *sql.Rows) ([]DbVulnerability, error) {
	var vulns []DbVulnerability

	for rows.Next() {
		var (
			id                int64
			hash              sql.NullString
			scopeOffsetID     string
			optimalScopeStart int
			optimalScopeEnd   int
			warningCount      int
			tool              string
			warningID         string
			category          string
			shortMessage      string
			cweID             sql.NullString
			filePath          string
			rangeStartLine    int
			rangeEndLine      int
			rangeStartColumn  int
			rangeEndColumn    int
			severityLevel     string
			confidenceLevel   string
		)

		// 扫描行数据到变量
		err := rows.Scan(
			&id, &hash, &scopeOffsetID, &optimalScopeStart, &optimalScopeEnd, &warningCount,
			&tool, &warningID, &category, &shortMessage, &cweID, &filePath,
			&rangeStartLine, &rangeEndLine, &rangeStartColumn, &rangeEndColumn,
			&severityLevel, &confidenceLevel,
		)
		if err != nil {
			return nil, fmt.Errorf("扫描行数据失败: %w", err)
		}

		// 构造DbVulnerability结构体
		dbVuln := DbVulnerability{
			Hash:          hash.String, // sql.NullString自动处理null值
			ScopeOffsetID: scopeOffsetID,
			OptimalScope: ScopeRange{
				Start: optimalScopeStart,
				End:   optimalScopeEnd,
			},
			WarningCount: warningCount,
			Vulnerabilities: UnifiedVulnerability{
				Tool:         tool,
				WarningID:    warningID,
				Category:     category,
				ShortMessage: shortMessage,
				CWEID:        cweID.String, // 空值自动转为""
				FilePath:     filePath,
				Range: Range{
					StartLine:   NullableInt(rangeStartLine),
					EndLine:     NullableInt(rangeEndLine),
					StartColumn: NullableInt(rangeStartColumn),
					EndColumn:   NullableInt(rangeEndColumn),
				},
				SeverityLevel:   SeverityLevel(severityLevel),
				ConfidenceLevel: ConfidenceLevel(confidenceLevel),
			},
		}

		vulns = append(vulns, dbVuln)
	}

	// 检查行遍历过程中的错误
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("遍历行数据失败: %w", err)
	}

	return vulns, nil
}

// 辅助函数：将DbVulnerability转为JSON字符串（可选）
func (m *DbManager) GetVulnerabilityByID(id int64) (DbVulnerability, error) {
	querySQL := `
	SELECT
		id, hash, scope_offset_id, optimal_scope_start, optimal_scope_end,warning_count,
		tool, warning_id, category, short_message, cwe_id, file_path,
		range_start_line, range_end_line, range_start_column, range_end_column,
		severity_level, confidence_level
	FROM db_vulnerabilities
	WHERE id = ?;`

	row := m.db.QueryRow(querySQL, id)

	var (
		dbVuln            DbVulnerability
		hash              sql.NullString
		scopeOffsetID     string
		optimalScopeStart int
		optimalScopeEnd   int
		warningCount      int
		tool              string
		warningID         string
		category          string
		shortMessage      string
		cweID             sql.NullString
		filePath          string
		rangeStartLine    int
		rangeEndLine      int
		rangeStartColumn  int
		rangeEndColumn    int
		severityLevel     string
		confidenceLevel   string
	)

	err := row.Scan(
		&id, &hash, &scopeOffsetID, &optimalScopeStart, &optimalScopeEnd, &warningCount,
		&tool, &warningID, &category, &shortMessage, &cweID, &filePath,
		&rangeStartLine, &rangeEndLine, &rangeStartColumn, &rangeEndColumn,
		&severityLevel, &confidenceLevel,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return dbVuln, fmt.Errorf("未找到ID为%d的条目", id)
		}
		return dbVuln, fmt.Errorf("查询指定ID数据失败: %w", err)
	}

	dbVuln = DbVulnerability{
		Hash:          hash.String,
		ScopeOffsetID: scopeOffsetID,
		OptimalScope: ScopeRange{
			Start: optimalScopeStart,
			End:   optimalScopeEnd,
		},
		WarningCount: warningCount,
		Vulnerabilities: UnifiedVulnerability{
			Tool:         tool,
			WarningID:    warningID,
			Category:     category,
			ShortMessage: shortMessage,
			CWEID:        cweID.String,
			FilePath:     filePath,
			Range: Range{
				StartLine:   NullableInt(rangeStartLine),
				EndLine:     NullableInt(rangeEndLine),
				StartColumn: NullableInt(rangeStartColumn),
				EndColumn:   NullableInt(rangeEndColumn),
			},
			SeverityLevel:   SeverityLevel(severityLevel),
			ConfidenceLevel: ConfidenceLevel(confidenceLevel),
		},
	}

	return dbVuln, nil
}
