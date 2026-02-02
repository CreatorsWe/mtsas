package cweMapper

import (
	"database/sql"
	"fmt"
	"os"
	"sync"

	_ "modernc.org/sqlite" // 导入 SQLite 驱动

	. "github.com/mtsas/common"
)

type mapRecord struct {
	message_id string
	cwe_id     string
}

type CWEMapper struct {
	db_path     string
	toolMap     map[string]string      // 记录 工具名称与表名的映射
	loadResult  map[string][]mapRecord // 记录 工具名称与 record 的映射
	db          *sql.DB
	mu          sync.Mutex // 添加互斥锁
	isConnected bool       // 跟踪连接状态
}

func NewCWEMapper(_mappingPath string, _toolMaps map[string]string) (*CWEMapper, error) {
	// 检查 MappingPath 是否存在
	if _, err := os.Stat(_mappingPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("cwe 预映射库不存在: %s", _mappingPath)
	}

	mapper := &CWEMapper{
		db_path:     _mappingPath,
		toolMap:     _toolMaps,
		loadResult:  make(map[string][]mapRecord),
		db:          nil,
		isConnected: false,
	}

	// 初始化数据库连接
	if err := mapper.initDB(); err != nil {
		return nil, fmt.Errorf("初始化数据库连接失败: %v", err)
	}

	return mapper, nil
}

// 初始化数据库连接（修复版本）
func (m *CWEMapper) initDB() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.db != nil && m.isConnected {
		// 检查连接是否仍然有效
		if err := m.db.Ping(); err == nil {
			return nil // 连接仍然有效
		}
		// 连接已失效，需要重新连接
		m.db.Close()
		m.db = nil
		m.isConnected = false
	}

	var err error
	m.db, err = sql.Open("sqlite", m.db_path)
	if err != nil {
		return fmt.Errorf("初始化 CWE 映射数据库失败: %w", err)
	}

	// 设置连接参数
	m.db.SetMaxOpenConns(1)
	m.db.SetMaxIdleConns(1)

	err = m.db.Ping()
	if err != nil {
		m.db.Close()
		m.db = nil
		return fmt.Errorf("CWE 映射数据库连接失败: %w", err)
	}

	m.isConnected = true
	return nil
}

// 查询记录:在指定工具映射表中根据 message_id 查询 cwe_id（改进版本）
func (m *CWEMapper) QueryRecord(toolName string, message_id string) (string, error) {
	if !m.IsLoaded(toolName) {
		err := m.loadToolMapping(toolName)
		if err != nil {
			return "", fmt.Errorf("加载工具 %s 的映射失败: %v", toolName, err)
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	if records, exists := m.loadResult[toolName]; exists {
		for _, record := range records {
			if record.message_id == message_id {
				ConsoleLogger.Info(fmt.Sprintf("cweMapper 查询: %s message_id: %s 匹配 cwe_id: %s", toolName, message_id, record.cwe_id))
				return record.cwe_id, nil
			}
		}
		// 加载后仍然没有找到
		return "", nil
	}

	return "", fmt.Errorf("工具 %s 的映射加载后仍然不可用", toolName)
}

// 加载单个工具的映射（内部方法）
func (m *CWEMapper) loadToolMapping(toolName string) error {
	// 检查表是否存在
	tableName, exists := m.toolMap[toolName]
	if !exists {
		return fmt.Errorf("配置文件为定义工具 %s 的映射表路径", toolName)
	}
	tableExistsQuery := "SELECT name FROM sqlite_master WHERE type='table' AND name=?"
	var existingTable string
	err := m.db.QueryRow(tableExistsQuery, tableName).Scan(&existingTable)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("表 %s 不存在", tableName)
		}
		return fmt.Errorf("检查表存在性失败: %v", err)
	}

	// 查询数据
	query := fmt.Sprintf("SELECT message_id, cwe_id FROM %s", tableName)
	rows, err := m.db.Query(query)
	if err != nil {
		return fmt.Errorf("查询表 %s 失败: %v", tableName, err)
	}
	defer rows.Close()

	var records []mapRecord
	var count int
	for rows.Next() {
		var record mapRecord
		err := rows.Scan(&record.message_id, &record.cwe_id)
		if err != nil {
			return fmt.Errorf("扫描行数据失败: %v", err)
		}
		records = append(records, record)
		count++
	}

	if err = rows.Err(); err != nil {
		return fmt.Errorf("行迭代错误: %v", err)
	}

	ConsoleLogger.Info(fmt.Sprintf("cweMapper 加载工具 %s 预映射数据 %d 条", toolName, count))

	m.loadResult[toolName] = records
	return nil
}

// 显式关闭连接的方法
func (m *CWEMapper) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.db != nil {
		err := m.db.Close()
		m.db = nil
		m.isConnected = false
		m.loadResult = make(map[string][]mapRecord) // 清空内存数据
		return err
	}
	return nil
}

// 检查指定工具的映射是否已加载
func (m *CWEMapper) IsLoaded(toolName string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.loadResult[toolName] != nil {
		return true
	}
	return false
}

// 调试使用，返回数据
func (m *CWEMapper) GetAllRecords() map[string][]mapRecord {
	return m.loadResult
}
