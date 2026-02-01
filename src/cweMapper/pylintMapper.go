package cweMapper

import (
	"database/sql"
	"fmt"
	"sync"

	_ "modernc.org/sqlite"
)

type PylintMapper struct {
	pylintMappingPath string
	loadResult        []MapRecord
	db                *sql.DB
	mu                sync.Mutex // 添加互斥锁
	isConnected       bool       // 跟踪连接状态
}

func NewPylintMapper(pylintMappingPath string) *PylintMapper {
	return &PylintMapper{
		pylintMappingPath: pylintMappingPath,
		loadResult:        nil,
		db:                nil,
		isConnected:       false,
	}
}

// 初始化数据库连接（修复版本）
func (m *PylintMapper) initDB() error {
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
	m.db, err = sql.Open("sqlite", m.pylintMappingPath)
	if err != nil {
		return fmt.Errorf("初始化 pylint 预映射数据库失败: %w", err)
	}

	// 设置连接参数
	m.db.SetMaxOpenConns(1)
	m.db.SetMaxIdleConns(1)

	err = m.db.Ping()
	if err != nil {
		m.db.Close()
		m.db = nil
		return fmt.Errorf("pylint 预映射数据库连接失败: %w", err)
	}

	m.isConnected = true
	return nil
}

// 从 pylintMappingPath 数据库读取数据到内存 loadResult（修复版本）
func (m *PylintMapper) LoadMapping() error {
	// 初始化数据库连接
	err := m.initDB()
	if err != nil {
		return err
	}

	// 查询数据
	query := "SELECT message_id, cwe_id FROM pylint_cwe_mapping"
	rows, err := m.db.Query(query)
	if err != nil {
		return fmt.Errorf("pylint 预映射数据库内存加载失败: %w", err)
	}
	defer rows.Close()

	// 清空现有数据
	m.loadResult = nil

	// 遍历结果集
	var records []MapRecord
	for rows.Next() {
		var record MapRecord
		err := rows.Scan(&record.message_id, &record.cwe_id)
		if err != nil {
			return fmt.Errorf("pylint 加载结果集失败: %w", err)
		}
		records = append(records, record)
	}

	// 检查遍历过程中是否有错误
	if err = rows.Err(); err != nil {
		return fmt.Errorf("行错误: %w", err)
	}

	m.loadResult = records

	// 注意：不再自动关闭连接，保持连接打开供后续查询使用
	return nil
}

// 查询记录:根据 message_id 查询 cwe_id（修复版本）
func (m *PylintMapper) QueryRecord(message_id string) (string, error) {
	if !m.IsLoaded() {
		err := m.LoadMapping()
		if err != nil {
			return "", fmt.Errorf("加载映射失败: %v", err)
		}
	}

	// 线性搜索匹配的 message_id
	for _, record := range m.loadResult {
		if record.message_id == message_id {
			return record.cwe_id, nil
		}
	}

	// 未找到匹配项
	return "", nil
}

// 显式关闭连接的方法
func (m *PylintMapper) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.db != nil {
		err := m.db.Close()
		m.db = nil
		m.isConnected = false
		return err
	}
	return nil
}

// 检查映射是否已加载
func (m *PylintMapper) IsLoaded() bool {
	return m.loadResult != nil
}

// 调试使用，返回数据
func (m *PylintMapper) GetAllRecords() []MapRecord {
	return m.loadResult
}
