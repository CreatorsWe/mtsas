package common

import (
	"encoding/json"
	"fmt"
	"strconv"
)

// 第一步：定义自定义类型（基于int）
type NullableInt int

// 第二步：实现json.Unmarshaler接口（反序列化逻辑）
// 规则：
// - JSON null → -1
// - JSON number（int/float）→ 对应int值
// - JSON string（数字字符串）→ 转为int值
// - 非法值 → 报错
func (n *NullableInt) UnmarshalJSON(data []byte) error {
	// 1. 处理JSON null
	if string(data) == "null" {
		*n = NullableInt(-1)
		return nil
	}

	// 2. 尝试解析为JSON number（优先处理）
	var num float64 // JSON number默认解析为float64
	if err := json.Unmarshal(data, &num); err == nil {
		*n = NullableInt(num)
		return nil
	}

	// 3. 尝试解析为JSON string（数字字符串）
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return fmt.Errorf("NullableInt反序列化失败：不支持的类型（数据：%s）", string(data))
	}

	// 空字符串按null处理，映射为-1
	if str == "" {
		*n = NullableInt(-1)
		return nil
	}

	// 字符串转int
	numInt, err := strconv.Atoi(str)
	if err != nil {
		return fmt.Errorf("NullableInt字符串转int失败：%s（数据：%s）", err.Error(), str)
	}
	*n = NullableInt(numInt)
	return nil
}

// 第三步：实现json.Marshaler接口（序列化逻辑）
// 规则：
// - Go值为-1 → JSON null
// - 其他值 → JSON number（int类型）
func (n NullableInt) MarshalJSON() ([]byte, error) {
	if n == NullableInt(-1) {
		return []byte("null"), nil // 直接返回 null 的JSON字面量
	}
	// 转为int后序列化（确保输出是number类型）
	return json.Marshal(int(n))
}

// 可选：封装类型转换方法，方便业务代码使用
func (n NullableInt) Int() int {
	return int(n)
}

// Range 统一字段中的行/列范围结构体
type Range struct {
	StartLine   NullableInt `json:"start_line"`
	EndLine     NullableInt `json:"end_line"`
	StartColumn NullableInt `json:"start_column"`
	EndColumn   NullableInt `json:"end_column"`
}

// 定义 SeverityLevel 枚举类型
type SeverityLevel string

const (
	SeverityLevelCritical SeverityLevel = "CRITICAL"
	// SeverityLevelHigh 表示高严重性级别
	SeverityLevelHigh SeverityLevel = "HIGH"
	// SeverityLevelMedium 表示中等严重性级别
	SeverityLevelMedium SeverityLevel = "MEDIUM"
	// SeverityLevelLow 表示低严重性级别
	SeverityLevelLow SeverityLevel = "LOW"
	// SeverityLevelUnknown 表示未知严重性级别
	SeverityLevelUnknown SeverityLevel = "UNKNOWN"
)

// 定义 ConfidenceLevel 类型
type ConfidenceLevel string

const (
	ConfidenceLevelHigh   ConfidenceLevel = "HIGH"
	ConfidenceLevelMedium ConfidenceLevel = "MEDIUM"
	ConfidenceLevelLow    ConfidenceLevel = "LOW"
)

// UnifiedVulnerability 统一的漏洞字段结构体
// 使用指针类型处理null值（Go中nil指针序列化后为null）
type UnifiedVulnerability struct {
	Tool            string          `json:"tool"`
	WarningID       string          `json:"warning_id"`
	Category        string          `json:"category"`
	ShortMessage    string          `json:"short_messgae"` // 保持你指定的字段名（注意拼写）
	CWEID           string          `json:"cwe_id"`        // 无值则为null
	FilePath        string          `json:"file_path"`
	Module          string          `json:"module"` // 模块名.(类 / 函数),即错误发生的最小层级
	Range           Range           `json:"range"`
	SeverityLevel   SeverityLevel   `json:"severity_level"`
	ConfidenceLevel ConfidenceLevel `json:"confidence_level"`
}

type Language string

// 编程语言的枚举类型
const (
	LanguageGo      Language = "go"
	LanguageJava    Language = "java"
	LanguagePython  Language = "python"
	LanguageC       Language = "c"
	LanguageCsharp  Language = "c#"
	LanguageCpp     Language = "cpp"
	LanguageKotlin  Language = "kotlin"
	LanguageJs      Language = "javascript"
	LanguageTs      Language = "typescript"
	LanguageRuby    Language = "ruby"
	LanguageRust    Language = "rust"
	LanguageUnknown Language = "unknown"
)
