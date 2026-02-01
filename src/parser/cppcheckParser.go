package parser

import (
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"strings"

	. "github.com/mtsas/common"
)

type CppcheckParser struct {
	parseFilePath string
}

func NewCppcheckParser(parseFilePath string) *CppcheckParser {
	return &CppcheckParser{
		parseFilePath: parseFilePath,
	}
}

// Cppcheck XML 报告结构定义
type CppcheckReport struct {
	XMLName xml.Name        `xml:"results"`
	Version string          `xml:"version,attr"`
	Errors  []CppcheckError `xml:"errors>error"`
}

type CppcheckError struct {
	ID       string   `xml:"id,attr"`
	Severity string   `xml:"severity,attr"`
	Message  string   `xml:"msg,attr"`
	Verbose  string   `xml:"verbose,attr"`
	CWE      string   `xml:"cwe,attr"`
	File0    string   `xml:"file0,attr"`
	Location Location `xml:"location"`
	Symbol   string   `xml:"symbol"`
}

type Location struct {
	File   string `xml:"file,attr"`
	Line   int    `xml:"line,attr"`
	Column int    `xml:"column,attr"`
	Info   string `xml:"info,attr"`
}

// 将 Cppcheck severity 映射为 unified severity_level
func (c *CppcheckParser) getSeverityLevel(severity string) SeverityLevel {
	switch strings.ToLower(severity) {
	case "error":
		return SeverityLevelHigh
	case "warning":
		return SeverityLevelMedium
	case "style", "performance", "portability":
		return SeverityLevelLow
	case "information":
		return SeverityLevelLow
	default:
		return SeverityLevelUnknown
	}
}

// 获取置信度级别（Cppcheck 不直接提供，基于严重级别推断）
func (c *CppcheckParser) getConfidenceLevel(severity string) ConfidenceLevel {
	switch strings.ToLower(severity) {
	case "error", "warning":
		return ConfidenceLevelHigh
	case "style", "performance", "portability":
		return ConfidenceLevelMedium
	case "information":
		return ConfidenceLevelLow
	default:
		return ConfidenceLevelLow
	}
}

// 获取模块名称
// func (c *CppcheckParser) getModule(filePath string) string {
// 	if filePath == "" {
// 		return "unknown"
// 	}

// 	// 从文件路径提取文件名（不含扩展名）作为模块名
// 	baseName := filepath.Base(filePath)
// 	moduleName := strings.TrimSuffix(baseName, filepath.Ext(baseName))
// 	return moduleName
// }

// 获取类别信息
func (c *CppcheckParser) getCategory(errorID string, severity string) string {
	// 基于 error ID 和严重级别推断类别
	switch errorID {
	case "missingIncludeSystem":
		return "include"
	case "constVariablePointer", "cstyleCast":
		return "code.style"
	case "deallocuse":
		return "memory"
	case "unusedFunction":
		return "dead.code"
	case "checkersReport":
		return "system.info"
	default:
		return "general"
	}
}

// 转换 Cppcheck 错误为统一漏洞格式
func (c *CppcheckParser) convertToUnified(errorObj CppcheckError) UnifiedVulnerability {
	// 构建范围信息
	vulnRange := Range{
		StartLine:   NullableInt(errorObj.Location.Line),
		EndLine:     NullableInt(errorObj.Location.Line), // Cppcheck 通常只提供单行
		StartColumn: NullableInt(errorObj.Location.Column),
		EndColumn:   NullableInt(errorObj.Location.Column), // Cppcheck 通常只提供单列
	}

	// 获取严重级别和置信度
	severityLevel := c.getSeverityLevel(errorObj.Severity)
	confidenceLevel := c.getConfidenceLevel(errorObj.Severity)

	// 获取警告类别
	category := c.getCategory(errorObj.ID, errorObj.Severity)

	// 获取模块
	// module := c.getModule(errorObj.Location.File)

	// 使用 Verbose 消息作为详细描述，如果没有则使用 Message
	shortMessage := errorObj.Message
	if errorObj.Verbose != "" {
		shortMessage = errorObj.Verbose
	}

	// 处理 CWE 字段
	cweID := errorObj.CWE

	return UnifiedVulnerability{
		Tool:            "cppcheck",
		WarningID:       errorObj.ID,
		WarningType:     errorObj.ID,
		Category:        category,
		ShortMessage:    shortMessage,
		CWEID:           cweID,
		FilePath:        errorObj.Location.File,
		Module:          "",
		Range:           vulnRange,
		SeverityLevel:   severityLevel,
		ConfidenceLevel: confidenceLevel,
	}
}

// 读取并解析XML文件
func (c *CppcheckParser) readXMLReport() (*CppcheckReport, error) {
	file, err := os.Open(c.parseFilePath)
	if err != nil {
		return nil, fmt.Errorf("打开文件失败: %v", err)
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("读取文件失败: %v", err)
	}

	var report CppcheckReport
	err = xml.Unmarshal(data, &report)
	if err != nil {
		return nil, fmt.Errorf("解析XML失败: %v", err)
	}

	return &report, nil
}

// Parse 解析 Cppcheck XML 报告并返回 UnifiedVulnerability 列表
func (c *CppcheckParser) Parse() ([]UnifiedVulnerability, error) {
	// 读取并解析XML报告
	report, err := c.readXMLReport()
	if err != nil {
		return nil, fmt.Errorf("解析Cppcheck报告失败: %v", err)
	}

	// 过滤掉系统信息类型的错误（如checkersReport）
	var filteredErrors []CppcheckError
	for _, errorObj := range report.Errors {
		// 跳过系统信息类型的错误
		if errorObj.ID == "checkersReport" {
			continue
		}
		filteredErrors = append(filteredErrors, errorObj)
	}

	// 转换为统一格式
	var unifiedVulns []UnifiedVulnerability
	for _, errorObj := range filteredErrors {
		unifiedVuln := c.convertToUnified(errorObj)
		unifiedVulns = append(unifiedVulns, unifiedVuln)
	}

	return unifiedVulns, nil
}

func (c *CppcheckParser) GetName() string {
	return "cppcheckParser"
}

// // GetReportSummary 获取报告摘要信息
// func (c *CppcheckParser) GetReportSummary() (map[string]interface{}, error) {
// 	report, err := c.readXMLReport()
// 	if err != nil {
// 		return nil, err
// 	}

// 	summary := make(map[string]interface{})
// 	summary["version"] = report.Version
// 	summary["total_errors"] = len(report.Errors)

// 	// 统计各严重级别的错误数量
// 	severityCount := make(map[string]int)
// 	for _, error := range report.Errors {
// 		severityCount[error.Severity]++
// 	}
// 	summary["severity_distribution"] = severityCount

// 	// 统计文件分布
// 	fileDistribution := make(map[string]int)
// 	for _, error := range report.Errors {
// 		if error.Location.File != "" {
// 			fileDistribution[error.Location.File]++
// 		}
// 	}
// 	summary["file_distribution"] = fileDistribution

// 	return summary, nil
// }

// // FilterBySeverity 按严重级别过滤漏洞
// func (c *CppcheckParser) FilterBySeverity(severity SeverityLevel) ([]UnifiedVulnerability, error) {
// 	allVulns, err := c.Parse()
// 	if err != nil {
// 		return nil, err
// 	}

// 	var filtered []UnifiedVulnerability
// 	for _, vuln := range allVulns {
// 		if vuln.SeverityLevel == severity {
// 			filtered = append(filtered, vuln)
// 		}
// 	}

// 	return filtered, nil
// }

// // FilterByFile 按文件路径过滤漏洞
// func (c *CppcheckParser) FilterByFile(filePattern string) ([]UnifiedVulnerability, error) {
// 	allVulns, err := c.Parse()
// 	if err != nil {
// 		return nil, err
// 	}

// 	var filtered []UnifiedVulnerability
// 	for _, vuln := range allVulns {
// 		if strings.Contains(vuln.FilePath, filePattern) {
// 			filtered = append(filtered, vuln)
// 		}
// 	}

// 	return filtered, nil
// }

// // GetErrorsByCWE 按CWE ID分组获取错误
// func (c *CppcheckParser) GetErrorsByCWE() (map[string][]UnifiedVulnerability, error) {
// 	allVulns, err := c.Parse()
// 	if err != nil {
// 		return nil, err
// 	}

// 	cweMap := make(map[string][]UnifiedVulnerability)
// 	for _, vuln := range allVulns {
// 		if vuln.CWEID != "" {
// 			cweMap[vuln.CWEID] = append(cweMap[vuln.CWEID], vuln)
// 		} else {
// 			// 没有CWE ID的归为一类
// 			cweMap["unknown"] = append(cweMap["unknown"], vuln)
// 		}
// 	}

// 	return cweMap, nil
// }
