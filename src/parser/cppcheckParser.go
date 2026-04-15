package parser

import (
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	. "github.com/mtsas/common"
)

type CppcheckParser struct {
	parseFilePath  string
	queryInterface func(string, string) (int, error)
}

func NewCppcheckParser(parseFilePath string, queryInterface func(string, string) (int, error)) *CppcheckParser {
	return &CppcheckParser{
		parseFilePath:  parseFilePath,
		queryInterface: queryInterface,
	}
}

// Cppcheck XML 报告结构定义
type o_cppcheckIssues struct {
	Errors []cppcheckIssues `xml:"errors>error"`
}

type cppcheckIssues struct {
	ID       string   `xml:"id,attr"`
	Severity string   `xml:"severity,attr"`
	Message  string   `xml:"msg,attr"`
	CWE      string   `xml:"cwe,attr"`
	Location location `xml:"location"`
}

type location struct {
	File string `xml:"file,attr"`
	Line int    `xml:"line,attr"`
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

// 获取 cwe 字段
func (c *CppcheckParser) getCWE(issuesID string) (int, error) {
	if issuesID == "" {
		return c.queryInterface("cppcheck", issuesID)
	} else {
		return strconv.Atoi(issuesID)
	}

}

// 转换 Cppcheck 错误为统一漏洞格式
func (c *CppcheckParser) convertIssuesToUnified(issues cppcheckIssues) (UnifiedVulnerability, error) {

	// 获取严重级别和置信度
	severityLevel := c.getSeverityLevel(issues.Severity)
	confidenceLevel := c.getConfidenceLevel(issues.Severity)

	cweID, err := c.getCWE(issues.CWE)
	if err != nil {
		return UnifiedVulnerability{}, err
	}

	return UnifiedVulnerability{
		Tool:            "cppcheck",
		WarningID:       issues.ID,
		Category:        "",
		ShortMessage:    issues.Message,
		CWEID:           cweID,
		FilePath:        issues.Location.File,
		Line:            issues.Location.Line,
		SeverityLevel:   severityLevel,
		ConfidenceLevel: confidenceLevel,
	}, nil
}

// 读取并解析XML文件
func (c *CppcheckParser) readReportToIssues(file_path string) ([]cppcheckIssues, error) {
	file, err := os.Open(file_path)
	if err != nil {
		return nil, fmt.Errorf("打开文件失败: %v", err)
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("读取文件失败: %v", err)
	}

	var report o_cppcheckIssues
	err = xml.Unmarshal(data, &report)
	if err != nil {
		return nil, fmt.Errorf("解析XML失败: %v", err)
	}

	return report.Errors, nil
}

// Parse 解析 Cppcheck XML 报告并返回 UnifiedVulnerability 列表
func (c *CppcheckParser) Parse() ([]UnifiedVulnerability, error) {
	// 读取并解析XML报告
	report, err := c.readReportToIssues(c.parseFilePath)
	if err != nil {
		return nil, fmt.Errorf("解析Cppcheck报告失败: %v", err)
	}

	// 转换为统一格式
	var unifiedVulns []UnifiedVulnerability
	for _, errorObj := range report {
		unifiedVuln, err := c.convertIssuesToUnified(errorObj)
		if err != nil {
			return nil, err
		}
		unifiedVulns = append(unifiedVulns, unifiedVuln)
	}

	return unifiedVulns, nil
}

func (c *CppcheckParser) GetName() string {
	return "cppcheckParser"
}
