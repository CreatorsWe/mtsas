package parser

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	. "github.com/mtsas/common"
)

type InsiderParser struct {
	parseFilePath string
}

func NewInsiderParser(parseFilePath string) *InsiderParser {
	return &InsiderParser{
		parseFilePath: parseFilePath,
	}
}

// InsiderReport 定义 Insider JSON 报告的结构体
type InsiderReport struct {
	Vulnerabilities []InsiderVulnerability `json:"vulnerabilities"`
	None            int                    `json:"none"`
	Low             int                    `json:"low"`
	Medium          int                    `json:"medium"`
	High            int                    `json:"high"`
	Critical        int                    `json:"critical"`
	Total           int                    `json:"total"`
	Sast            struct {
		AverageCvss   float64 `json:"averageCvss"`
		SecurityScore int     `json:"securityScore"`
		Size          string  `json:"size"`
		NumberOfLines int     `json:"numberOfLines"`
	} `json:"sast"`
}

type InsiderVulnerability struct {
	Cvss          float64 `json:"cvss"`
	Cwe           string  `json:"cwe"`
	Line          int     `json:"line"`
	Class         string  `json:"class"`
	VulID         string  `json:"vul_id"`
	Method        string  `json:"method"`
	Column        int     `json:"column"`
	Description   string  `json:"description"`
	ClassMessage  string  `json:"classMessage"`
	Recomendation string  `json:"recomendation,omitempty"`
}

// 将 CVSS 分数映射为 unified severity_level
func (p *InsiderParser) getSeverityLevel(cvss float64) SeverityLevel {
	switch {
	case cvss >= 9.0:
		return SeverityLevelCritical
	case cvss >= 7.0:
		return SeverityLevelHigh
	case cvss >= 4.0:
		return SeverityLevelMedium
	case cvss > 0:
		return SeverityLevelLow
	default:
		return SeverityLevelLow
	}
}

// 获取置信度级别（基于 CVSS 分数推断）
func (p *InsiderParser) getConfidenceLevel(cvss float64) ConfidenceLevel {
	switch {
	case cvss >= 7.0:
		return ConfidenceLevelHigh
	case cvss >= 4.0:
		return ConfidenceLevelMedium
	default:
		return ConfidenceLevelLow
	}
}

// 从 class 字段提取文件路径
func (p *InsiderParser) getFilePath(class string) string {
	// class 格式示例: "Demo1.java (16:20)"
	parts := strings.Split(class, " (")
	if len(parts) > 0 {
		return parts[0]
	}
	return class
}

// 从 CWE 字符串中提取 CWE ID
func (p *InsiderParser) getCWEID(cwe string) string {
	if strings.HasPrefix(cwe, "CWE-") {
		// 提取 CWE- 后面的数字部分
		parts := strings.Split(cwe, "-")
		if len(parts) >= 2 {
			// 去掉可能的后缀
			cweID := parts[1]
			if idx := strings.Index(cweID, " "); idx != -1 {
				cweID = cweID[:idx]
			}
			return cweID
		}
	}
	return cwe
}

// 获取警告类型
func (p *InsiderParser) getWarningType(cwe, description string) string {
	// 基于 CWE 和描述生成警告类型
	if cwe != "" {
		cweID := p.getCWEID(cwe)
		switch cweID {
		case "312":
			return "cleartext.storage"
		case "327":
			return "weak.hash.algorithm"
		case "532":
			return "information.logging"
		case "330":
			return "weak.random.generator"
		case "78":
			return "command.injection"
		default:
			return "cwe." + cweID
		}
	}

	// 从描述中提取关键信息
	if strings.Contains(strings.ToLower(description), "password") {
		return "password.exposure"
	} else if strings.Contains(strings.ToLower(description), "log") {
		return "information.logging"
	} else if strings.Contains(strings.ToLower(description), "random") {
		return "weak.random"
	} else if strings.Contains(strings.ToLower(description), "hash") {
		return "weak.hash"
	} else if strings.Contains(strings.ToLower(description), "command") {
		return "command.injection"
	}

	return "security.issue"
}

// 获取类别
func (p *InsiderParser) getCategory(cwe, description string) string {
	cweID := p.getCWEID(cwe)
	switch cweID {
	case "312", "532":
		return "information.disclosure"
	case "327", "330":
		return "cryptography"
	case "78":
		return "injection"
	default:
		return "code.quality"
	}
}

// 获取模块名称
// func (p *InsiderParser) getModule(filePath string) string {
// 	if filePath == "" {
// 		return "unknown"
// 	}
// 	baseName := filepath.Base(filePath)
// 	return strings.TrimSuffix(baseName, filepath.Ext(baseName))
// }

// ConvertInsiderVulnToUnified 将 InsiderVulnerability 转换为统一漏洞结构体
func (p *InsiderParser) convertInsiderVulnToUnified(vuln InsiderVulnerability) UnifiedVulnerability {
	// 构建 Range 结构
	vulnRange := Range{
		StartLine:   NullableInt(vuln.Line),
		EndLine:     NullableInt(vuln.Line), // Insider 通常只提供单行
		StartColumn: NullableInt(vuln.Column),
		EndColumn:   NullableInt(vuln.Column), // Insider 通常只提供单列
	}

	// 获取严重级别和置信度
	severityLevel := p.getSeverityLevel(vuln.Cvss)
	confidenceLevel := p.getConfidenceLevel(vuln.Cvss)

	// 提取文件路径和模块
	filePath := p.getFilePath(vuln.Class)
	module := ""

	// 提取 CWE ID
	cweID := p.getCWEID(vuln.Cwe)

	// 获取警告类型和类别
	warningType := p.getWarningType(vuln.Cwe, vuln.Description)
	category := p.getCategory(vuln.Cwe, vuln.Description)

	return UnifiedVulnerability{
		Tool:            "insider",
		WarningID:       vuln.VulID,
		WarningType:     warningType,
		Category:        category,
		ShortMessage:    vuln.Description,
		CWEID:           cweID,
		FilePath:        filePath,
		Module:          module,
		Range:           vulnRange,
		SeverityLevel:   severityLevel,
		ConfidenceLevel: confidenceLevel,
	}
}

// readJSONToInsiderReport 读取 JSON 文件并解析为 InsiderReport
func readJSONToInsiderReport(path string) (*InsiderReport, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取文件失败: %v", err)
	}

	var report InsiderReport
	err = json.Unmarshal(data, &report)
	if err != nil {
		return nil, fmt.Errorf("解析JSON失败: %v", err)
	}

	return &report, nil
}

// Parse 解析 Insider JSON 报告并返回 UnifiedVulnerability 列表
func (p *InsiderParser) Parse() ([]UnifiedVulnerability, error) {
	// 读取并解析 Insider 报告
	report, err := readJSONToInsiderReport(p.parseFilePath)
	if err != nil {
		return nil, fmt.Errorf("解析Insider报告失败: %v", err)
	}

	// 转换为统一格式
	var unifiedVulns []UnifiedVulnerability
	for _, vuln := range report.Vulnerabilities {
		unifiedVuln := p.convertInsiderVulnToUnified(vuln)
		unifiedVulns = append(unifiedVulns, unifiedVuln)
	}

	return unifiedVulns, nil
}

// GetName 获取解析器名称
func (p *InsiderParser) GetName() string {
	return "insiderParser"
}
