package parser

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	. "github.com/mtsas/common"
)

type SemgrepParser struct {
	parseFilePath string
}

func NewSemgrepParser(parseFilePath string) *SemgrepParser {
	return &SemgrepParser{
		parseFilePath: parseFilePath,
	}
}

// SemgrepIssue 定义 Semgrep JSON 报告的结构体
type SemgrepIssue struct {
	CheckID string `json:"check_id"`
	Path    string `json:"path"`
	Start   struct {
		Line   int `json:"line"`
		Col    int `json:"col"`
		Offset int `json:"offset"`
	} `json:"start"`
	End struct {
		Line   int `json:"line"`
		Col    int `json:"col"`
		Offset int `json:"offset"`
	} `json:"end"`
	Extra struct {
		Message  string `json:"message"`
		Fix      string `json:"fix,omitempty"`
		Metadata struct {
			FunctionalCategories []string `json:"functional-categories,omitempty"`
			Owasp                []string `json:"owasp,omitempty"`
			Cwe                  []string `json:"cwe,omitempty"`
			SourceRuleURL        string   `json:"source-rule-url,omitempty"`
			Category             string   `json:"category,omitempty"`
			Technology           []string `json:"technology,omitempty"`
			References           []string `json:"references,omitempty"`
			Subcategory          []string `json:"subcategory,omitempty"`
			Likelihood           string   `json:"likelihood,omitempty"`
			Impact               string   `json:"impact,omitempty"`
			Confidence           string   `json:"confidence,omitempty"`
			License              string   `json:"license,omitempty"`
			VulnerabilityClass   []string `json:"vulnerability_class,omitempty"`
			Source               string   `json:"source,omitempty"`
			Shortlink            string   `json:"shortlink,omitempty"`
			Cwe2022Top25         bool     `json:"cwe2022-top25,omitempty"`
			Cwe2021Top25         bool     `json:"cwe2021-top25,omitempty"`
		} `json:"metadata"`
		Severity        string `json:"severity"`
		Fingerprint     string `json:"fingerprint"`
		Lines           string `json:"lines"`
		ValidationState string `json:"validation_state"`
		EngineKind      string `json:"engine_kind"`
	} `json:"extra"`
}

// SemgrepReport 完整的 Semgrep 报告结构
type SemgrepReport struct {
	Version string         `json:"version"`
	Results []SemgrepIssue `json:"results"`
	Errors  []any          `json:"errors"`
	Paths   struct {
		Scanned []string `json:"scanned"`
	} `json:"paths"`
	Time struct {
		Rules          []any   `json:"rules"`
		RulesParseTime float64 `json:"rules_parse_time"`
		ProfilingTimes struct {
			ConfigTime  float64 `json:"config_time"`
			CoreTime    float64 `json:"core_time"`
			IgnoresTime float64 `json:"ignores_time"`
			TotalTime   float64 `json:"total_time"`
		} `json:"profiling_times"`
		ParsingTime struct {
			TotalTime   float64 `json:"total_time"`
			PerFileTime struct {
				Mean   float64 `json:"mean"`
				StdDev float64 `json:"std_dev"`
			} `json:"per_file_time"`
			VerySlowStats struct {
				TimeRatio  float64 `json:"time_ratio"`
				CountRatio float64 `json:"count_ratio"`
			} `json:"very_slow_stats"`
			VerySlowFiles []any `json:"very_slow_files"`
		} `json:"parsing_time"`
		ScanningTime struct {
			TotalTime   float64 `json:"total_time"`
			PerFileTime struct {
				Mean   float64 `json:"mean"`
				StdDev float64 `json:"std_dev"`
			} `json:"per_file_time"`
			VerySlowStats struct {
				TimeRatio  float64 `json:"time_ratio"`
				CountRatio float64 `json:"count_ratio"`
			} `json:"very_slow_stats"`
			VerySlowFiles []any `json:"very_slow_files"`
		} `json:"scanning_time"`
		MatchingTime struct {
			TotalTime          float64 `json:"total_time"`
			PerFileAndRuleTime struct {
				Mean   float64 `json:"mean"`
				StdDev float64 `json:"std_dev"`
			} `json:"per_file_and_rule_time"`
			VerySlowStats struct {
				TimeRatio  float64 `json:"time_ratio"`
				CountRatio float64 `json:"count_ratio"`
			} `json:"very_slow_stats"`
			VerySlowRulesOnFiles []any `json:"very_slow_rules_on_files"`
		} `json:"matching_time"`
		TaintingTime struct {
			TotalTime         float64 `json:"total_time"`
			PerDefAndRuleTime struct {
				Mean   float64 `json:"mean"`
				StdDev float64 `json:"std_dev"`
			} `json:"per_def_and_rule_time"`
			VerySlowStats struct {
				TimeRatio  float64 `json:"time_ratio"`
				CountRatio float64 `json:"count_ratio"`
			} `json:"very_slow_stats"`
			VerySlowRulesOnDefs []any `json:"very_slow_rules_on_defs"`
		} `json:"tainting_time"`
		FixpointTimeouts []any `json:"fixpoint_timeouts"`
		Prefiltering     struct {
			ProjectLevelTime                float64 `json:"project_level_time"`
			FileLevelTime                   float64 `json:"file_level_time"`
			RulesWithProjectPrefiltersRatio float64 `json:"rules_with_project_prefilters_ratio"`
			RulesWithFilePrefiltersRatio    float64 `json:"rules_with_file_prefilters_ratio"`
			RulesSelectedRatio              float64 `json:"rules_selected_ratio"`
			RulesMatchedRatio               float64 `json:"rules_matched_ratio"`
		} `json:"prefiltering"`
		Targets        []any `json:"targets"`
		TotalBytes     int   `json:"total_bytes"`
		MaxMemoryBytes int   `json:"max_memory_bytes"`
	} `json:"time"`
	EngineRequested  string `json:"engine_requested"`
	SkippedRules     []any  `json:"skipped_rules"`
	ProfilingResults []any  `json:"profiling_results"`
}

// 将 Semgrep severity 字段映射为 unified severity_level 字段
func (s *SemgrepParser) getSeverityLevel(severity string) SeverityLevel {
	switch strings.ToUpper(severity) {
	case "ERROR":
		return SeverityLevelHigh
	case "WARNING":
		return SeverityLevelMedium
	case "INFO":
		return SeverityLevelLow
	default:
		return SeverityLevelUnknown
	}
}

// 将 Semgrep confidence 字段映射成 unified confidence_level 字段
func (s *SemgrepParser) getConfidenceLevel(confidence string) ConfidenceLevel {
	switch strings.ToUpper(confidence) {
	case "HIGH":
		return ConfidenceLevelHigh
	case "MEDIUM":
		return ConfidenceLevelMedium
	case "LOW":
		return ConfidenceLevelLow
	default:
		return ConfidenceLevelLow // 默认中等置信度
	}
}

// 获取 Module 字段 - 从文件路径和检查ID中提取模块信息
// func (s *SemgrepParser) getModule(filePath string, checkID string) string {
// }

// 从 cwe 数组获取 CWE 字段
func (p *SemgrepParser) getCWEID(cweList []string) string {
	if len(cweList) == 0 {
		return "" // 返回空字符串，序列化时会变成null
	}

	// 取第一个CWE ID
	cwe := cweList[0]

	// 提取CWE编号，格式可能是 "CWE-328: Use of Weak Hash"
	if strings.HasPrefix(cwe, "CWE-") {
		// 提取CWE-后面的数字部分
		parts := strings.Split(cwe, " ")
		if len(parts) > 0 {
			cweID := strings.TrimPrefix(parts[0], "CWE-")
			// 去掉可能的分隔符
			cweID = strings.TrimSuffix(cweID, ":")
			return cweID
		}
	}

	return cwe
}

// ConvertSemgrepIssueToUnified 将 SemgrepIssue 转换为统一漏洞结构体
func (p *SemgrepParser) convertSemgrepIssueToUnified(issue SemgrepIssue) UnifiedVulnerability {
	// 构建Range结构
	vulnRange := Range{
		StartLine:   NullableInt(issue.Start.Line),
		EndLine:     NullableInt(issue.End.Line),
		StartColumn: NullableInt(issue.Start.Col),
		EndColumn:   NullableInt(issue.End.Col),
	}

	// 获取严重级别和置信度
	severityLevel := p.getSeverityLevel(issue.Extra.Severity)
	confidenceLevel := p.getConfidenceLevel(issue.Extra.Metadata.Confidence)

	// 获取CWE ID
	cweID := p.getCWEID(issue.Extra.Metadata.Cwe)

	// 获取模块信息
	// module := p.getModule(issue.Path, issue.CheckID)

	return UnifiedVulnerability{
		Tool:            "semgrep",
		WarningID:       issue.CheckID,
		WarningType:     issue.CheckID,
		Category:        issue.Extra.Metadata.Category,
		ShortMessage:    issue.Extra.Message,
		CWEID:           cweID,
		FilePath:        issue.Path,
		Module:          "",
		Range:           vulnRange,
		SeverityLevel:   severityLevel,
		ConfidenceLevel: confidenceLevel,
	}
}

// readJsonToSemgrepReport 读取JSON文件并解析为SemgrepReport
func readJsonToSemgrepReport(path string) (*SemgrepReport, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取文件失败: %v", err)
	}

	var report SemgrepReport
	err = json.Unmarshal(data, &report)
	if err != nil {
		return nil, fmt.Errorf("解析JSON失败: %v", err)
	}

	return &report, nil
}

func (p *SemgrepParser) Parse() ([]UnifiedVulnerability, error) {
	// 读取并解析Semgrep报告
	report, err := readJsonToSemgrepReport(p.parseFilePath)
	if err != nil {
		return nil, fmt.Errorf("解析Semgrep报告失败: %v", err)
	}

	// 转换每个结果为统一格式
	var unifiedVulns []UnifiedVulnerability
	for _, issue := range report.Results {
		unifiedVuln := p.convertSemgrepIssueToUnified(issue)
		unifiedVulns = append(unifiedVulns, unifiedVuln)
	}

	return unifiedVulns, nil
}

func (p *SemgrepParser) GetName() string {
	return "semgrepParser"
}
