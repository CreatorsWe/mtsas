## `UnifiedVulerability`

解析器 parser 读取工具输出的 `json/xml/sarif` 报告将其反序列化成统一的 `UnifiedVulerability` 结构：

```go
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

type Range struct {
	StartLine   NullableInt `json:"start_line"` // NullableInt 将 -1 序列化成 json 的 null
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
```

每个 Parser 应该实现以下几个方法：

```go
func(*ParserName) getSeverityLevel(field string) SeverityLevel
func(*ParserName) getConfidenceLevel(field string) ConfidenceLevel
func(*ParserName) getModule(field string) string // 目前没有实现
func(*ParserName) getCWEID(field string) string
func(*ParserName) readReportToIssues(path string) ([]Issues, error)  // 将报告反序列化成 Issues 中间结构
func(*ParserName) convertIssuesToUnified(issues Issues) (UnifiedVulnerability, error)  // 将 Issues 中间结构转换成统一的 UnifiedVulnerability 类型
func(*ParserName) Parse() ([]UnifiedVulnerability, error) // 对外暴露的统一接口
```



## `PylintParser`

```go
return UnifiedVulnerability {
	Tool:       		"pylint"
    WarningID:  		{message-id}  // {} 表示 json 字段
    Category: 			{type}
    ShortMessage: 		{message}
    CWEID: 				[cweMapper 预映射表(message-id)]  // [] 表示方法
    FilePath: 			{path}
    Module: 			""  // 未实现
    Range {
        StartLine: 		{line}
        EndLine: 		{endLine}
        StartColumn: 	{column}
        EndColumn: 		{endColumn}
    }
    SeverityLevel: 		[从 {type} 字段映射]
    ConfidenceLevel: 	[从 {type} 字段映射]
}
```



## `BanditParser`

```go
return UnifiedVulnerability {
	Tool:       		"bandit"
    WarningID:  		{text_id}
    Category: 			""
    ShortMessage: 		{issue_text}
    CWEID: 				[从 {issue_cwe.id} 中提取]
    FilePath: 			{filename}
    Module: 			""  // 未实现
    Range {
        StartLine: 		{line_range[0]}
        EndLine: 		{line_range[1]，没有则为 line_range[0]}
        StartColumn: 	{col_offset}
        EndColumn: 		{end_col_offset}
    }
    SeverityLevel: 		[从 {issue_severity} 字段映射]
    ConfidenceLevel: 	[从 {issue_confidence} 字段映射]
}
```



## `HorusecParser`

```go
return UnifiedVulnerability {
	Tool:       		"horusec"
    WarningID:  		{rule_id}
    Category: 			{type}
    ShortMessage: 		{details}
    CWEID: 				[从 {details} 中提取]
    FilePath: 			{file}      // 相对与扫描目录的相对路径，后续可能统一绝对路径
    Module: 			""  // 未实现
    Range {
        StartLine: 		{line}
        EndLine: 		-1  // 映射到 null
        StartColumn: 	{column}
        EndColumn: 		-1
    }
    SeverityLevel: 		[从 {severity} 字段映射]
    ConfidenceLevel: 	[从 {confidence} 字段映射]
}
```



## `InsiderParser`

```go
return UnifiedVulnerability {
	Tool:       		"insider"
    WarningID:  		{cwe}
    Category: 			""
    ShortMessage: 		{description}
    CWEID: 				[从 {cwe} 中提取]
    FilePath: 			{class}      // 仅文件名
    Module: 			""  // 未实现
    Range {
        StartLine: 		{line}
        EndLine: 		-1  // 映射到 null
        StartColumn: 	{column}
        EndColumn: 		-1
    }
    SeverityLevel: 		[从 {cvss} 字段映射]
    ConfidenceLevel: 	[从 {cvss} 字段映射]
}
```



## `semgrepParser`

```go
return UnifiedVulnerability {
	Tool:       		"semgrep"
    WarningID:  		{check_id}
    Category: 			{extra.metadta.category}
    ShortMessage: 		{extra.message}
    CWEID: 				[从 {extra.metadata.cwe} 中提取]
    FilePath: 			{path}
    Module: 			""  // 未实现
    Range {
        StartLine: 		{start.line}
        EndLine: 		{end.line}
        StartColumn: 	{start.col}
        EndColumn: 		{end.col}
    }
    SeverityLevel: 		[从 {extra.severity} 字段映射]
    ConfidenceLevel: 	[从 {extra.metadata.confidence} 字段映射]
}
```



## `cppcheckParser`

解析 `xml` 文件

```go
return UnifiedVulnerability {
	Tool:       		"cppcheck"
    WarningID:  		{id}
    Category: 			""
    ShortMessage: 		{msg}
    CWEID: 				[部分从 {cwe} 中提取，没有从 cweMapper 获取(id)]
    FilePath: 			{location.file}
    Module: 			""  // 未实现
    Range {
        StartLine: 		{location.line}
        EndLine: 		-1
        StartColumn: 	{location.column}
        EndColumn: 		-1
    }
    SeverityLevel: 		[从 {severity} 字段映射]
    ConfidenceLevel: 	[从 {severity} 字段映射]
}
```



## `spotbugsParser`

解析 `xml` 文件，且仅能扫描 `.class` java 字节码

```go
return UnifiedVulnerability {
	Tool:       		"spotbugs"
    WarningID:  		{type}
    Category: 			{category}
    ShortMessage: 		""
    CWEID: 				[从 cweMapper 获取(type)]
    FilePath: 			{SourceLine.sourcepath}  // 相对与扫描目录的相对路径
    Module: 			""  // 未实现
    Range {
        StartLine: 		{SourceLine.start}
        EndLine: 		{SourceLine.end}
        StartColumn: 	-1
        EndColumn: 		-1
    }
    SeverityLevel: 		[从 {priority} 字段映射]
    ConfidenceLevel: 	[从 {rank} 字段映射]
}
```



## `CodeQlParser`

解析 `sarif` 文件。该报告的漏洞（位于 runs.results） 和该漏洞对应的 ruleId 的信息（位于 runs.tool.driver.rules）是分开的，所以都需要获取。

```go
return UnifiedVulnerability {
	Tool:       		"codeql"
    WarningID:  		{results.ruleId}
    Category: 			kind
    ShortMessage: 		{results.message.text}
    CWEID: 				[部分从 rules.properties.tags  获取，部分查询数据库(ruleId)]
    FilePath: 			{results.locations.physicalLocation.artifactLocation.uri}  // 相对与扫描目录的相对路径
    Module: 			""  // 未实现
    Range {
        StartLine: 		{results.locations.physicalLocation.region.startLine}
        EndLine: 		{results.locations.physicalLocation.region.endLine}
        StartColumn: 	{results.locations.physicalLocation.region.startColumn}
        EndColumn: 		{results.locations.physicalLocation.region.endColumn}
    }
    SeverityLevel: 		[从 {rules.properties.problem.severity} 字段映射]
    ConfidenceLevel: 	[从 {rules.properties.precision} 字段映射]
}
```





## `CSAParser`

解析 `index.html` 网页。

```go
return UnifiedVulnerability {
	Tool:       		"clang static analyzer"
    WarningID:  		{bug Type}
    Category: 			{bug Group}
    ShortMessage: 		[从跳转的网页获取，获取 <tr data-linenumber = ?> 为 line 处获取其下面的 <tr>.<div> 内容]
    CWEID: 				[从 cweMapper 查询(bug Type)]
    FilePath: 			{File}  // 文件名
    Module: 			""  // 未实现
    Range {
        StartLine: 		{跳转网页获取 Line}
        EndLine: 		{跳转网页获取 Column}
        StartColumn: 	-1
        EndColumn: 		-1
    }
    SeverityLevel: 		[从 bug Group 提取]
    ConfidenceLevel: 	[csa 置信度较高]
}
```
