package common

// ToolInfo 工具基本信息
type ToolInfo struct {
	Name               string
	Version            string
	Path               string
	Command            string // 命令由外部提供，不需要校验，如果错误，直接返回错误即可
	SupportedLanguages []Language
}

// ExecutionResult 执行结果
type ExecutionResult struct {
	Success  bool
	Output   []byte // 工具输出信息
	Error    error  // 自定义错误信息
	ExitCode int
}

// Executor 核心执行器接口
type Executor interface {
	GetToolInfo() ToolInfo
	// 获取工具生成的文件
	GetReportPath() string
	// 执行 command 语句
	Execute() *ExecutionResult
}
