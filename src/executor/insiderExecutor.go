package executor

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	. "github.com/mtsas/common"
)

// 1. 定义技术标识类型（空结构体，轻量仅做类型区分，无存储数据）
// 每个类型唯一对应一种技术，且实现GetTechName()方法返回固定字符串
type TechJava struct{}
type TechJs struct{}
type TechCsharp struct{}

// 2. 定义核心约束接口Tech
// 约束：仅允许TechJava/TechJs/TechCsharp三种类型，且必须实现GetTechName()方法
type Tech interface {
	TechJava | TechJs | TechCsharp
	GetTechName() string // 强制每个类型实现“获取技术名字符串”的方法
}

// 3. 为每个技术类型实现GetTechName()方法（核心：返回对应固定字符串）
func (t TechJava) GetTechName() string {
	return "java" // TechJava固定获取"java"
}

func (t TechJs) GetTechName() string {
	return "js" // TechJs固定获取"js"
}

func (t TechCsharp) GetTechName() string {
	return "csharp" // TechCsharp固定获取"csharp"
}

// 要求 Tech 必须是 TechJava TechJs TechCsharp 中的一个，且类似 TechJava 可以获取 java 字符串
type InsiderExecutor[T Tech] struct {
	ToolInfo    // 匿名字段
	tech        T
	workdir     string
	command_dir string
	reportPath  string
}

// 占位符替换
func (i *InsiderExecutor[T]) replaceCommand(scan_files []string) error {

	// 替换占位符
	i.Command = strings.ReplaceAll(i.Command, "{language_type}", string(i.tech.GetTechName()))
	i.Command = strings.ReplaceAll(i.Command, "{scan_files}", strings.Join(scan_files, " "))

	// 检查是否还有未定义占位符
	if strings.Contains(i.Command, "{") && strings.Contains(i.Command, "}") {
		// 提取占位符
		start := strings.Index(i.Command, "{")
		end := strings.Index(i.Command, "}")
		if start != -1 && end != -1 && end > start {
			placeholder := i.Command[start+1 : end]
			return fmt.Errorf("未定义占位符：%s", placeholder)
		}
	}
	return nil
}

// NewInsiderExecutor 创建新的 InsiderExecutor 实例，在初始化时完成命令替换
func NewInsiderExecutor[T Tech](toolinfo ToolInfo, work_dir string, scan_files []string) (*InsiderExecutor[T], error) {
	t := T{}
	InsiderExecutor := &InsiderExecutor[T]{
		ToolInfo: ToolInfo{
			Name:               toolinfo.Name,
			Version:            toolinfo.Version,
			Path:               toolinfo.Path,
			Command:            toolinfo.Command, // 使用替换后的命令
			SupportedLanguages: toolinfo.SupportedLanguages,
		},
		tech:       t,
		workdir:    work_dir,
		reportPath: filepath.Join(work_dir, fmt.Sprintf("insider.%s_report.json", t.GetTechName())),
	}

	// 占位符替换
	if err := InsiderExecutor.replaceCommand(scan_files); err != nil {
		return nil, err
	}
	return InsiderExecutor, nil
}

// GetToolInfo 返回工具信息
func (i *InsiderExecutor[T]) GetToolInfo() ToolInfo {
	return i.ToolInfo
}

// Execute 执行命令（命令已在初始化时替换完成，不需要参数）
func (i *InsiderExecutor[T]) Execute() *ExecutionResult {
	// 根据操作系统选择合适的 shell 执行命令
	var cmd *exec.Cmd

	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/C", i.Command)
	} else {
		cmd = exec.Command("sh", "-c", i.Command)
	}

	cmd.Dir = i.workdir
	// 执行命令并捕获输出
	output, err := cmd.CombinedOutput()
	exitCode := 0
	success := false

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			// 工具正常执行但返回非零退出码
			exitCode = exitErr.ExitCode()
			// 根据 Insider 工具特性判断是否算成功
			success = isExitCodeAcceptable("Insider", exitCode)
		} else {
			// 真正的执行错误（命令找不到、权限问题等）
			exitCode = -1
			success = false
		}
	} else {
		// 完全成功（退出码为0）
		exitCode = 0
		success = true
	}

	// 如果在 work_dir 下找到 report.json，则重命名为 reportPath
	reportPath := filepath.Join(i.workdir, "report.json")
	if _, err := os.Stat(reportPath); err == nil {
		if err := os.Rename(reportPath, i.reportPath); err != nil {
			fmt.Printf("Failed to rename report.json: %v\n", err)
		}
	}

	return &ExecutionResult{
		Success:  success,
		Output:   output,
		Error:    err,
		ExitCode: exitCode,
	}
}

func (i *InsiderExecutor[T]) GetReportPath() string {
	return i.reportPath
}
