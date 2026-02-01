package executor

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	. "github.com/mtsas/common"
)

type CppcheckExecutor struct {
	ToolInfo   // 匿名字段
	ReportPath string
}

// 占位符替换
func (b *CppcheckExecutor) replaceCommand(tmpdir string, scan_files []string) error {
	// 替换占位符
	b.Command = strings.ReplaceAll(b.Command, "{output_file:xml}", b.ReportPath)
	b.Command = strings.ReplaceAll(b.Command, "{scan_files}", strings.Join(scan_files, " "))

	// 检查是否还有未定义占位符
	if strings.Contains(b.Command, "{") && strings.Contains(b.Command, "}") {
		// 提取占位符
		start := strings.Index(b.Command, "{")
		end := strings.Index(b.Command, "}")
		if start != -1 && end != -1 && end > start {
			placeholder := b.Command[start+1 : end]
			return fmt.Errorf("未定义占位符：%s", placeholder)
		}
	}
	return nil
}

// NewCppcheckExecutor 创建新的 CppcheckExecutor 实例，在初始化时完成命令替换
func NewCppcheckExecutor(toolinfo ToolInfo, tmpdir string, scan_files []string) (*CppcheckExecutor, error) {

	CppcheckExecutor := &CppcheckExecutor{
		ToolInfo: ToolInfo{
			Name:               toolinfo.Name,
			Version:            toolinfo.Version,
			Path:               toolinfo.Path,
			Command:            toolinfo.Command, // 使用替换后的命令
			SupportedLanguages: toolinfo.SupportedLanguages,
		},
		ReportPath: filepath.Join(tmpdir, fmt.Sprintf("%s_report.xml", toolinfo.Name)),
	}
	if err := CppcheckExecutor.replaceCommand(tmpdir, scan_files); err != nil {
		return nil, err
	}
	return CppcheckExecutor, nil
}

// GetToolInfo 返回工具信息
func (p *CppcheckExecutor) GetToolInfo() ToolInfo {
	return p.ToolInfo
}

// Execute 执行命令（命令已在初始化时替换完成，不需要参数）
func (p *CppcheckExecutor) Execute() *ExecutionResult {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/C", p.Command)
	} else {
		cmd = exec.Command("sh", "-c", p.Command)
	}

	output, err := cmd.CombinedOutput()
	exitCode := 0
	success := false

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			// 工具正常执行但返回非零退出码
			exitCode = exitErr.ExitCode()
			// 根据工具类型判断是否算成功
			success = isExitCodeAcceptable("Cppcheck", exitCode)
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

	return &ExecutionResult{
		Success:  success,
		Output:   output,
		Error:    err,
		ExitCode: exitCode,
	}
}

func (c *CppcheckExecutor) GetReportPath() string {
	return c.ReportPath
}
