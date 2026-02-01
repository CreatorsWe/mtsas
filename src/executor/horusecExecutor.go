package executor

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	. "github.com/mtsas/common"
)

type HorusecExecutor struct {
	ToolInfo   // 匿名字段
	ReportPath string
}

// 占位符替换
func (b *HorusecExecutor) replaceCommand(tmpdir string, target_dir string, exclude_dirs []string) error {
	// 替换占位符
	b.Command = strings.ReplaceAll(b.Command, "{output_file:json}", b.ReportPath)
	b.Command = strings.ReplaceAll(b.Command, "{target_dir}", target_dir)
	b.Command = strings.ReplaceAll(b.Command, "{exclude_dirs}", b.handleExcludeDirs(exclude_dirs))

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

// 返回合法的 horusec -i 字段，在目录末尾加上 /** ，每个目录间用 , 分隔
func (b *HorusecExecutor) handleExcludeDirs(exclude_dirs []string) string {
	for i, dir := range exclude_dirs {
		dir = strings.TrimRight(dir, "/")
		exclude_dirs[i] = fmt.Sprintf("%s/**", dir)
	}
	return strings.Join(exclude_dirs, ",")
}

// NewHorusecExecutor 创建新的 HorusecExecutor 实例，在初始化时完成命令替换
func NewHorusecExecutor(toolinfo ToolInfo, tmpdir string, target_dir string, exclude_dirs []string) (*HorusecExecutor, error) {

	horusecExecutor := &HorusecExecutor{
		ToolInfo: ToolInfo{
			Name:               toolinfo.Name,
			Version:            toolinfo.Version,
			Path:               toolinfo.Path,
			Command:            toolinfo.Command, // 使用替换后的命令
			SupportedLanguages: toolinfo.SupportedLanguages,
		},
		ReportPath: filepath.Join(tmpdir, fmt.Sprintf("%s_report.json", toolinfo.Name)),
	}

	if err := horusecExecutor.replaceCommand(tmpdir, target_dir, exclude_dirs); err != nil {
		return nil, err
	}

	return horusecExecutor, nil
}

// GetToolInfo 返回工具信息
func (p *HorusecExecutor) GetToolInfo() ToolInfo {
	return p.ToolInfo
}

// Execute 执行命令（命令已在初始化时替换完成，不需要参数）
func (p *HorusecExecutor) Execute() *ExecutionResult {
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
			success = isExitCodeAcceptable("Horusec", exitCode)
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

func (h *HorusecExecutor) GetReportPath() string {
	return h.ReportPath
}
