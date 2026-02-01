package scheduler

import (
	"fmt"
	"slices"
	"sync"

	. "github.com/mtsas/common"
	"github.com/mtsas/executor"
	"github.com/mtsas/fileManager"
	"github.com/mtsas/parser"
	"github.com/mtsas/systemConfigParser"
)

// Scheduler 调度器
type Scheduler struct {
	flagResult      *ScanFlag
	fileManager     *fileManager.FileManager
	sysConfigResult *systemConfigParser.SystemConfigResult
	tools           map[Executor]Parser
}

// NewScheduler 创建调度器
func NewScheduler(flagResult *ScanFlag, sysConfigResult *systemConfigParser.SystemConfigResult) *Scheduler {
	return &Scheduler{
		flagResult:      flagResult,
		fileManager:     nil,
		sysConfigResult: sysConfigResult,
		tools:           nil,
	}
}

func (s *Scheduler) Init() error {
	s.fileManager = fileManager.NewFileManager(s.flagResult.OutputDir, s.flagResult.ProjectName)

	// 创建 tmpdir
	tmpDir, err := s.fileManager.CreateTmpDir()
	ConsoleLogger.Debug(fmt.Sprintf("tmpDir: %s", tmpDir))
	if err != nil {
		return err
	}

	return nil
}

func (s *Scheduler) Scheduler() {
	// 1. 调用 getTools 获取工具
	if err := s.getTools(); err != nil {
		ConsoleLogger.Error(err.Error())
	}

	// 2. 并行执行工具
	var unifiedVulnerabilities []UnifiedVulnerability
	var wg sync.WaitGroup
	var mutex sync.Mutex
	for exec, parser := range s.tools {
		wg.Add(1)
		go func(exec Executor, parser Parser) {
			defer wg.Done()
			executeResult := exec.Execute()
			if !executeResult.Success {
				ConsoleLogger.Error(fmt.Sprintf("工具 %s 执行失败：%s，输出信息：%s", exec.GetToolInfo().Name, executeResult.Error, executeResult.Output))
				return
			}
			vulnerabilities, err := parser.Parse()
			if err != nil {
				ConsoleLogger.Error(fmt.Sprintf("解析器 %s 解析结果失败：%s", parser.GetName(), err.Error()))
				return
			}
			mutex.Lock()
			unifiedVulnerabilities = append(unifiedVulnerabilities, vulnerabilities...)
			mutex.Unlock()
		}(exec, parser)
	}
	wg.Wait()
	ConsoleLogger.Info("所有工具执行完成")

	switch s.flagResult.OutputFormat {
	case "json":
		path, _ := s.fileManager.CreateOutputFormatFile("json")
		StructsToJSONFile(unifiedVulnerabilities, path)
	case "csv":
		path, _ := s.fileManager.CreateOutputFormatFile("csv")
		StructsToCSVFile(unifiedVulnerabilities, path)
	default:
		ConsoleLogger.Error("不支持的输出格式")
	}
}

// map[Executor]Paser <- map[ExecuotorName][]path

// scan_files map[Language][]path; 使用 Lanugage -> map[Lanuage][]ExecutorName
func (s *Scheduler) getTools() error {
	var tools map[Executor]Parser = make(map[Executor]Parser)

	toolNamesToPaths := s.getMapToolNameToPaths()

	// 调式信息
	for executorName, paths := range toolNamesToPaths {
		ConsoleLogger.Debug(fmt.Sprintf("ExecutorName: %s, Paths: %+v", executorName, paths))
	}

	for executorName, paths := range toolNamesToPaths {
		executer, parser, err := s.initExecutorAndParser(executorName, paths)
		if err != nil {
			ConsoleLogger.Warning(fmt.Sprintf("%s 初始化失败: %s", executorName, err.Error()))
			continue
		}
		tools[executer] = parser
	}
	s.tools = tools
	return nil
}

// 遍历 scan_files ，提取 sysConfigResult.Tools 中支持该语言的工具名称，得到 map[ExecutorName]paths
func (s *Scheduler) getMapToolNameToPaths() map[string][]string {
	var result map[string][]string = make(map[string][]string)
	// 遍历 scan_files
	for language, paths := range s.flagResult.ScanFiles {
		toolNames := s.getToolNamesByLanguage(language)
		for _, toolName := range toolNames {
			result[toolName] = append(result[toolName], paths...)
		}
	}

	return result
}

// 遍历 systemConfigResult 中的 Tools，获取支持扫描指定 Lanuage 的工具名称
func (s *Scheduler) getToolNamesByLanguage(language Language) []string {
	var toolNames []string = make([]string, 0)
	for _, tool := range s.sysConfigResult.Tools {
		if slices.Contains(tool.SupportedLanguages, language) {
			// 特殊处理 insider 工具，它的工具名称需要带上解析的语言
			if tool.Name == "insider" {
				toolNames = append(toolNames, fmt.Sprintf("insider:%s", string(language)))
				break
			}
			toolNames = append(toolNames, tool.Name)
		}
	}
	return toolNames
}

// 根据工具名称初始化 Executor 和 Parser
func (s *Scheduler) initExecutorAndParser(toolName string, paths []string) (Executor, Parser, error) {
	tmpDir := s.fileManager.GetTmpDir()
	switch toolName {
	case "pylint":
		// 初始化 executor
		pylintExecutor, err := executor.NewPylintExecutor(s.sysConfigResult.Tools["pylint"], tmpDir, paths)
		if err != nil {
			return nil, nil, err
		}
		// 获取报告文件路径
		report_path := pylintExecutor.GetReportPath()

		// 获取 pylint cwe 映射数据库的地址
		ConsoleLogger.Debug(fmt.Sprintf("systemConfigReuslt.CweMapping: %+v", s.sysConfigResult.CweMapping))
		cwe_db_path := s.sysConfigResult.CweMapping["pylint"]
		// 初始化 parser
		pylintParser, err := parser.NewPylintParser(report_path, cwe_db_path)
		if err != nil {
			return nil, nil, err
		}

		return pylintExecutor, pylintParser, nil
	case "bandit":
		banditExecutor, err := executor.NewBanditExecutor(s.sysConfigResult.Tools["bandit"], tmpDir, paths)
		if err != nil {
			return nil, nil, err
		}
		report_path := banditExecutor.GetReportPath()
		banditParser := parser.NewBanditParser(report_path)

		return banditExecutor, banditParser, nil
	case "horusec":
		horusecExecutor, err := executor.NewHorusecExecutor(s.sysConfigResult.Tools["horusec"], tmpDir, s.flagResult.ScanDir, s.flagResult.Exclude)
		if err != nil {
			return nil, nil, err
		}
		report_path := horusecExecutor.GetReportPath()
		horusecParser := parser.NewHorusecParser(report_path)

		return horusecExecutor, horusecParser, nil
	case "semgrep":
		semgrepExecutor, err := executor.NewSemgrepExecutor(s.sysConfigResult.Tools["semgrep"], tmpDir, paths)
		if err != nil {
			return nil, nil, err
		}
		report_path := semgrepExecutor.GetReportPath()
		semgrepParser := parser.NewSemgrepParser(report_path)

		return semgrepExecutor, semgrepParser, nil
	case "insider:java":
		// 获取 work_dir，即 tmp_dir
		insiderExecutor, err := executor.NewInsiderExecutor[executor.TechJava](s.sysConfigResult.Tools["insider"], tmpDir, paths)
		if err != nil {
			return nil, nil, err
		}
		report_path := insiderExecutor.GetReportPath()
		insiderParser := parser.NewInsiderParser(report_path)

		return insiderExecutor, insiderParser, nil
	case "insider:javascript":
		// 获取 work_dir，即 tmp_dir
		insiderExecutor, err := executor.NewInsiderExecutor[executor.TechJs](s.sysConfigResult.Tools["insider"], tmpDir, paths)
		if err != nil {
			return nil, nil, err
		}
		report_path := insiderExecutor.GetReportPath()
		insiderParser := parser.NewInsiderParser(report_path)

		return insiderExecutor, insiderParser, nil
	case "insider:csharp":
		// 获取 work_dir，即 tmp_dir
		insiderExecutor, err := executor.NewInsiderExecutor[executor.TechCsharp](s.sysConfigResult.Tools["insider"], tmpDir, paths)
		if err != nil {
			return nil, nil, err
		}
		report_path := insiderExecutor.GetReportPath()
		insiderParser := parser.NewInsiderParser(report_path)

		return insiderExecutor, insiderParser, nil
	case "cppcheck":
		cppcheckExecutor, err := executor.NewCppcheckExecutor(s.sysConfigResult.Tools["cppcheck"], tmpDir, paths)
		if err != nil {
			return nil, nil, err
		}
		report_path := cppcheckExecutor.GetReportPath()
		cppcheckParser := parser.NewCppcheckParser(report_path)

		return cppcheckExecutor, cppcheckParser, nil
	default:
		return nil, nil, fmt.Errorf("不支持的工具 %s", toolName)
	}
}
