package scheduler

import (
	"fmt"
	"os"
	"slices"
	"sync"
	"time"

	. "github.com/mtsas/common"
	"github.com/mtsas/cweMapper"
	"github.com/mtsas/dbManager"
	"github.com/mtsas/executor"
	"github.com/mtsas/featureExtractor"
	"github.com/mtsas/fileManager"
	"github.com/mtsas/parser"
	"github.com/mtsas/scheduler/utility"
	"github.com/mtsas/systemConfigParser"
)

// Scheduler 调度器
type Scheduler struct {
	flagResult      *ScanFlag
	fileManager     *fileManager.FileManager
	sysConfigResult *systemConfigParser.SystemConfigResult
	tools           map[Executor]Parser
	queryInterface  func(string, string) (int, error)
}

// NewScheduler 创建调度器
func NewScheduler(flagResult *ScanFlag, sysConfigResult *systemConfigParser.SystemConfigResult) *Scheduler {
	return &Scheduler{
		flagResult:      flagResult,
		fileManager:     nil,
		sysConfigResult: sysConfigResult,
		tools:           nil,
		queryInterface:  nil,
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
	// 初始化 CWE 映射器
	cweMapper, err := cweMapper.NewCWEMapper(s.sysConfigResult.CweMapping.Path, s.sysConfigResult.CweMapping.Maps)
	if err != nil {
		ConsoleLogger.Error(err.Error())
		os.Exit(0)
	}

	s.queryInterface = cweMapper.QueryRecord

	// 1. 调用 getTools 获取工具
	if err := s.getTools(); err != nil {
		ConsoleLogger.Error(err.Error())
		os.Exit(0)
	}
	// 2. 并行执行工具
	var unifiedVulnerabilities []UnifiedVulnerability
	var wg sync.WaitGroup
	var mutex sync.Mutex
	for exec, parser := range s.tools {
		wg.Add(1)
		go func(exec Executor, parser Parser) {
			defer wg.Done()
			start := time.Now()
			executeResult := exec.Execute()
			if !executeResult.Success {
				ConsoleLogger.Error(fmt.Sprintf("工具 %s 执行失败：%s，输出信息：%s", exec.GetToolInfo().Name, executeResult.Error, executeResult.Output))
				return
			}
			executeTime := time.Since(start)
			ConsoleLogger.Info(fmt.Sprintf("工具 %s 执行成功，耗时 %.2f", exec.GetToolInfo().Name, executeTime.Seconds()))
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

	// 去重
	var final_dbVulnerabilities []DbVulnerability = make([]DbVulnerability, 0)
	// 有 cwe 的漏洞，计算 hash 去重
	var m_hash_vuln map[string]DbVulnerability = make(map[string]DbVulnerability)
	// 1. 分离有无 cwe 的漏洞
	// 2. 对有 cwe 的漏洞计算 hash ，得到 map[hash][DbVulner] 如果 hash 相同去重
	// 3. 合并所有漏洞
	for _, vuln := range unifiedVulnerabilities {
		if vuln.CWEID == -1 {
			// 计算得分
			dbvuln := DbVulnerability{
				Vulnerabilities: vuln,
				WarningCount:    1,
				Hash:            "",
				Score:           utility.GetScore(vuln.SeverityLevel, vuln.ConfidenceLevel, 1),
			}
			final_dbVulnerabilities = append(final_dbVulnerabilities, dbvuln)
		} else {
			hash, err := featureExtractor.GetFeatureVuln(vuln.FilePath, vuln.Line, vuln.CWEID)
			if err != nil {
				ConsoleLogger.Warning(fmt.Sprintf("计算漏洞特征失败: %s,丢弃该漏洞: %+v", err, vuln))
				continue
			}
			if old, exists := m_hash_vuln[hash]; !exists {
				m_hash_vuln[hash] = DbVulnerability{
					Vulnerabilities: vuln,
					WarningCount:    1,
					Hash:            hash,
					Score:           utility.GetScore(vuln.SeverityLevel, vuln.ConfidenceLevel, 1),
				}
			} else {
				// 计算 old 和 vuln 的得分，取分高者
				old_score := utility.GetScore(old.Vulnerabilities.SeverityLevel, old.Vulnerabilities.ConfidenceLevel, 1)
				new_score := utility.GetScore(vuln.SeverityLevel, vuln.ConfidenceLevel, 1)
				if new_score > old_score {
					m_hash_vuln[hash] = DbVulnerability{
						Vulnerabilities: vuln,
						WarningCount:    old.WarningCount + 1,
						Hash:            hash,
						Score:           -1, // 暂时不计分
					}
				} else {
					m_hash_vuln[hash] = DbVulnerability{
						Vulnerabilities: old.Vulnerabilities,
						WarningCount:    old.WarningCount + 1,
						Hash:            hash,
						Score:           -1,
					}
				}
			}
		}
	}

	// 对 m_hash_vuln 计算得分后并入 final_dbVulnerabilities
	for _, vuln := range m_hash_vuln {
		vuln.Score = utility.GetScore(vuln.Vulnerabilities.SeverityLevel, vuln.Vulnerabilities.ConfidenceLevel, vuln.WarningCount)
		final_dbVulnerabilities = append(final_dbVulnerabilities, vuln)
	}

	// 存储在数据库中
	// 1. 创建数据库
	vulnerdbPath, err := s.fileManager.CreateVulnerDB()
	if err != nil {
		ConsoleLogger.Error(fmt.Sprintf("漏洞数据库创建失败: %s", err))
		os.Exit(0)
	}
	// 2. 初始化数据库对象
	vulnerDB, err := dbManager.NewDbManager(vulnerdbPath)
	if err != nil {
		ConsoleLogger.Error(fmt.Sprintf("漏洞数据库连接失败: %s", err))
		os.Exit(0)
	}
	// 3. 存储数据库中
	count, _, err := vulnerDB.BatchInsertVulnerabilities(final_dbVulnerabilities)
	if err != nil {
		ConsoleLogger.Warning(fmt.Sprintf("数据库插入失败: %s", err))
	}
	ConsoleLogger.Info(fmt.Sprintf("成功插入 %d 条漏洞信息", count))

	// 输出文件
	switch s.flagResult.OutputFormat {
	case "json":
		path, _ := s.fileManager.CreateOutputFormatFile("json")
		utility.StructsToJSONFile(final_dbVulnerabilities, path)
	case "csv":
		path, _ := s.fileManager.CreateOutputFormatFile("csv")
		utility.StructsToCSVFile(final_dbVulnerabilities, path)
	default:
		ConsoleLogger.Error(fmt.Sprintf("不支持的输出格式: %s", s.flagResult.OutputFormat))
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

		// 初始化 parser
		if s.queryInterface == nil {
			return nil, nil, fmt.Errorf("pylintparser 需要 cwe 预映射库查询接口")
		}
		pylintParser := parser.NewPylintParser(report_path, s.queryInterface)

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
		horusecParser := parser.NewHorusecParser(report_path, s.flagResult.ScanDir)

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
		insiderExecutor, err := executor.NewInsiderExecutor[executor.TechJava](s.sysConfigResult.Tools["insider"], tmpDir, s.flagResult.ScanDir)
		if err != nil {
			return nil, nil, err
		}
		report_path := insiderExecutor.GetReportPath()
		insiderParser := parser.NewInsiderParser(report_path)

		return insiderExecutor, insiderParser, nil
	case "insider:javascript":
		// 获取 work_dir，即 tmp_dir
		insiderExecutor, err := executor.NewInsiderExecutor[executor.TechJs](s.sysConfigResult.Tools["insider"], tmpDir, s.flagResult.ScanDir)
		if err != nil {
			return nil, nil, err
		}
		report_path := insiderExecutor.GetReportPath()
		insiderParser := parser.NewInsiderParser(report_path)

		return insiderExecutor, insiderParser, nil
	case "insider:csharp":
		// 获取 work_dir，即 tmp_dir
		insiderExecutor, err := executor.NewInsiderExecutor[executor.TechCsharp](s.sysConfigResult.Tools["insider"], tmpDir, s.flagResult.ScanDir)
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
		if s.queryInterface == nil {
			return nil, nil, fmt.Errorf("cppcheckparser 需要 cwe 预映射库查询接口")
		}
		cppcheckParser := parser.NewCppcheckParser(report_path, s.queryInterface)

		return cppcheckExecutor, cppcheckParser, nil
	default:
		return nil, nil, fmt.Errorf("不支持的工具 %s", toolName)
	}
}
