package fileManager

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type FileManager struct {
	OutputDir   string
	ProjectName string
	timeDir     string
}

func NewFileManager(outputDir string, projectName string) *FileManager {
	return &FileManager{
		OutputDir:   outputDir,
		ProjectName: projectName,
	}
}

// 目录结构如下：
// .mtsas
// ├── <ProjectName>
// │   │── <时间：年-月-日_时.分.秒>,如 2026-1-24_11.42.23
// │   ├── .tmp
// │   │   ├── <toolname>_result.json
// │   └── <ProjectName>_result.json

func (f *FileManager) GetMtsasDir() string {
	return filepath.Join(f.OutputDir, ".mtsas")
}

// 在 OutputDir 目录中创建 .mtsas 目录，如果存在，则不创建
// func (f *FileManager) CreateMtsasDir() error {
// 	mtsasDir := f.GetMtsasDir()
// 	if _, err := os.Stat(mtsasDir); os.IsNotExist(err) {
// 		err := os.MkdirAll(mtsasDir, 0755)
// 		if err != nil {
// 			return err
// 		}
// 	}
// 	return nil
// }

func (f *FileManager) GetProjectDir() string {
	return filepath.Join(f.GetMtsasDir(), f.ProjectName)
}

// 在 .mtsas 目录中创建名称为 ProjectName 的目录，如果存在，则不创建
// func (f *FileManager) CreateProjectDir() error {
// 	projectDir := f.GetProjectDir()
// 	if _, err := os.Stat(projectDir); os.IsNotExist(err) {
// 		err := os.MkdirAll(projectDir, 0755)
// 		if err != nil {
// 			return err
// 		}
// 	}
// 	return nil
// }

func (f *FileManager) GetTimeDir() string {
	if f.timeDir == "" {
		timeStr := time.Now().Format("2006-1-2_15.04.05")
		f.timeDir = filepath.Join(f.GetProjectDir(), timeStr)
		return f.timeDir
	} else {
		return f.timeDir
	}
}

// 在 ProjectName 目录下创建 时间 目录
// func (f *FileManager) CreateTimeDir() error {
// 	timeDir := f.GetTimeDir()
// 	if _, err := os.Stat(timeDir); os.IsNotExist(err) {
// 		err := os.MkdirAll(timeDir, 0755)
// 		if err != nil {
// 			return err
// 		}
// 	}
// 	return nil
// }

func (f *FileManager) GetTmpDir() string {
	timeDir := f.GetTimeDir()
	return filepath.Join(timeDir, ".tmp")
}

// 在 .mtsas/ProjectName/Time 目录中创建名称为 .tmp 的目录，如果存在，则不创建
func (f *FileManager) CreateTmpDir() (string, error) {
	tmpDir := f.GetTmpDir()

	// 	// 确保父目录存在
	dir := filepath.Dir(tmpDir)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("创建目录失败: %w", err)
	}
	if _, err := os.Stat(tmpDir); os.IsNotExist(err) {
		err := os.MkdirAll(tmpDir, 0755)
		if err != nil {
			return "", err
		}
	}
	return tmpDir, nil
}

// 在 .mtsas/ProjectName/Time/.tmp 目录中删除名称为 .tmp 的目录，如果不存在，则不删除
func (f *FileManager) RemoveTmpDir() error {
	tmpDir := f.GetTmpDir()
	if _, err := os.Stat(tmpDir); err == nil {
		return os.RemoveAll(tmpDir)
	}
	return nil
}

// func (f *FileManager) CreateToolOutputFile(toolName string) error {
// 	outputFile := f.GetToolOutputFile(toolName)

// 	// 确保父目录存在
// 	dir := filepath.Dir(outputFile)
// 	if err := os.MkdirAll(dir, 0755); err != nil {
// 		return fmt.Errorf("创建目录失败: %w", err)
// 	}

// 	if _, err := os.Stat(outputFile); os.IsNotExist(err) {
// 		file, err := os.Create(outputFile)
// 		if err != nil {
// 			return fmt.Errorf("创建工具输出文件失败: %w", err)
// 		}
// 		defer file.Close()
// 	}
// 	return nil
// }

func (f *FileManager) GetOutputFormatFile(outputFormat string) string {
	timeDir := f.GetTimeDir()

	filename := fmt.Sprintf("%s_result.%s", f.ProjectName, outputFormat)
	return filepath.Join(timeDir, filename)
}

// 在 .mtsas/ProjectName/Time 目录中创建名称为 <ProjectName>_result.json 文件，如果存在，则不创建
func (f *FileManager) CreateOutputFormatFile(outputFormat string) (string, error) {
	outputFile := f.GetOutputFormatFile(outputFormat)

	dir := filepath.Dir(outputFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("创建目录失败: %w", err)
	}
	if _, err := os.Stat(outputFile); os.IsNotExist(err) {
		file, err := os.Create(outputFile)
		if err != nil {
			return "", err
		}
		defer file.Close()
	}
	return outputFile, nil
}
