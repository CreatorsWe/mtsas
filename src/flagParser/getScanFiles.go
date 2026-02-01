package flagParser

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	. "github.com/mtsas/common"
)

// 后缀到 Language 的映射表,方便映射
var ExtToLanguage = map[string]Language{
	"java": LanguageJava,
	"py":   LanguagePython,
	"go":   LanguageGo,
	"c":    LanguageC,
	"cpp":  LanguageCpp,
	"cc":   LanguageCpp, // C++的另一种后缀
}

// 从 scanPath 获取要扫描的文件列表, scanPath 可以是文件或目录
// 如果是目录，递归遍历所有子目录
// excludedDirs 为要排除的目录列表，如果为 nil 则不排除任何目录
func getScanFiles(scanPath string, excludedDirs []string) (map[Language][]string, error) {
	result := make(map[Language][]string)

	// 检查 scanPath 是否存在
	fileInfo, err := os.Stat(scanPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("扫描路径不存在: %s", scanPath)
		}
		return nil, fmt.Errorf("检查扫描路径失败: %v", err)
	}

	if fileInfo.IsDir() {
		// 使用 WalkDir 递归遍历所有子目录
		err = filepath.WalkDir(scanPath, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				fmt.Printf("访问路径失败 %s: %v\n", path, err)
				return nil
			}

			// 如果是目录，检查是否需要排除
			if d.IsDir() {
				// 只有当 excludedDirs 不为 nil 时才进行排除检查
				if excludedDirs != nil {
					baseName := filepath.Base(path)
					if slices.Contains(excludedDirs, baseName) {
						return filepath.SkipDir // 跳过整个目录
					}
				}
				return nil
			}

			// 获取文件语言类型
			lang := getFileLanguage(path)
			if lang != LanguageUnknown {
				result[lang] = append(result[lang], path)
			}

			return nil
		})

		if err != nil {
			return nil, fmt.Errorf("遍历目录失败: %v", err)
		}
	} else {
		// 如果是单个文件，直接处理
		lang := getFileLanguage(scanPath)
		if lang != LanguageUnknown {
			result[lang] = []string{scanPath}
		} else {
			return nil, fmt.Errorf("不支持的文件类型: %s", scanPath)
		}
	}

	return result, nil
}

// 根据文件扩展名判断编程语言
func getFileLanguage(filename string) Language {
	ext := strings.ToLower(filepath.Ext(filename))
	if ext != "" && ext[0] == '.' {
		ext = ext[1:] // 去掉点号
	}

	// 使用映射表查找语言
	if lang, exists := ExtToLanguage[ext]; exists {
		return lang
	}

	return LanguageUnknown
}
