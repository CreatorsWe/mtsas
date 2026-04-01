package utility

import (
	"fmt"
	"sort"

	. "github.com/mtsas/common"
)

// 定义严重性等级和置信度的优先级（可根据业务调整）
var severityPriority = map[SeverityLevel]int{
	SeverityLevelCritical: 5, // 最高
	SeverityLevelHigh:     4,
	SeverityLevelMedium:   3,
	SeverityLevelLow:      2,
	SeverityLevelUnknown:  1, // 最低
}

var confidencePriority = map[ConfidenceLevel]int{
	ConfidenceLevelHigh:   3, // 最高
	ConfidenceLevelMedium: 2,
	ConfidenceLevelLow:    1, // 最低
}

// DedupDbVulnerabilities 对DbVulnerability去重：
// 1. 利用同Tool内无重复Hash的特性，先按Tool分组存储漏洞
// 2. 跨Tool识别重复Hash，筛选最优漏洞并累加WarningCount
// 3. 保留无重复Hash的漏洞和Hash为空的漏洞
func DedupDbVulnerabilities(dbVuls []DbVulnerability) ([]DbVulnerability, error) {
	// 1. 初始化分组容器
	var noHashVuls []DbVulnerability                          // 存储Hash为空的漏洞
	toolVulMap := make(map[string]map[string]DbVulnerability) // key1: Tool, key2: Hash, value: 漏洞（同Tool同Hash唯一）
	hashToolMap := make(map[string][]string)                  // key: Hash, value: 拥有该Hash的Tool列表（跨Tool去重核心）

	// 2. 按Tool分组，同时构建Hash-Tool映射
	for _, vul := range dbVuls {
		// 处理Hash为空的漏洞，直接保留
		if vul.Hash == "" || vul.Hash == "null" {
			noHashVuls = append(noHashVuls, vul)
			continue
		}

		// 校验Tool字段合法性
		tool := vul.Vulnerabilities.Tool
		if tool == "" {
			return nil, fmt.Errorf("漏洞Tool字段为空，hash：%s", vul.Hash)
		}

		// 初始化Tool对应的Hash-漏洞映射（同Tool内Hash唯一，直接覆盖即可）
		if _, ok := toolVulMap[tool]; !ok {
			toolVulMap[tool] = make(map[string]DbVulnerability)
		}
		toolVulMap[tool][vul.Hash] = vul // 同Tool同Hash唯一，直接赋值

		// 构建Hash对应的Tool列表（去重，避免重复添加同一Tool）
		if _, ok := hashToolMap[vul.Hash]; !ok {
			hashToolMap[vul.Hash] = []string{}
		}
		// 检查Tool是否已存在，不存在则添加
		toolExists := false
		for _, t := range hashToolMap[vul.Hash] {
			if t == tool {
				toolExists = true
				break
			}
		}
		if !toolExists {
			hashToolMap[vul.Hash] = append(hashToolMap[vul.Hash], tool)
		}
	}

	// 3. 处理跨Tool重复Hash的漏洞
	var dedupedVuls []DbVulnerability
	processedHash := make(map[string]bool) // 标记已处理的Hash，避免重复

	for hash, tools := range hashToolMap {
		if processedHash[hash] {
			continue
		}
		processedHash[hash] = true

		// 3.1 单Tool的Hash：直接保留漏洞
		if len(tools) == 1 {
			tool := tools[0]
			dedupedVuls = append(dedupedVuls, toolVulMap[tool][hash])
			continue
		}

		// 3.2 多Tool的重复Hash：筛选最优漏洞，并累加WarningCount
		var crossToolVuls []DbVulnerability
		totalWarningCount := 0 // 累加所有同Hash漏洞的WarningCount

		// 收集所有该Hash下的漏洞，并累加计数
		for _, tool := range tools {
			vul := toolVulMap[tool][hash]
			crossToolVuls = append(crossToolVuls, vul)
			totalWarningCount += vul.WarningCount
		}

		// 筛选最优漏洞
		optimalVul, err := selectOptimalVulnerability(crossToolVuls)
		if err != nil {
			return nil, fmt.Errorf("Hash：%s，跨Tool筛选最优漏洞失败：%w", hash, err)
		}
		// 赋值累加后的WarningCount
		optimalVul.WarningCount = totalWarningCount
		dedupedVuls = append(dedupedVuls, optimalVul)
	}

	// 4. 合并结果：去重后的Hash非空漏洞 + Hash为空的漏洞
	finalVuls := append(dedupedVuls, noHashVuls...)
	return finalVuls, nil
}

// selectOptimalVulnerability 从跨Tool的同Hash漏洞中筛选最优（严重性优先，其次置信度）
func selectOptimalVulnerability(vuls []DbVulnerability) (DbVulnerability, error) {
	if len(vuls) == 0 {
		return DbVulnerability{}, fmt.Errorf("漏洞列表为空")
	}

	// 按优先级排序：严重性降序 → 置信度降序
	sort.Slice(vuls, func(i, j int) bool {
		// 1. 比较严重性等级
		sevI := getSeverityPriority(vuls[i].Vulnerabilities.SeverityLevel)
		sevJ := getSeverityPriority(vuls[j].Vulnerabilities.SeverityLevel)
		if sevI != sevJ {
			return sevI > sevJ
		}

		// 2. 严重性相同，比较置信度
		confI := getConfidencePriority(vuls[i].Vulnerabilities.ConfidenceLevel)
		confJ := getConfidencePriority(vuls[j].Vulnerabilities.ConfidenceLevel)
		return confI > confJ
	})

	// 排序后第一个即为最优漏洞
	return vuls[0], nil
}

// getSeverityPriority 获取严重性等级的优先级数值（兼容未知等级）
func getSeverityPriority(severity SeverityLevel) int {
	if priority, ok := severityPriority[severity]; ok {
		return priority
	}
	return 0 // 未知等级优先级最低
}

// getConfidencePriority 获取置信度的优先级数值（兼容未知置信度）
func getConfidencePriority(confidence ConfidenceLevel) int {
	if priority, ok := confidencePriority[confidence]; ok {
		return priority
	}
	return 0 // 未知置信度优先级最低
}
