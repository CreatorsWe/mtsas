package featureExtractor

import (
	"fmt"
	"testing"
)

func TestFeatureExtractor(t *testing.T) {
	var file_path = `/home/PatrickStar/Downloads/mtsas/example_code/python/demo.py`
	const cwe_id = 001
	var result string
	result, _ = GetFeatureVulnTest(file_path, 6)
	fmt.Printf("测试文件: %s\n", file_path)
	fmt.Printf("代码行: 6 ScopeOffset: %s\n", result)
	result, _ = GetFeatureVulnTest(file_path, 22)
	fmt.Printf("代码行: 22 ScopeOffset: %s\n", result)
	file_path = `/home/PatrickStar/Downloads/mtsas/example_code/java/Demo1.java`
	fmt.Printf("测试文件: %s\n", file_path)
	result, _ = GetFeatureVulnTest(file_path, 16)
	fmt.Printf("代码行: 16 ScopeOffset: %s\n", result)
	result, _ = GetFeatureVulnTest(file_path, 40)
	fmt.Printf("代码行: 40 ScopeOffset: %s\n", result)
}
