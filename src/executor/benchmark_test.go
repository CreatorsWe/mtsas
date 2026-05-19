package executor

import (
	"fmt"
	"testing"

	common "github.com/mtsas/common"
)

var pylint_info = common.ToolInfo{
	Name:    "pylint",
	Command: "pylint {scan_files}",
}

var bandit_info = common.ToolInfo{
	Name:    "bandit",
	Command: "bandit -r {scan_files}",
}

var horusec_info = common.ToolInfo{
	Name:    "horusec",
	Command: "horusec start --disable-docker -p {target_dir}",
}

var semgrep_info = common.ToolInfo{
	Name:    "semgrep",
	Command: "semgrep scan --quiet {scan_files}",
}

var insider_info = common.ToolInfo{
	Name:    "insider",
	Command: "insider -tech {language_type} -no-html -target {target_dir}",
}

var cppcheck_info = common.ToolInfo{
	Name:    "cppcheck",
	Command: "cppcheck --enable=all {scan_files}",
}

func BenchmarkExecutor(b *testing.B) {
	pylint, err := NewPylintExecutor(pylint_info, ".", []string{`/home/PatrickStar/Downloads/mtsas/example_code/python/demo.py`})
	if err != nil {
		fmt.Printf("pylint 初始化失败")
		return
	}

	bandit, err := NewBanditExecutor(bandit_info, ".", []string{`home/PatrickStar/Downloads/mtsas/example_code/python/demo.py`})
	if err != nil {
		fmt.Printf("bandit 初始化失败")
		return
	}

	horusec, err := NewHorusecExecutor(horusec_info, ".", `/home/PatrickStar/Downloads/mtsas/example_code/python`, []string{})
	if err != nil {
		fmt.Printf("horusec 初始化失败")
		return
	}

	semgrep, err := NewSemgrepExecutor(semgrep_info, ".", []string{`home/PatrickStar/Downloads/mtsas/example_code/python/demo.py`})
	if err != nil {
		fmt.Printf("semgrep 初始化失败")
		return
	}

	insider, err := NewInsiderExecutor[TechJava](insider_info, ".", `/home/PatrickStar/Downloads/mtsas/example_code/java`)
	if err != nil {
		fmt.Printf("insider 初始化失败")
		return
	}

	cppcheck, err := NewCppcheckExecutor(cppcheck_info, ".", []string{`/home/PatrickStar/Downloads/mtsas/example_code/cpp/demo1.cpp`})
	if err != nil {
		fmt.Printf("cppcheck 初始化失败")
		return
	}

	var output interface{}

	b.Run("pylint_bench", func(b *testing.B) {
		var out interface{}
		for i := 0; i < b.N; i++ {
			out = pylint.Execute()
		}
		output = out
	})

	b.Run("bandit_bench", func(b *testing.B) {
		var out interface{}
		for i := 0; i < b.N; i++ {
			out = bandit.Execute()
		}
		output = out
	})

	b.Run("semgrep_bench", func(b *testing.B) {
		var out interface{}
		for i := 0; i < b.N; i++ {
			out = semgrep.Execute()
		}
		output = out
	})

	b.Run("horusec_bench", func(b *testing.B) {
		var out interface{}
		for i := 0; i < b.N; i++ {
			out = horusec.Execute()
		}
		output = out
	})

	b.Run("insider_bench", func(b *testing.B) {
		var out interface{}
		for i := 0; i < b.N; i++ {
			out = insider.Execute()
		}
		output = out
	})

	b.Run("cppcheck_bench", func(b *testing.B) {
		var out interface{}
		for i := 0; i < b.N; i++ {
			out = cppcheck.Execute()
		}
		output = out
	})

	_ = output
}
