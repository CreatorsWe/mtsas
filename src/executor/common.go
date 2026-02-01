package executor

// 工具特定的退出码判断逻辑
func isExitCodeAcceptable(tool_name string, exitCode int) bool {
	switch tool_name {
	case "pylint":
		// pylint: 0-31 都算正常执行（0=无问题，1-31=发现问题）
		return exitCode >= 0 && exitCode <= 31
	case "bandit":
		// bandit: 0和1都算正常执行（0=无问题，1=发现问题）
		return exitCode == 0 || exitCode == 1
	case "horusec":
		// horusec: 0=无问题，1=发现问题，其他=执行错误
		return exitCode == 0 || exitCode == 1
	case "semgrep":
		// semgrep: 0=无问题，1=发现问题，其他=执行错误
		return exitCode == 0 || exitCode == 1
	case "insider":
		// insider: 0=无问题，1=发现问题，其他=执行错误
		return exitCode == 0 || exitCode == 1
	case "cppcheck":
		// cppcheck: 0=无问题，1=发现问题，其他=执行错误
		return exitCode == 0 || exitCode == 1
	default:
		// 默认行为：只有退出码0算成功
		return exitCode == 0
	}
}
