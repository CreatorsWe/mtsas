package utility

import (
	"math"

	. "github.com/mtsas/common"
)

func GetScore(severity SeverityLevel, confidence ConfidenceLevel, count int) float64 {
	// ======================== 1. 基础分（严重性）========================
	baseScore := 0.0
	switch severity {
	case SeverityLevelCritical:
		baseScore = 9.0
	case SeverityLevelHigh:
		baseScore = 7.0
	case SeverityLevelMedium:
		baseScore = 5.0
	case SeverityLevelLow:
		baseScore = 2.5
	case SeverityLevelUnknown:
		baseScore = 2.0
	}

	// ======================== 2. 置信度系数（越高越准，分数越高）========================
	confidenceCoeff := 0.0
	switch confidence {
	case ConfidenceLevelHigh:
		confidenceCoeff = 1.0
	case ConfidenceLevelMedium:
		confidenceCoeff = 0.8
	case ConfidenceLevelLow:
		confidenceCoeff = 0.5
	}

	// ======================== 3. 数量系数（越多风险越高）========================
	countCoeff := 1.0
	if count > 1 {
		// 对数增长，避免无限变大：count=1 →1，count=5→1.7，count=10→2.0
		countCoeff = 1.0 + 0.3*math.Log10(float64(count))
	}

	// ======================== 4. 计算总分 ========================
	score := baseScore * confidenceCoeff * countCoeff

	// ======================== 5. 限制在 1~10 之间 ========================
	if score < 1.0 {
		score = 1.0
	}
	if score > 10.0 {
		score = 10.0
	}

	// 保留 1 位小数（美观）
	return math.Round(score*10) / 10
}
