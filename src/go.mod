module github.com/mtsas

replace github.com/mtsas/common => ./common

replace github.com/mtsas/logger => ./logger

replace github.com/mtsas/flagParser => ./flagParser

replace github.com/mtsas/fileManager => ./fileManager

replace github.com/mtsas/systemConfigParser => ./systemConfigParser

replace github.com/mtsas/executor => ./executor

replace github.com/mtsas/parser => ./parser

replace github.com/mtsas/cweMapper => ./cweMapper

replace github.com/mtsas/scheduler => ./scheduler

go 1.25.5

require (
	github.com/mtsas/common v0.0.0-00010101000000-000000000000
	github.com/mtsas/flagParser v0.0.0-00010101000000-000000000000
	github.com/mtsas/scheduler v0.0.0-00010101000000-000000000000
	github.com/mtsas/systemConfigParser v0.0.0-00010101000000-000000000000
)

require (
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mtsas/cweMapper v0.0.0-00010101000000-000000000000 // indirect
	github.com/mtsas/executor v0.0.0-00010101000000-000000000000 // indirect
	github.com/mtsas/fileManager v0.0.0-00010101000000-000000000000 // indirect
	github.com/mtsas/logger v0.0.0-00010101000000-000000000000 // indirect
	github.com/mtsas/parser v0.0.0-00010101000000-000000000000 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/pelletier/go-toml/v2 v2.2.4 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	golang.org/x/exp v0.0.0-20251023183803-a4bb9ffd2546 // indirect
	golang.org/x/sys v0.37.0 // indirect
	modernc.org/libc v1.67.6 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
	modernc.org/sqlite v1.44.3 // indirect
)
