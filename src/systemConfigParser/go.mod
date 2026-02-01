module github.com/mtsas/systemConfigParser

replace github.com/mtsas/common => ../common

replace github.com/mtsas/logger => ../logger

go 1.25.5

require (
	github.com/mtsas/common v0.0.0-00010101000000-000000000000
	github.com/pelletier/go-toml/v2 v2.2.4
)

require github.com/mtsas/logger v0.0.0-00010101000000-000000000000 // indirect
