module github.com/mtsas/parser

replace github.com/mtsas/common => ../common

replace github.com/mtsas/cweMapper => ../cweMapper

replace github.com/mtsas/logger => ../logger

go 1.25.5

require (
	github.com/mtsas/common v0.0.0-00010101000000-000000000000
//golang.org/x/net v0.49.0
)

require github.com/mtsas/logger v0.0.0-00010101000000-000000000000 // indirect
