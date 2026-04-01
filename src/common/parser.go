package common

type Parser interface {
	GetName() string
	Parse() ([]UnifiedVulnerability, error)
}
