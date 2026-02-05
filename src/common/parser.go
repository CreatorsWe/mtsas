package common

type Parser interface {
	GetName() string
	Parse() ([]UnifiedVulnerability, error)
	ParseToFile(output_file string) error
}
