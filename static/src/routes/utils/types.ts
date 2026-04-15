// 对应 Go: SeverityLevel / ConfidenceLevel
export type SeverityLevel = "UNKNOWN" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type ConfidenceLevel = "LOW" | "MEDIUM" | "HIGH";

// 对应 Go: UnifiedVulnerability
export interface UnifiedVulnerability {
  tool: string;
  warning_id: string;
  category: string;
  short_message: string; // 后端字段拼写
  cwe_id: number;
  file_path: string;
  line: number;
  severity_level: SeverityLevel;
  confidence_level: ConfidenceLevel;
}

// 对应 Go: DbVulnerability
export interface DbVulnerability {
  vulnerabilities: UnifiedVulnerability;
  hash: string;
  warningCount: number;
  score: number;
  final_score: number;
}

// 对应 Go: VulnerData
export interface VulnerData {
  hasCWEVulns: DbVulnerability[];
  emptyCWEVulns: DbVulnerability[];
}

export interface TimestampMap {
  number: number;
  timestamp: string;
}
