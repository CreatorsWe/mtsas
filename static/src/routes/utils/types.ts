// 对应 Go: SeverityLevel / ConfidenceLevel
export type SeverityLevel = "UNKNOWN" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type ConfidenceLevel = "LOW" | "MEDIUM" | "HIGH";

// 对应 Go: Range
export interface Range {
    start_line: number;
    end_line: number | null;
    start_column: number;
    end_column: number | null;
}

// 对应 Go: ScopeRange
export interface ScopeRange {
    start: number;
    end: number;
}

// 对应 Go: UnifiedVulnerability
export interface UnifiedVulnerability {
    tool: string;
    warning_id: string;
    category: string;
    short_messgae: string; // 后端字段拼写
    cwe_id: string | null;
    file_path: string;
    range: Range;
    severity_level: SeverityLevel;
    confidence_level: ConfidenceLevel;
}

// 对应 Go: DbVulnerability
export interface DbVulnerability {
    vulnerabilities: UnifiedVulnerability;
    hash: string;
    scopeoffsetID: string;
    optimalscope: ScopeRange;
    warningCount: number;
}

// 对应 Go: VulnerData
export interface VulnerData {
    hashVulns: DbVulnerability[];
    emptyHashVulns: DbVulnerability[];
}

export interface TimestampMap {
    number: number;
    timestamp: string;
}
