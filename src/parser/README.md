`parser` 将各工具的 json 报告格式化成统一的 json 结构:
```json
[
  {
  	"tool": 工具名称,
  	"warning_id": 工具标识的警告 ID,
    "warning_type": 工具标识的警告类型,
  	"category": 工具标识的警告种类，
  	"short_message": 工具标识的警告信息，
    "cwe_id": CWE 编号，
  	"file_path": 文件路径,
  	"module": 错误所属完整模块,
  	"range": {
  		"start_line": 起始行,
  		"end_line": 结束行，
  		"start_column": 起始偏移,
  		"end_column": 结束偏移
  	},
  	"severity_level": 严重性等级,
  	"confidence_level": 置信度等级
  }
]
```

### `pylint_parser`
pylint json 报告格式：
``` json
[
    {
        "type": "convention",  // type 字段表示严重性程度，有 error、warning、refactor、convention、fatal(解析失败)
        "module": "demo",      // 触发代码的 Python 模块名（文件名）。src/utils.py → module: "src.utils"
        "obj": "",             // 触发代码所属的对象（函数、类、方法、类属性等）；若在模块级，则该字段为空字符串 ""
        "line": 1,
        "column": 0,
        "endLine": null,
        "endColumn": null,
        "path": "demo.py",
        "symbol": "missing-module-docstring",
        "message": "Missing module docstring",
        "message-id": "C0114"
    }
]
```
字段映射:
```json
  {
  	"tool": "pylint",
  	"warning_id": "message-id",
    "warning_type": "symbol",
  	"category": "type"，
  	"short_message": "message"，
  	"file_path": "path",
  	"range": {
  		"start_line": "line",
  		"end_line": "endLine"，
  		"start_column": "column",
  		"end_column": "endColumn"
  	}
  	"cwe_id": ""，
  	"severity_level": 根据 "type" 计算,error -> high; warning -> medium; convention -> low; refactor -> low; fatal -> unknown
  	"confidence_level": 根据 "type" 计算,error -> high; warning -> medium; convention -> low; refactor -> low; fatal -> low
  	"module": 拼接 module + obj
  } 
```


### `horusec_parser`
horusec 报告格式:
```json
{
  "version": "v2.8.0",
  ...,
  "analysisVulnerabilities": [
    {
      "vulnerabilityID": "00000000-0000-0000-0000-000000000000",
      "analysisID": "cb33294f-49fc-4a98-b7b6-6e4be262f4af",
      "createdAt": "2026-01-13T19:48:18.7045282+08:00",
      "vulnerabilities": {
        "vulnerabilityID": "9865bda9-1007-48d3-830f-eb5d4ad048e3",
        "line": "10",
        "column": "19",
        "confidence": "MEDIUM",
        "file": "demo.py",
        "code": "SSH_PRIVATE_KEY = \"-----BEGIN RSA PRIVATE KEY-----\\nfakekey\\n-----END RSA PRIVATE KEY-----\"",
        "details": "(1/1) * Possible vulnerability detected: Asymmetric Private Key\nFound SSH and/or x.509 Cerficates among the files of your project, make sure you want this kind of information inside your Git repo, since it can be missused by someone with access to any kind of copy.  For more information checkout the CWE-312 (https://cwe.mitre.org/data/definitions/312.html) advisory.",
        "securityTool": "HorusecEngine",
        "language": "Leaks",
        "severity": "CRITICAL",
        "type": "Vulnerability",
        "commitAuthor": "-",
        "commitEmail": "-",
        "commitHash": "-",
        "commitMessage": "-",
        "commitDate": "-",
        "rule_id": "HS-LEAKS-12",
        "vulnHash": "4130402c2096433bed4180ceb11106dc813961f3fe59922adffcfdc7d6c29b3f",
        "deprecatedHashes": [
          "2300504cfc572871f44a6107d147035c6f92b99199a33c5f78d34f1dc9aa51f5",
          "1e8e21e5a1f680216882a28d03411c2d8d33775848dc4601a007bedd853d7a48"
        ],
        "securityToolVersion": "",
        "securityToolInfoUri": ""
      }
    },
    ...,
  ]
}
```
字段映射:
```json
  {
  	"tool": "horusec",
  	"warning_id": "rule_id",
    "warning_type": "rule_id",
  	"category": "type"，
  	"short_message": "details"，
  	"file_path": "file",
  	"range": {
  		"start_line": "line",
  		"end_line": ""，
  		"start_column": "column",
  		"end_column": ""
  	}
  	"cwe_id":计算，从 details 中提取，
  	"severity_level": "severity"
  	"confidence_level": "confidence"
  	"module": ""
  } 
```

### `bandit_parser`
bandit 报告格式:
```json
{
  "errors": [],
  "generated_at": "2026-01-13T11:46:27Z",
  "metrics": {  },
  "results": [
    {
      "code": "7 # \u786c\u7f16\u7801\u6570\u636e\u5e93\u5bc6\u7801\n8 DB_PASSWORD = \"MyWeakPassword123!\"\n9 # \u786c\u7f16\u7801SSH\u79c1\u94a5\uff08\u7b80\u5316\u793a\u4f8b\uff09\n",
      "col_offset": 14,
      "end_col_offset": 34,
      "filename": ".\\demo.py",
      "issue_confidence": "MEDIUM",
      "issue_cwe": {
        "id": 259,
        "link": "https://cwe.mitre.org/data/definitions/259.html"
      },
      "issue_severity": "LOW",
      "issue_text": "Possible hardcoded password: 'MyWeakPassword123!'",
      "line_number": 8,
      "line_range": [
        8
      ],
      "more_info": "https://bandit.readthedocs.io/en/1.9.2/plugins/b105_hardcoded_password_string.html",
      "test_id": "B105",
      "test_name": "hardcoded_password_string"
    }
  ]
```
字段映射:
```json
  {
  	"tool": "bandit",
  	"warning_id": "test_id",
    "warning_type": "test_name",
  	"category": ""，
  	"short_message": "issue_text"，
  	"file_path": "filename",
  	"range": {
  		"start_line": "line_number",
  		"end_line": 计算，从 "line_range" 中提取，
  		"start_column": "col_offset",
  		"end_column": "end_col_offset"
  	}
  	"cwe_id":"issue_cwe.id"，
  	"severity_level": "issue_severity"
  	"confidence_level": "issue_confidence"
  	"module": ""
  } 
```

### `semgrep_parser`
```json
 {
      "check_id": "java.lang.security.audit.crypto.use-of-md5.use-of-md5",
      "path": "D:\\Code\\Project\\Multi-tool_Static_Analysis_System_refactor\\example_code\\java\\Demo1.java",
      "start": { "line": 47, "col": 58, "offset": 1655 },
      "end": { "line": 47, "col": 63, "offset": 1660 },
      "extra": {
        "message": "Detected MD5 hash algorithm which is considered insecure. MD5 is not collision resistant and is therefore not suitable as a cryptographic signature. Use HMAC instead.",
        "fix": "\"SHA-512\"",
        "metadata": {
          "functional-categories": [
            "crypto::search::hash-algorithm::java.security"
          ],
          "owasp": [
            "A03:2017 - Sensitive Data Exposure",
            "A02:2021 - Cryptographic Failures",
            "A04:2025 - Cryptographic Failures"
          ],
          "cwe": ["CWE-328: Use of Weak Hash"],
          "source-rule-url": "https://find-sec-bugs.github.io/bugs.htm#WEAK_MESSAGE_DIGEST_MD5",
          "category": "security",
          "technology": ["java"],
          "references": [
            "https://owasp.org/Top10/A02_2021-Cryptographic_Failures"
          ],
          "subcategory": ["vuln"],
          "likelihood": "MEDIUM",
          "impact": "MEDIUM",
          "confidence": "HIGH",
          "license": "Semgrep Rules License v1.0. For more details, visit semgrep.dev/legal/rules-license",
          "vulnerability_class": ["Insecure Hashing Algorithm"],
          "source": "https://semgrep.dev/r/java.lang.security.audit.crypto.use-of-md5.use-of-md5",
          "shortlink": "https://sg.run/ryJn"
        },
        "severity": "WARNING",
        "fingerprint": "requires login",
        "lines": "requires login",
        "validation_state": "NO_VALIDATOR",
        "engine_kind": "OSS"
      }
    },
```
字段映射:
```json
  {
  	"tool": "semgrep",
  	"warning_id": "check_id",
    "warning_type": "check_id",
  	"category": "category"，
  	"short_message": "extra.message"，
  	"file_path": "path",
  	"range": {
  		"start_line": "start.line",
  		"end_line": "end.line"
  		"start_column": "start.col",
  		"end_column": "end.col"
  	}
  	"cwe_id":"cwe 提取"，
  	"severity_level": "extra.metadata.impact"
  	"confidence_level": "extra.metadata.confidence"
  	"module": ""
  } 
```
