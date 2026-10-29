# Phase 1: Foundation - Implementation Plan

## Overview
Build the core foundation of AI Bug Hunter with basic scanning capabilities.

## Tasks

### Task 1: Project Structure
Create directory structure:
```
ai_bug_hunter/
├── src/
│   ├── __init__.py
│   ├── main.py                 # CLI entry point
│   ├── repo_manager.py         # Git operations
│   ├── code_parser.py          # File parsing
│   ├── secret_scanner.py       # Secret detection
│   └── report_generator.py     # Report output
├── tests/
│   ├── __init__.py
│   ├── test_repo_manager.py
│   ├── test_code_parser.py
│   ├── test_secret_scanner.py
│   └── test_report_generator.py
├── config/
│   └── patterns.yaml           # Secret patterns
├── requirements.txt
├── pyproject.toml
└── README.md
```

### Task 2: Dependencies
- `gitpython` - Git operations
- `pyyaml` - Configuration
- `click` - CLI framework
- `rich` - Terminal output
- `pytest` - Testing

### Task 3: Repository Manager
Functions:
- `clone_repo(url, dest)` - Clone GitHub repo
- `get_file_tree(repo_path)` - List all files
- `read_file(repo_path, file_path)` - Read file content
- `cleanup(repo_path)` - Remove cloned repo

### Task 4: Code Parser
Functions:
- `detect_language(file_path)` - Detect programming language
- `read_and_chunk(file_path)` - Read file and split into chunks
- `get_file_stats(file_path)` - Get line count, complexity

### Task 5: Secret Scanner
Functions:
- `scan_for_secrets(file_content, file_path)` - Find secrets
- `calculate_entropy(string)` - Measure randomness
- `load_patterns()` - Load regex patterns from config

Patterns to detect:
- AWS keys (AKIA...)
- GitHub tokens (ghp_...)
- API keys (generic)
- Private keys (BEGIN PRIVATE KEY)
- Database URLs
- Passwords in code

### Task 6: Report Generator
Functions:
- `generate_markdown_report(findings)` - Create Markdown report
- `generate_json_report(findings)` - Create JSON output
- `print_summary(findings)` - Terminal summary

### Task 7: CLI Entry Point
Commands:
- `ai-bug-hunter scan <repo_url>` - Scan a repository
- `ai-bug-hunter scan-local <path>` - Scan local directory
- `ai-bug-hunter report <scan_id>` - View report

### Task 8: Unit Tests
Test each module independently with mock data.

### Task 9: End-to-End Test
Scan a real public repo (e.g., `pallets/flask` or `psf/requests`).

## Success Criteria
- [ ] Can clone a GitHub repo
- [ ] Can parse files and detect languages
- [ ] Can find secrets in code
- [ ] Can generate Markdown report
- [ ] CLI works with scan command
- [ ] All tests pass
- [ ] Can scan a real repo end-to-end