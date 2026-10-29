# AI Bug Hunter - Architecture & Tracking Document

## 🎯 Project Overview

**AI Bug Hunter** is an automated security scanning tool that:
- Scans GitHub repositories for bugs and security vulnerabilities
- Uses AI/LLM to understand code context and suggest fixes
- Creates pull requests with automated fixes
- Generates detailed reports

---

## 🛠️ Tech Stack Breakdown

### 1. **Python 3.11+** - Core Language
**Why Python?**
- Best ecosystem for AI/ML libraries
- Rich security scanning tools
- Fast development cycle
- Strong GitHub API support

**What it's used for:**
- All backend logic
- Security scanners
- AI integration
- Report generation

---

### 2. **FastAPI** - Web Framework
**What is it?** Modern, fast web framework for building APIs

**Why FastAPI?**
- Automatic API documentation
- Async support (handles many requests)
- Type validation with Pydantic
- Fast performance

**What it's used for:**
- REST API endpoints
- Handling scan requests
- Serving reports
- WebSocket for real-time updates

---

### 3. **Tree-sitter** - Code Parser
**What is it?** Parser generator for source code

**Why Tree-sitter?**
- Supports 40+ programming languages
- Fast incremental parsing
- Generates Abstract Syntax Trees (AST)
- Used by VS Code, GitHub

**What it's used for:**
- Parsing code into AST
- Extracting functions, classes, imports
- Understanding code structure
- Language-agnostic analysis

**How it works:**
```
Source Code → Tree-sitter → AST → Extract Features → Analysis
```

---

### 4. **OpenAI GPT-4 / Anthropic Claude** - AI Analysis
**What are they?** Large Language Models for code understanding

**Why these models?**
- Excellent code comprehension
- Can understand context
- Generate fix suggestions
- Explain vulnerabilities

**What they're used for:**
- Analyzing code for bugs
- Understanding vulnerability context
- Generating fix suggestions
- Writing commit messages

**How it works:**
```
Code + Context → LLM → Bug Analysis + Fix Suggestions
```

---

### 5. **ChromaDB** - Vector Database
**What is it?** Database for storing embeddings (vector representations)

**Why ChromaDB?**
- Simple to use
- Stores code embeddings
- Enables semantic search
- Local storage (no cloud required)

**What it's used for:**
- Storing code embeddings
- Finding similar code patterns
- Semantic search across codebase
- RAG (Retrieval-Augmented Generation)

**How it works:**
```
Code → Embedding Model → Vector → ChromaDB → Similarity Search
```

---

### 6. **Semgrep** - Static Analysis
**What is it?** Static analysis tool for finding bugs

**Why Semgrep?**
- 2000+ community rules
- Custom rule support
- Multi-language
- Used by security teams

**What it's used for:**
- Pattern-based vulnerability detection
- OWASP Top 10 scanning
- Custom security rules
- Quick vulnerability checks

---

### 7. **PyGithub** - GitHub Integration
**What is it?** Python wrapper for GitHub API

**Why PyGithub?**
- Easy repo cloning
- PR creation
- Issue management
- Commit operations

**What it's used for:**
- Cloning repositories
- Creating pull requests
- Posting comments
- Managing branches

---

### 8. **Streamlit** - Web Dashboard
**What is it?** Framework for building data apps

**Why Streamlit?**
- Quick to build
- Interactive widgets
- Real-time updates
- No frontend expertise needed

**What it's used for:**
- Web dashboard
- Scan results visualization
- Interactive reports
- User interface

---

## 📊 Component Architecture

### Layer 1: User Interface
```
┌─────────────────────────────────────────┐
│           USER INTERFACE                 │
├─────────────────────────────────────────┤
│ • CLI (Command Line Interface)           │
│ • Web Dashboard (Streamlit)              │
│ • API (FastAPI)                          │
└─────────────────────────────────────────┘
```

**How it works:**
1. User provides GitHub repo URL
2. User selects scan type (security, bugs, full)
3. System starts scanning
4. Results displayed in real-time

---

### Layer 2: Repository Manager
```
┌─────────────────────────────────────────┐
│        REPOSITORY MANAGER                │
├─────────────────────────────────────────┤
│ • Clone repos (git clone)                │
│ • Checkout branches                      │
│ • Get file changes (diff)                │
│ • Create branches for fixes              │
└─────────────────────────────────────────┘
```

**How it works:**
1. Receives GitHub URL
2. Clones repo to temp directory
3. Analyzes file structure
4. Tracks changes for PR creation

**Key functions:**
- `clone_repo(url)` - Downloads repository
- `get_file_tree()` - Lists all files
- `create_branch(name)` - Creates fix branch
- `commit_changes(files)` - Saves fixes

---

### Layer 3: Code Parser
```
┌─────────────────────────────────────────┐
│          CODE PARSER                     │
├─────────────────────────────────────────┤
│ • Tree-sitter AST parsing                │
│ • Extract functions, classes, imports    │
│ • Code chunking (by function/class)      │
│ • Language detection                     │
└─────────────────────────────────────────┘
```

**How it works:**
1. Detects programming language
2. Parses code into AST
3. Extracts code units (functions, classes)
4. Chunks code for AI analysis

**Example:**
```python
# Input: Python file
def login(username, password):
    query = f"SELECT * FROM users WHERE name='{username}'"
    return db.execute(query)

# AST Output:
{
  "type": "function",
  "name": "login",
  "params": ["username", "password"],
  "vulnerabilities": ["sql_injection"]
}
```

---

### Layer 4: Security Scanners
```
┌─────────────────────────────────────────┐
│        SECURITY SCANNERS                 │
├─────────────────────────────────────────┤
│ • Secret Scanner (API keys, passwords)   │
│ • Vulnerability Scanner (OWASP Top 10)   │
│ • Dependency Scanner (CVE checking)      │
│ • Pattern Matcher (Semgrep rules)        │
└─────────────────────────────────────────┘
```

#### 4.1 Secret Scanner
**What it detects:**
- AWS keys, GitHub tokens
- API keys, passwords
- Private keys, certificates
- Database connection strings

**How it works:**
```
File Content → Regex Patterns → Entropy Check → Flag Secrets
```

**Example patterns:**
```regex
AKIA[0-9A-Z]{16}           # AWS Access Key
ghp_[a-zA-Z0-9]{36}        # GitHub Token
-----BEGIN PRIVATE KEY----- # Private Key
```

#### 4.2 Vulnerability Scanner
**What it detects (OWASP Top 10):**
1. **Injection** - SQL, NoSQL, OS command injection
2. **Broken Authentication** - Weak passwords, session issues
3. **Sensitive Data Exposure** - Unencrypted data
4. **XML External Entities** - XXE attacks
5. **Broken Access Control** - Missing authorization
6. **Security Misconfiguration** - Default credentials
7. **Cross-Site Scripting** - XSS vulnerabilities
8. **Insecure Deserialization** - Unsafe object handling
9. **Using Components with Known Vulnerabilities**
10. **Insufficient Logging & Monitoring**

**How it works:**
```
Code → Pattern Matching → Vulnerability Database → Risk Score
```

#### 4.3 Dependency Scanner
**What it checks:**
- Known CVEs in dependencies
- Outdated packages
- License compliance
- Security advisories

**How it works:**
```
package.json/requirements.txt → OSV API → CVE Database → Report
```

---

### Layer 5: AI Analyzer
```
┌─────────────────────────────────────────┐
│          AI ANALYZER                     │
├─────────────────────────────────────────┤
│ • LLM-powered code understanding        │
│ • Context-aware bug detection            │
│ • Fix suggestion generation              │
│ • Code explanation                       │
└─────────────────────────────────────────┘
```

**How it works:**
```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│ Code Chunk   │ →  │ Embedding    │ →  │ Vector DB    │
│              │    │ Model        │    │ (ChromaDB)   │
└──────────────┘    └──────────────┘    └──────────────┘
                           │
                           ▼
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│ Similar Code │ →  │ Context      │ →  │ LLM          │
│ Retrieved    │    │ Builder      │    │ Analysis     │
└──────────────┘    └──────────────┘    └──────────────┘
                           │
                           ▼
                    ┌──────────────┐
                    │ Bug Report + │
                    │ Fix Suggest  │
                    └──────────────┘
```

**Key AI features:**
1. **Semantic Search** - Find similar code patterns
2. **Context Building** - Gather relevant code context
3. **Bug Analysis** - Understand vulnerability impact
4. **Fix Generation** - Create code patches

**Example AI prompt:**
```
Analyze this code for security vulnerabilities:

```python
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return db.execute(query)
```

Provide:
1. Vulnerability type
2. Severity level
3. Explanation
4. Fix suggestion
```

---

### Layer 6: Report Generator
```
┌─────────────────────────────────────────┐
│        REPORT GENERATOR                  │
├─────────────────────────────────────────┤
│ • Markdown reports                       │
│ • JSON output                            │
│ • HTML dashboards                        │
│ • GitHub Issue creation                  │
└─────────────────────────────────────────┘
```

**Report sections:**
1. Executive Summary
2. Findings by Severity (Critical, High, Medium, Low)
3. Detailed Vulnerabilities
4. Code Snippets with Line Numbers
5. Fix Suggestions
6. Compliance Status

---

### Layer 7: GitHub Integration
```
┌─────────────────────────────────────────┐
│       GITHUB INTEGRATION                 │
├─────────────────────────────────────────┤
│ • Create pull requests                   │
│ • Add comments to code                   │
│ • Create issues                          │
│ • Manage branches                        │
└─────────────────────────────────────────┘
```

**How it works:**
1. Create fix branch from main
2. Apply code fixes
3. Commit with descriptive message
4. Create PR with description
5. Add review comments

**PR creation flow:**
```
Scan Complete → Create Branch → Apply Fixes → Commit → Create PR
```

---

## 🔄 Complete Data Flow

```
User Input (GitHub URL)
        │
        ▼
┌─────────────────────────────────────────────────────┐
│ 1. REPO MANAGER                                     │
│    • Clone repository                                │
│    • Analyze structure                               │
│    • Get file list                                   │
└─────────────────────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────────────────────┐
│ 2. CODE PARSER                                       │
│    • Parse each file (Tree-sitter)                   │
│    • Extract AST                                     │
│    • Chunk by function/class                         │
│    • Store in ChromaDB                               │
└─────────────────────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────────────────────┐
│ 3. SECURITY SCANNERS (Parallel)                      │
│    • Secret Scanner                                  │
│    • Vulnerability Scanner                           │
│    • Dependency Scanner                              │
│    • Semgrep Rules                                   │
└─────────────────────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────────────────────┐
│ 4. AI ANALYSIS                                       │
│    • For each finding:                               │
│      - Retrieve context from ChromaDB                │
│      - Build prompt with context                     │
│      - Send to LLM                                   │
│      - Get analysis + fix                            │
└─────────────────────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────────────────────┐
│ 5. REPORT GENERATION                                 │
│    • Compile all findings                            │
│    • Generate Markdown report                        │
│    • Create JSON output                              │
│    • Build HTML dashboard                            │
└─────────────────────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────────────────────┐
│ 6. GITHUB ACTIONS (Optional)                         │
│    • Create fix branch                               │
│    • Apply code patches                              │
│    • Commit changes                                  │
│    • Create Pull Request                             │
│    • Add review comments                             │
└─────────────────────────────────────────────────────┘
        │
        ▼
    User receives:
    • Detailed report
    • PR with fixes (optional)
    • Security score
```

---

## 📡 API Endpoints

### Core Endpoints
```
POST /api/scan                    # Start repository scan
GET  /api/scan/{scan_id}          # Get scan status
GET  /api/scan/{scan_id}/results  # Get scan results
POST /api/scan/{scan_id}/pr       # Create PR with fixes
```

### Repository Endpoints
```
GET  /api/repos                   # List scanned repos
GET  /api/repos/{repo_id}         # Get repo details
POST /api/repos/analyze           # Quick repo analysis
```

### Report Endpoints
```
GET  /api/reports/{scan_id}       # Get report (JSON)
GET  /api/reports/{scan_id}/md    # Get report (Markdown)
GET  /api/reports/{scan_id}/html  # Get report (HTML)
```

### GitHub Endpoints
```
POST /api/github/auth             # Authenticate
GET  /api/github/repos            # List user repos
POST /api/github/pr               # Create PR
```

---

## 🧪 Testing Strategy

### Unit Tests
- Test each scanner independently
- Test code parser with sample files
- Test AI analyzer with mock responses
- Test report generator

### Integration Tests
- Test full scan pipeline
- Test GitHub API integration
- Test PR creation flow

### Security Tests
- Test secret detection accuracy
- Test vulnerability pattern matching
- Test false positive rates

---

## 🚀 Deployment

### Local Development
```bash
# Install dependencies
pip install -r requirements.txt

# Run CLI
python -m ai_bug_hunter scan https://github.com/user/repo

# Run Web UI
streamlit run src/ui/dashboard.py
```

### Docker Deployment
```bash
# Build image
docker build -t ai-bug-hunter .

# Run container
docker run -p 8000:8000 ai-bug-hunter
```

### GitHub Actions Integration
```yaml
# .github/workflows/security-scan.yml
name: Security Scan
on: [pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run AI Bug Hunter
        run: |
          pip install ai-bug-hunter
          ai-bug-hunter scan . --output report.json
```

---

## 🔑 Configuration

### Environment Variables
```bash
# AI Configuration
OPENAI_API_KEY=sk-...           # OpenAI API key
ANTHROPIC_API_KEY=sk-ant-...    # Anthropic API key

# GitHub Configuration
GITHUB_TOKEN=ghp_...            # GitHub personal access token

# Database
CHROMA_DB_PATH=./data/chroma    # ChromaDB storage path

# Scanner Settings
MAX_FILE_SIZE=1000000           # Max file size (1MB)
SCAN_TIMEOUT=300                # Scan timeout (5 minutes)
```

### Configuration File (config.yaml)
```yaml
scanners:
  secrets:
    enabled: true
    patterns: ["aws", "github", "api_keys"]
  vulnerabilities:
    enabled: true
    rules: ["owasp_top_10", "custom"]
  dependencies:
    enabled: true
    check_cves: true

ai:
  provider: "openai"            # openai | anthropic | local
  model: "gpt-4"
  max_tokens: 2000
  temperature: 0.3

reports:
  formats: ["markdown", "json", "html"]
  include_code: true
  include_fixes: true

github:
  auto_pr: false                # Auto-create PRs
  pr_labels: ["security", "bug-fix"]
```

---

## 📈 Metrics & Monitoring

### Scan Metrics
- Total scans performed
- Average scan duration
- Vulnerabilities found per scan
- False positive rate

### Performance Metrics
- Files processed per second
- API response time
- Memory usage
- CPU utilization

### Security Metrics
- Critical vulnerabilities found
- Time to fix
- Recurring vulnerabilities
- Coverage percentage

---

## 🔮 Future Enhancements

### Short Term (1-2 months)
- [ ] VS Code extension
- [ ] GitHub App
- [ ] More language support
- [ ] Custom rule editor

### Medium Term (3-6 months)
- [ ] Real-time monitoring
- [ ] Team collaboration features
- [ ] Compliance reporting (SOC2, HIPAA)
- [ ] Integration with CI/CD tools

### Long Term (6-12 months)
- [ ] Self-hosted LLM support
- [ ] Custom AI model training
- [ ] Enterprise features
- [ ] Marketplace for rules

---

## 📚 Key Libraries Reference

| Library | Purpose | Documentation |
|---------|---------|---------------|
| FastAPI | Web framework | https://fastapi.tiangolo.com |
| Tree-sitter | Code parsing | https://tree-sitter.github.io |
| ChromaDB | Vector database | https://docs.trychroma.com |
| OpenAI | LLM integration | https://platform.openai.com/docs |
| Semgrep | Static analysis | https://semgrep.dev/docs |
| PyGithub | GitHub API | https://pygithub.readthedocs.io |
| Streamlit | Web dashboard | https://streamlit.io |
| Pydantic | Data validation | https://docs.pydantic.dev |

---

## 🎯 Success Criteria

1. **Accuracy**: Detect 90%+ of known vulnerabilities
2. **Performance**: Scan 1000-file repo in <5 minutes
3. **False Positives**: <10% false positive rate
4. **Fix Quality**: 80%+ of suggested fixes are valid
5. **User Experience**: Intuitive UI, clear reports

---

*This document tracks the architecture and implementation details of AI Bug Hunter.*
*Last updated: July 2026*