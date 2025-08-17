RomeshNotConfused is a next-generation dependency confusion vulnerability scanner that helps organizations identify and prevent supply chain attacks across multiple package ecosystems.
🚀 Features
Core Capabilities

🔍 Multi-Package Manager Support: npm, pip, maven, nuget, ruby gems, and more
🧠 Advanced Detection Logic: Smart heuristics for private package identification
⚡ High Performance: Multi-threaded concurrent scanning with configurable thread pools
📊 Rich Reporting: Console, JSON, CSV, and HTML output formats
🔄 CI/CD Ready: Perfect integration for automated security pipelines
📦 Zero Dependencies: Single static binary with no runtime dependencies

Advanced Security Features

🎯 CVSS Scoring: Risk-based vulnerability prioritization
🕵️ Private Package Detection: Advanced pattern matching for internal packages
📈 Trend Analysis: Historical vulnerability tracking and reporting
🔒 Secure Scanning: Rate limiting and respectful API usage
🎨 Scoped Package Handling: Proper @scoped and namespaced package support

📦 #Installation
Quick Install (Recommended)

curl -sSL https://raw.githubusercontent.com/yourusername/romeshnotconfused/main/install.sh | bash

or download directly

curl -L https://github.com/yourusername/romeshnotconfused/releases/latest/download/romeshnotconfused-linux-amd64 -o romeshnotconfused

chmod +x romeshnotconfused

sudo mv romeshnotconfused /usr/local/bin/

# Build from Source

 _Clone repository_
 
git clone https://github.com/yourusername/romeshnotconfused.git

cd romeshnotconfused

 _build and install_
 
go build -o romeshnotconfused ./cmd/romeshnotconfused

sudo mv romeshnotconfused /usr/local/bin/

Package Managers

# Homebrew (macOS/Linux)

brew install yourusername/tap/romeshnotconfused

# Go install
go install github.com/yourusername/romeshnotconfused@latest

# Docker
docker run --rm -v $(pwd):/scan yourusername/romeshnotconfused:latest /scan

⚡ Quick Start
Basic Usage

# Scan current directory
romeshnotconfused .

# Scan specific project
romeshnotconfused /path/to/your/project

# Verbose output with progress
romeshnotconfused -v /path/to/project

Advanced Usage

# High-performance scan with 20 threads
romeshnotconfused -t 20 /path/to/project

# JSON output for automation
romeshnotconfused -o json . > vulnerability-report.json

# CSV for spreadsheet analysis
romeshnotconfused -o csv . > vulnerabilities.csv

# Only show critical and high severity
romeshnotconfused --min-severity high /path/to/project

📊 Example Output
Console Output


        ROMESHNOTCONFUSED DEPENDENCY SCANNER v2.0.0
================================================================================

Scan Summary:
  📁 Files Scanned: 23
  📦 Packages Found: 187
  🚨 Vulnerabilities: CRITICAL(3) HIGH(7) MEDIUM(12) LOW(5)

Package Managers:
  📦 npm: 89 packages
  🐍 python: 53 packages
  ☕ maven: 45 packages

Detailed Findings:
--------------------------------------------------------------------------------

[1] 🚨 CRITICAL - Private package name available for dependency confusion attack
    📦 Package: @mycompany/internal-auth (npm)
    📄 File: ./frontend/package.json
    🌐 Public Registry: Available for registration
    💡 Recommendation: Immediately reserve package name in NPM registry
    📊 CVSS Score: 9.1 (Critical)

[2] ⚠️  HIGH - Potential typosquatting vulnerability detected
    📦 Package: requsets (python) - Similar to 'requests'
    📄 File: ./backend/requirements.txt
    🌐 Public Registry: Package exists with suspicious metadata
    💡 Recommendation: Verify package authenticity and use correct spelling
    📊 CVSS Score: 7.2 (High)

[3] 🔍 MEDIUM - Public package with no verification
    📦 Package: awesome-utils (npm)
    📄 File: ./package.json
    🌐 Public Registry: Exists but lacks verification indicators
    💡 Recommendation: Verify publisher identity and package integrity
    📊 CVSS Score: 4.8 (Medium)

Scan completed in 2.3 seconds ✅
Total packages at risk: 10/187 (5.3%)

🛠️ Configuration
Configuration File
Create .romeshnotconfused.yml in your project root:

# Scanner configuration
threads: 20
timeout: 30s
output: console
verbose: false

# Filtering options
min_severity: medium
include_dev_dependencies: true
include_internal: false

# Package manager specific settings
npm:
  check_scoped: true
  verify_publishers: true
  
python:
  check_requirements_txt: true
  check_pipfile: true
  check_setup_py: true

# Exclusions
ignore_patterns:
  - "node_modules/**"
  - ".git/**"
  - "vendor/**"
  - "*.test.js"

ignore_packages:
  - "test-package"
  - "example-*"

# Output customization
output_config:
  show_progress: true
  color_output: true
  max_results: 100
