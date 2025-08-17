# RomeshNotConfused Scanner 🔍

> Advanced Dependency Confusion Vulnerability Scanner

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Build Status](https://github.com/romesh0/romeshnotconfused/workflows/build/badge.svg)](https://github.com/romesh0/romeshnotconfused/actions)
[![Security Scan](https://img.shields.io/badge/Security-Scanned-green.svg)](https://github.com/yourusername/romeshnotconfused/security)

## 🚀 Features

- **Multi-Package Manager Support**: npm, pip, maven, nuget, and more
- **Advanced Detection**: Smart heuristics for private package identification  
- **High Performance**: Multi-threaded concurrent scanning
- **Multiple Output Formats**: Console, JSON, CSV, HTML
- **CI/CD Ready**: Perfect for automated security pipelines
- **Zero Dependencies**: Single static binary

## ⚡ Quick Start

### Installation/Usage
```bash
# Via Go install
go install github.com/romesh0/romeshnotconfused@latest

# Via releases (recommended)
curl -L https://github.com/romesh0/romeshnotconfused/releases/latest/download/romeshnotconfused-linux-amd64 -o romeshnotconfused
chmod +x romeshnotconfused

### Usage

# Scan current directory
./romeshnotconfused

# high-performance scan
./romeshnotconfused -t 20 /path/to/project

# JSON output for CI/CD
./romeshnotconfused -o json . > results.json
