/* Inspired by Alex Birsan 
Blog post detailing Dependency Confusion : https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610
*/
package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// Configuration for the scanner
type Config struct {
	Threads         int
	Timeout         time.Duration
	OutputFormat    string
	OutputFile      string
	Verbose         bool
	CheckPublished  bool
	CheckVersions   bool
	IncludeInternal bool
	UserAgent       string
	ProxyURL        string
	CustomUA        bool
}

// Package represents a dependency package
type Package struct {
	Name            string `json:"name"`
	Version         string `json:"version"`
	Manager         string `json:"manager"`
	File            string `json:"file"`
	IsPrivate       bool   `json:"is_private"`
	Scope           string `json:"scope,omitempty"`
	Namespace       string `json:"namespace,omitempty"`
}

// Vulnerability represents a potential dependency confusion vulnerability
type Vulnerability struct {
	Package          Package   `json:"package"`
	Severity         string    `json:"severity"`
	Type             string    `json:"type"`
	Description      string    `json:"description"`
	PublicExists     bool      `json:"public_exists"`
	PublicVersion    string    `json:"public_version,omitempty"`
	LatestVersion    string    `json:"latest_version,omitempty"`
	Downloads        int64     `json:"downloads,omitempty"`
	PublishDate      time.Time `json:"publish_date,omitempty"`
	Recommendation   string    `json:"recommendation"`
	CVE              string    `json:"cve,omitempty"`
	CVSS             float64   `json:"cvss,omitempty"`
}

// Scanner interface for different package managers
type Scanner interface {
	ParseFile(filename string) ([]Package, error)
	CheckPackage(pkg Package, client *http.Client) (*Vulnerability, error)
	GetName() string
}

// NPMScanner for Node.js packages
type NPMScanner struct{}

func (n *NPMScanner) GetName() string { return "npm" }

func (n *NPMScanner) ParseFile(filename string) ([]Package, error) {
	var packages []Package
	
	if strings.Contains(filename, "package.json") {
		return n.parsePackageJSON(filename)
	} else if strings.Contains(filename, "package-lock.json") {
		return n.parsePackageLock(filename)
	} else if strings.Contains(filename, "yarn.lock") {
		return n.parseYarnLock(filename)
	}
	
	return packages, nil
}

func (n *NPMScanner) parsePackageJSON(filename string) ([]Package, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var packageJSON struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
		Name            string            `json:"name"`
		Version			string			  `json:"version"`
	}

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&packageJSON); err != nil {
		return nil, err
	}

	var packages []Package

	// Add the project itself as a package
    if packageJSON.Name != "" && packageJSON.Version != "" {
        projectPackage := Package{
            Name:      packageJSON.Name,
            Version:   packageJSON.Version,
            Manager:   "npm",
            File:      filename,
            IsPrivate: n.isPrivatePackage(packageJSON.Name, packageJSON.Name),
        }
        packages = append(packages, projectPackage)
    }
	
	// Parse dependencies
	for name, version := range packageJSON.Dependencies {
		pkg := Package{
			Name:      name,
			Version:   version,
			Manager:   "npm",
			File:      filename,
			IsPrivate: n.isPrivatePackage(name, packageJSON.Name),
		}
		if strings.HasPrefix(name, "@") {
			pkg.Scope = strings.Split(name, "/")[0]
		}
		packages = append(packages, pkg)
	}

	// Parse devDependencies
	for name, version := range packageJSON.DevDependencies {
		pkg := Package{
			Name:      name,
			Version:   version,
			Manager:   "npm",
			File:      filename,
			IsPrivate: n.isPrivatePackage(name, packageJSON.Name),
		}
		if strings.HasPrefix(name, "@") {
			pkg.Scope = strings.Split(name, "/")[0]
		}
		packages = append(packages, pkg)
	}

	return packages, nil
}

func (n *NPMScanner) parsePackageLock(filename string) ([]Package, error) {
	// Implementation for package-lock.json parsing
	// This would be more complex, parsing the lock file structure
	return nil, fmt.Errorf("package-lock.json parsing not implemented yet")
}

func (n *NPMScanner) parseYarnLock(filename string) ([]Package, error) {
	// Implementation for yarn.lock parsing
	return nil, fmt.Errorf("yarn.lock parsing not implemented yet")
}

func (n *NPMScanner) isPrivatePackage(packageName, projectName string) bool {
	// Heuristics to determine if a package might be private
	if strings.HasPrefix(packageName, "@") {
		scope := strings.Split(packageName, "/")[0]
		// Common private scopes
		privateScopes := []string{"@company", "@internal", "@private", "@org"}
		for _, privateScope := range privateScopes {
			if strings.Contains(scope, privateScope) {
				return true
			}
		}
	}
	
	// Check if package name contains project-specific identifiers
	if projectName != "" && strings.Contains(packageName, strings.Split(projectName, "/")[0]) {
		return true
	}
	
	return false
}

func (n *NPMScanner) CheckPackage(pkg Package, client *http.Client) (*Vulnerability, error) {
	// Check NPM registry
	url := fmt.Sprintf("https://registry.npmjs.org/%s", pkg.Name)
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	
	req.Header.Set("User-Agent", "RomeshNotConfused-Scanner/2.0")
	
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	vuln := &Vulnerability{
		Package: pkg,
		Type:    "dependency_confusion",
	}

	if resp.StatusCode == 200 {
		// Package exists publicly
		var npmData struct {
			DistTags map[string]string `json:"dist-tags"`
			Time     map[string]string `json:"time"`
			Downloads struct {
				Weekly int64 `json:"weekly"`
			} `json:"downloads"`
		}
		
		body, err := io.ReadAll(resp.Body)
		if err == nil {
			json.Unmarshal(body, &npmData)
			
			vuln.PublicExists = true
			vuln.PublicVersion = npmData.DistTags["latest"]
			
			// Determine severity based on various factors
			if pkg.IsPrivate {
				vuln.Severity = "HIGH"
				vuln.Description = "Private package name available in public NPM registry"
				vuln.Recommendation = "Verify if the package is reserved or use unique naming"
			} else {
				vuln.Severity = "MEDIUM"
				vuln.Description = "Package exists in public registry - verify authenticity"
				vuln.Recommendation = "Verify package publisher and integrity"
			}
			
			// Parse publish date
			if createTime, exists := npmData.Time["created"]; exists {
				if parsed, err := time.Parse(time.RFC3339, createTime); err == nil {
					vuln.PublishDate = parsed
				}
			}
		}
	} else if resp.StatusCode == 404 && pkg.IsPrivate {
		// Private package name available for squatting
		vuln.Severity = "CRITICAL"
		vuln.Description = "Private package name available for dependency confusion attack"
		vuln.Recommendation = "Immediately reserve this package name in NPM registry"
		vuln.PublicExists = false
	}

	return vuln, nil
}

// PythonScanner for Python packages
type PythonScanner struct{}

func (p *PythonScanner) GetName() string { return "python" }

func (p *PythonScanner) ParseFile(filename string) ([]Package, error) {
	var packages []Package
	
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0
	
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		
		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		
		// Parse package==version or package>=version format
		re := regexp.MustCompile(`^([a-zA-Z0-9\-_\.]+)([>=<~!]+.+)?$`)
		matches := re.FindStringSubmatch(line)
		
		if len(matches) > 1 {
			pkg := Package{
				Name:      matches[1],
				Manager:   "pip",
				File:      filename,
				IsPrivate: p.isPrivatePackage(matches[1]),
			}
			
			if len(matches) > 2 && matches[2] != "" {
				pkg.Version = matches[2]
			}
			
			packages = append(packages, pkg)
		}
	}

	return packages, nil
}

func (p *PythonScanner) isPrivatePackage(packageName string) bool {
	// Common patterns for private Python packages
	privatePatterns := []string{
		"company-", "internal-", "private-", "corp-",
	}
	
	for _, pattern := range privatePatterns {
		if strings.HasPrefix(packageName, pattern) {
			return true
		}
	}
	
	return false
}

func (p *PythonScanner) CheckPackage(pkg Package, client *http.Client) (*Vulnerability, error) {
	// Check PyPI
	url := fmt.Sprintf("https://pypi.org/pypi/%s/json", pkg.Name)
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	vuln := &Vulnerability{
		Package: pkg,
		Type:    "dependency_confusion",
	}

	if resp.StatusCode == 200 {
		vuln.PublicExists = true
		vuln.Severity = "MEDIUM"
		vuln.Description = "Package exists in PyPI"
		vuln.Recommendation = "Verify package authenticity and publisher"
	} else if resp.StatusCode == 404 && pkg.IsPrivate {
		vuln.Severity = "CRITICAL"
		vuln.Description = "Private package name available for dependency confusion attack"
		vuln.Recommendation = "Reserve package name in PyPI registry"
		vuln.PublicExists = false
	}

	return vuln, nil
}

// ScanResult holds all scan results
type ScanResult struct {
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	Summary         struct {
		TotalPackages    int            `json:"total_packages"`
		TotalFiles       int            `json:"total_files"`
		CriticalCount    int            `json:"critical_count"`
		HighCount        int            `json:"high_count"`
		MediumCount      int            `json:"medium_count"`
		LowCount         int            `json:"low_count"`
		PackageManagers  map[string]int `json:"package_managers"`
	} `json:"summary"`
	ScanTime time.Time `json:"scan_time"`
	Version  string    `json:"version"`
}

// Main scanner struct
type RomeshNotConfusedScanner struct {
	config   Config
	scanners map[string]Scanner
	client   *http.Client
}

func NewRomeshNotConfusedScanner(config Config) *RomeshNotConfusedScanner {
	// Create HTTP client with custom settings
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
	}
	
	client := &http.Client{
		Timeout:   config.Timeout,
		Transport: transport,
	}

	scanner := &RomeshNotConfusedScanner{
		config: config,
		client: client,
		scanners: map[string]Scanner{
			"npm":    &NPMScanner{},
			"python": &PythonScanner{},
			// Add more scanners here
		},
	}

	return scanner
}

func (rncs *RomeshNotConfusedScanner) ScanDirectory(dir string) (*ScanResult, error) {
	result := &ScanResult{
		ScanTime: time.Now(),
		Version:  "2.0.0",
	}
	result.Summary.PackageManagers = make(map[string]int)

	var allPackages []Package
	fileCount := 0

	// Walk through directory and find package files
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		filename := info.Name()
		
		// Check if this is a package file we can scan
		for _, scanner := range rncs.scanners {
			if rncs.isPackageFile(filename, scanner.GetName()) {
				if rncs.config.Verbose {
					fmt.Printf("Scanning file: %s\n", path)
				}
				
				packages, err := scanner.ParseFile(path)
				if err != nil {
					log.Printf("Error parsing %s: %v", path, err)
					continue
				}
				
				allPackages = append(allPackages, packages...)
				fileCount++
				result.Summary.PackageManagers[scanner.GetName()] += len(packages)
			}
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	result.Summary.TotalFiles = fileCount
	result.Summary.TotalPackages = len(allPackages)

	// Check packages concurrently
	vulnerabilities := rncs.checkPackagesConcurrently(allPackages)
	result.Vulnerabilities = vulnerabilities

	// Calculate summary statistics
	for _, vuln := range vulnerabilities {
		switch vuln.Severity {
		case "CRITICAL":
			result.Summary.CriticalCount++
		case "HIGH":
			result.Summary.HighCount++
		case "MEDIUM":
			result.Summary.MediumCount++
		case "LOW":
			result.Summary.LowCount++
		}
	}

	return result, nil
}

func (rncs *RomeshNotConfusedScanner) isPackageFile(filename, scannerType string) bool {
	packageFiles := map[string][]string{
		"npm":    {"package.json", "package-lock.json", "yarn.lock"},
		"python": {"requirements.txt", "Pipfile", "setup.py", "pyproject.toml"},
		"maven":  {"pom.xml"},
		"gradle": {"build.gradle", "build.gradle.kts"},
		"nuget":  {"packages.config", "*.csproj", "*.nuspec"},
	}

	if files, exists := packageFiles[scannerType]; exists {
		for _, file := range files {
			if strings.Contains(filename, file) || 
			   (strings.Contains(file, "*") && strings.HasSuffix(filename, strings.TrimPrefix(file, "*"))) {
				return true
			}
		}
	}

	return false
}

func (rncs *RomeshNotConfusedScanner) checkPackagesConcurrently(packages []Package) []Vulnerability {
	var vulnerabilities []Vulnerability
	var mutex sync.Mutex
	var wg sync.WaitGroup

	// Create a channel to limit concurrent requests
	semaphore := make(chan struct{}, rncs.config.Threads)

	for _, pkg := range packages {
		wg.Add(1)
		go func(p Package) {
			defer wg.Done()
			semaphore <- struct{}{} // Acquire semaphore
			defer func() { <-semaphore }() // Release semaphore

			scanner := rncs.scanners[p.Manager]
			if scanner == nil {
				return
			}

			vuln, err := scanner.CheckPackage(p, rncs.client)
			if err != nil {
				if rncs.config.Verbose {
					log.Printf("Error checking package %s: %v", p.Name, err)
				}
				return
			}

			if vuln != nil && (vuln.Severity != "" || rncs.config.IncludeInternal) {
				mutex.Lock()
				vulnerabilities = append(vulnerabilities, *vuln)
				mutex.Unlock()
			}
		}(pkg)
	}

	wg.Wait()

	// Sort vulnerabilities by severity
	sort.Slice(vulnerabilities, func(i, j int) bool {
		severityOrder := map[string]int{
			"CRITICAL": 4,
			"HIGH":     3,
			"MEDIUM":   2,
			"LOW":      1,
		}
		return severityOrder[vulnerabilities[i].Severity] > severityOrder[vulnerabilities[j].Severity]
	})

	return vulnerabilities
}

func (rncs *RomeshNotConfusedScanner) OutputResults(result *ScanResult) error {
	switch rncs.config.OutputFormat {
	case "json":
		return rncs.outputJSON(result)
	case "csv":
		return rncs.outputCSV(result)
	case "html":
		return rncs.outputHTML(result)
	default:
		return rncs.outputConsole(result)
	}
}

func (rncs *RomeshNotConfusedScanner) outputConsole(result *ScanResult) error {
	// Color coding
	red := color.New(color.FgRed, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)
	green := color.New(color.FgGreen, color.Bold)
	blue := color.New(color.FgBlue, color.Bold)

	fmt.Println("\n" + strings.Repeat("=", 80))
	blue.Println("        ROMESHNOTCONFUSED DEPENDENCY SCANNER")
	fmt.Println(strings.Repeat("=", 80))

	// Summary
	fmt.Printf("\nScan Summary:\n")
	fmt.Printf("  Files Scanned: %d\n", result.Summary.TotalFiles)
	fmt.Printf("  Packages Found: %d\n", result.Summary.TotalPackages)
	fmt.Printf("  Vulnerabilities: ")
	
	if result.Summary.CriticalCount > 0 {
		red.Printf("CRITICAL(%d) ", result.Summary.CriticalCount)
	}
	if result.Summary.HighCount > 0 {
		red.Printf("HIGH(%d) ", result.Summary.HighCount)
	}
	if result.Summary.MediumCount > 0 {
		yellow.Printf("MEDIUM(%d) ", result.Summary.MediumCount)
	}
	if result.Summary.LowCount > 0 {
		green.Printf("LOW(%d) ", result.Summary.LowCount)
	}
	fmt.Println()

	// Package managers
	fmt.Printf("\nPackage Managers:\n")
	for manager, count := range result.Summary.PackageManagers {
		fmt.Printf("  %s: %d packages\n", manager, count)
	}

	// Detailed vulnerabilities
	if len(result.Vulnerabilities) > 0 {
		fmt.Printf("\nDetailed Findings:\n")
		fmt.Println(strings.Repeat("-", 80))

		for i, vuln := range result.Vulnerabilities {
			var severityColor *color.Color
			switch vuln.Severity {
			case "CRITICAL", "HIGH":
				severityColor = red
			case "MEDIUM":
				severityColor = yellow
			case "LOW":
				severityColor = green
			}

			fmt.Printf("\n[%d] ", i+1)
			severityColor.Printf("%s", vuln.Severity)
			fmt.Printf(" - %s\n", vuln.Description)
			fmt.Printf("    Package: %s (%s)\n", vuln.Package.Name, vuln.Package.Manager)
			fmt.Printf("    File: %s\n", vuln.Package.File)
			fmt.Printf("    Public Exists: %v\n", vuln.PublicExists)
			
			if vuln.PublicVersion != "" {
				fmt.Printf("    Public Version: %s\n", vuln.PublicVersion)
			}
			
			fmt.Printf("    Recommendation: %s\n", vuln.Recommendation)
		}
	} else {
		green.Println("\n✓ No dependency confusion vulnerabilities found!")
	}

	fmt.Println(strings.Repeat("=", 80))
	return nil
}

func (rncs *RomeshNotConfusedScanner) outputJSON(result *ScanResult) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func (rncs *RomeshNotConfusedScanner) outputCSV(result *ScanResult) error {
	fmt.Println("Severity,Package,Manager,File,Description,PublicExists,Recommendation")
	for _, vuln := range result.Vulnerabilities {
		fmt.Printf("%s,%s,%s,%s,%s,%v,%s\n",
			vuln.Severity,
			vuln.Package.Name,
			vuln.Package.Manager,
			vuln.Package.File,
			vuln.Description,
			vuln.PublicExists,
			vuln.Recommendation)
	}
	return nil
}

func (rncs *RomeshNotConfusedScanner) outputHTML(result *ScanResult) error {
	// HTML output implementation
	return fmt.Errorf("HTML output not implemented yet")
}

// CLI Commands
var rootCmd = &cobra.Command{
	Use:   "romeshnotconfused [directory]",
	Short: "RomeshNotConfused Dependency Scanner",
	Long: `An advanced tool for detecting dependency confusion vulnerabilities across multiple package managers.
	
Features:
- Multi-threaded scanning
- Support for npm, pip, maven, nuget, and more
- Advanced heuristics for private package detection
- Multiple output formats
- Detailed vulnerability analysis`,
	Args: cobra.ExactArgs(1),
	Run:  runScan,
}

func runScan(cmd *cobra.Command, args []string) {
	directory := args[0]
	
	// Get flags
	threads, _ := cmd.Flags().GetInt("threads")
	timeout, _ := cmd.Flags().GetDuration("timeout")
	outputFormat, _ := cmd.Flags().GetString("output")
	verbose, _ := cmd.Flags().GetBool("verbose")
	
	config := Config{
		Threads:      threads,
		Timeout:      timeout,
		OutputFormat: outputFormat,
		Verbose:      verbose,
	}

	scanner := NewRomeshNotConfusedScanner(config)
	
	fmt.Printf("Starting RomeshNotConfused dependency scan on: %s\n", directory)
	
	result, err := scanner.ScanDirectory(directory)
	if err != nil {
		log.Fatalf("Scan failed: %v", err)
	}

	if err := scanner.OutputResults(result); err != nil {
		log.Fatalf("Output failed: %v", err)
	}
}

func init() {
	rootCmd.Flags().IntP("threads", "t", 10, "Number of concurrent threads")
	rootCmd.Flags().DurationP("timeout", "", 30*time.Second, "HTTP request timeout")
	rootCmd.Flags().StringP("output", "o", "console", "Output format (console, json, csv, html)")
	rootCmd.Flags().BoolP("verbose", "v", false, "Verbose output")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
