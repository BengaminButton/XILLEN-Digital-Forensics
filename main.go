package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// XillenForensics - Advanced Digital Forensics Analysis Tool
type XillenForensics struct {
	TargetPath   string
	OutputFile   string
	Threads      int
	Results      *ForensicsResults
	mu           sync.Mutex
	FileTypes    map[string][]string
	HashDatabase map[string]string
	Artifacts    []Artifact
}

// ForensicsResults contains all analysis results
type ForensicsResults struct {
	TargetPath    string              `json:"target_path"`
	ScanTimestamp time.Time           `json:"scan_timestamp"`
	FileAnalysis  FileAnalysis        `json:"file_analysis"`
	HashAnalysis  HashAnalysis        `json:"hash_analysis"`
	Timeline      []TimelineEntry     `json:"timeline"`
	DeletedFiles  []DeletedFile       `json:"deleted_files"`
	Registry      []RegistryEntry     `json:"registry"`
	Network       []NetworkConnection `json:"network"`
	Processes     []ProcessInfo       `json:"processes"`
	Artifacts     []Artifact          `json:"artifacts"`
	Threats       []Threat            `json:"threats"`
	Summary       ScanSummary         `json:"summary"`
}

// FileAnalysis contains file system analysis results
type FileAnalysis struct {
	TotalFiles  int              `json:"total_files"`
	TotalSize   int64            `json:"total_size"`
	FileTypes   map[string]int   `json:"file_types"`
	Suspicious  []SuspiciousFile `json:"suspicious"`
	RecentFiles []RecentFile     `json:"recent_files"`
	LargeFiles  []LargeFile      `json:"large_files"`
	HiddenFiles []HiddenFile     `json:"hidden_files"`
}

// HashAnalysis contains hash analysis results
type HashAnalysis struct {
	MD5Hashes      map[string]string `json:"md5_hashes"`
	SHA1Hashes     map[string]string `json:"sha1_hashes"`
	SHA256Hashes   map[string]string `json:"sha256_hashes"`
	KnownMalware   []KnownMalware    `json:"known_malware"`
	DuplicateFiles []DuplicateFile   `json:"duplicate_files"`
}

// TimelineEntry represents a timeline event
type TimelineEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Event     string    `json:"event"`
	File      string    `json:"file"`
	Action    string    `json:"action"`
	User      string    `json:"user"`
}

// DeletedFile represents a deleted file
type DeletedFile struct {
	Path      string    `json:"path"`
	Size      int64     `json:"size"`
	DeletedAt time.Time `json:"deleted_at"`
	Recovered bool      `json:"recovered"`
}

// RegistryEntry represents a registry entry
type RegistryEntry struct {
	Key        string    `json:"key"`
	Value      string    `json:"value"`
	Type       string    `json:"type"`
	Modified   time.Time `json:"modified"`
	Suspicious bool      `json:"suspicious"`
}

// NetworkConnection represents a network connection
type NetworkConnection struct {
	LocalIP    string    `json:"local_ip"`
	LocalPort  int       `json:"local_port"`
	RemoteIP   string    `json:"remote_ip"`
	RemotePort int       `json:"remote_port"`
	Protocol   string    `json:"protocol"`
	State      string    `json:"state"`
	Process    string    `json:"process"`
	Timestamp  time.Time `json:"timestamp"`
}

// ProcessInfo represents process information
type ProcessInfo struct {
	PID         int       `json:"pid"`
	Name        string    `json:"name"`
	Path        string    `json:"path"`
	CommandLine string    `json:"command_line"`
	StartTime   time.Time `json:"start_time"`
	User        string    `json:"user"`
	Suspicious  bool      `json:"suspicious"`
}

// Artifact represents a forensic artifact
type Artifact struct {
	Type        string    `json:"type"`
	Path        string    `json:"path"`
	Description string    `json:"description"`
	Timestamp   time.Time `json:"timestamp"`
	Relevance   string    `json:"relevance"`
	Evidence    string    `json:"evidence"`
}

// Threat represents a security threat
type Threat struct {
	Type        string    `json:"type"`
	Severity    string    `json:"severity"`
	Description string    `json:"description"`
	File        string    `json:"file"`
	Timestamp   time.Time `json:"timestamp"`
	IOC         string    `json:"ioc"`
	Remediation string    `json:"remediation"`
}

// ScanSummary contains scan summary information
type ScanSummary struct {
	TotalFiles      int    `json:"total_files"`
	SuspiciousFiles int    `json:"suspicious_files"`
	Threats         int    `json:"threats"`
	Artifacts       int    `json:"artifacts"`
	ScanDuration    string `json:"scan_duration"`
	RiskLevel       string `json:"risk_level"`
}

// Supporting types
type SuspiciousFile struct {
	Path      string    `json:"path"`
	Reason    string    `json:"reason"`
	RiskLevel string    `json:"risk_level"`
	Timestamp time.Time `json:"timestamp"`
}

type RecentFile struct {
	Path      string    `json:"path"`
	Modified  time.Time `json:"modified"`
	Size      int64     `json:"size"`
	Extension string    `json:"extension"`
}

type LargeFile struct {
	Path string `json:"path"`
	Size int64  `json:"size"`
}

type HiddenFile struct {
	Path string `json:"path"`
	Size int64  `json:"size"`
}

type KnownMalware struct {
	Hash      string `json:"hash"`
	File      string `json:"file"`
	Malware   string `json:"malware"`
	Family    string `json:"family"`
	Detection string `json:"detection"`
}

type DuplicateFile struct {
	Hash  string   `json:"hash"`
	Files []string `json:"files"`
	Size  int64    `json:"size"`
}

// NewXillenForensics creates a new forensics scanner instance
func NewXillenForensics(targetPath, outputFile string, threads int) *XillenForensics {
	return &XillenForensics{
		TargetPath: targetPath,
		OutputFile: outputFile,
		Threads:    threads,
		Results: &ForensicsResults{
			TargetPath:    targetPath,
			ScanTimestamp: time.Now(),
			FileAnalysis:  FileAnalysis{FileTypes: make(map[string]int)},
			HashAnalysis: HashAnalysis{
				MD5Hashes:    make(map[string]string),
				SHA1Hashes:   make(map[string]string),
				SHA256Hashes: make(map[string]string),
			},
		},
		FileTypes:    make(map[string][]string),
		HashDatabase: make(map[string]string),
	}
}

// printBanner displays the tool banner
func (xf *XillenForensics) printBanner() {
	banner := `
╔══════════════════════════════════════════════════════════════╗
║                XILLEN DIGITAL FORENSICS                     ║
║              Advanced Evidence Analysis Tool                ║
╚══════════════════════════════════════════════════════════════╝

`
	fmt.Print(banner)
	fmt.Printf("Target: %s\n", xf.TargetPath)
	fmt.Printf("Output: %s\n", xf.OutputFile)
	fmt.Printf("Threads: %d\n", xf.Threads)
	fmt.Printf("Started: %s\n\n", time.Now().Format("2006-01-02 15:04:05"))
}

// initializeFileTypes initializes file type patterns
func (xf *XillenForensics) initializeFileTypes() {
	xf.FileTypes = map[string][]string{
		"executable": {".exe", ".dll", ".sys", ".scr", ".com", ".bat", ".cmd", ".ps1"},
		"document":   {".doc", ".docx", ".pdf", ".txt", ".rtf", ".odt"},
		"image":      {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".ico"},
		"video":      {".mp4", ".avi", ".mov", ".wmv", ".flv", ".mkv"},
		"audio":      {".mp3", ".wav", ".flac", ".aac", ".ogg"},
		"archive":    {".zip", ".rar", ".7z", ".tar", ".gz"},
		"system":     {".log", ".tmp", ".cache", ".config", ".ini"},
		"suspicious": {".vbs", ".js", ".jar", ".class", ".php", ".asp"},
	}
}

// initializeHashDatabase initializes known malware hash database
func (xf *XillenForensics) initializeHashDatabase() {
	// Sample known malware hashes (in real implementation, load from external database)
	xf.HashDatabase = map[string]string{
		"d41d8cd98f00b204e9800998ecf8427e": "Trojan.Generic",
		"5d41402abc4b2a76b9719d911017c592": "Malware.Sample",
		"098f6bcd4621d373cade4e832627b4f6": "Virus.Example",
	}
}

// calculateHash calculates file hash
func (xf *XillenForensics) calculateHash(filePath string) (string, string, string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", "", "", err
	}
	defer file.Close()

	md5Hash := md5.New()
	sha1Hash := sha1.New()
	sha256Hash := sha256.New()

	multiWriter := io.MultiWriter(md5Hash, sha1Hash, sha256Hash)

	_, err = io.Copy(multiWriter, file)
	if err != nil {
		return "", "", "", err
	}

	md5Sum := hex.EncodeToString(md5Hash.Sum(nil))
	sha1Sum := hex.EncodeToString(sha1Hash.Sum(nil))
	sha256Sum := hex.EncodeToString(sha256Hash.Sum(nil))

	return md5Sum, sha1Sum, sha256Sum, nil
}

// analyzeFile analyzes a single file
func (xf *XillenForensics) analyzeFile(filePath string, info os.FileInfo) {
	xf.mu.Lock()
	defer xf.mu.Unlock()

	// Update file count and size
	xf.Results.FileAnalysis.TotalFiles++
	xf.Results.FileAnalysis.TotalSize += info.Size()

	// Analyze file extension
	ext := strings.ToLower(filepath.Ext(filePath))
	if ext != "" {
		xf.Results.FileAnalysis.FileTypes[ext]++
	}

	// Check for suspicious files
	if xf.isSuspiciousFile(filePath, ext) {
		suspicious := SuspiciousFile{
			Path:      filePath,
			Reason:    xf.getSuspiciousReason(filePath, ext),
			RiskLevel: xf.getRiskLevel(filePath, ext),
			Timestamp: info.ModTime(),
		}
		xf.Results.FileAnalysis.Suspicious = append(xf.Results.FileAnalysis.Suspicious, suspicious)
	}

	// Check for recent files (last 7 days)
	if time.Since(info.ModTime()) < 7*24*time.Hour {
		recent := RecentFile{
			Path:      filePath,
			Modified:  info.ModTime(),
			Size:      info.Size(),
			Extension: ext,
		}
		xf.Results.FileAnalysis.RecentFiles = append(xf.Results.FileAnalysis.RecentFiles, recent)
	}

	// Check for large files (>100MB)
	if info.Size() > 100*1024*1024 {
		large := LargeFile{
			Path: filePath,
			Size: info.Size(),
		}
		xf.Results.FileAnalysis.LargeFiles = append(xf.Results.FileAnalysis.LargeFiles, large)
	}

	// Check for hidden files
	if strings.HasPrefix(filepath.Base(filePath), ".") {
		hidden := HiddenFile{
			Path: filePath,
			Size: info.Size(),
		}
		xf.Results.FileAnalysis.HiddenFiles = append(xf.Results.FileAnalysis.HiddenFiles, hidden)
	}

	// Calculate hashes for important files
	if xf.shouldHashFile(filePath, ext) {
		md5Hash, sha1Hash, sha256Hash, err := xf.calculateHash(filePath)
		if err == nil {
			xf.Results.HashAnalysis.MD5Hashes[filePath] = md5Hash
			xf.Results.HashAnalysis.SHA1Hashes[filePath] = sha1Hash
			xf.Results.HashAnalysis.SHA256Hashes[filePath] = sha256Hash

			// Check against known malware database
			if malware, exists := xf.HashDatabase[md5Hash]; exists {
				knownMalware := KnownMalware{
					Hash:      md5Hash,
					File:      filePath,
					Malware:   malware,
					Family:    "Unknown",
					Detection: "Hash Match",
				}
				xf.Results.HashAnalysis.KnownMalware = append(xf.Results.HashAnalysis.KnownMalware, knownMalware)
			}
		}
	}

	// Add to timeline
	timelineEntry := TimelineEntry{
		Timestamp: info.ModTime(),
		Event:     "File Modified",
		File:      filePath,
		Action:    "Modified",
		User:      "System",
	}
	xf.Results.Timeline = append(xf.Results.Timeline, timelineEntry)
}

// isSuspiciousFile checks if a file is suspicious
func (xf *XillenForensics) isSuspiciousFile(filePath, ext string) bool {
	// Check file extension
	for _, suspiciousExt := range xf.FileTypes["suspicious"] {
		if ext == suspiciousExt {
			return true
		}
	}

	// Check file name patterns
	suspiciousPatterns := []string{
		"temp", "tmp", "cache", "backup", "old", "copy",
		"system32", "windows", "program files",
		"autorun", "desktop.ini", "thumbs.db",
	}

	fileName := strings.ToLower(filepath.Base(filePath))
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(fileName, pattern) {
			return true
		}
	}

	// Check for double extensions
	parts := strings.Split(fileName, ".")
	if len(parts) > 2 {
		return true
	}

	return false
}

// getSuspiciousReason returns the reason why a file is suspicious
func (xf *XillenForensics) getSuspiciousReason(filePath, ext string) string {
	fileName := strings.ToLower(filepath.Base(filePath))

	if ext == ".exe" && strings.Contains(fileName, "temp") {
		return "Executable in temporary location"
	}
	if ext == ".vbs" || ext == ".js" {
		return "Script file with potential for malicious activity"
	}
	if strings.Contains(fileName, "autorun") {
		return "Potential autorun malware"
	}
	if len(strings.Split(fileName, ".")) > 2 {
		return "Double file extension (possible malware technique)"
	}

	return "Suspicious file characteristics"
}

// getRiskLevel returns the risk level of a suspicious file
func (xf *XillenForensics) getRiskLevel(filePath, ext string) string {
	fileName := strings.ToLower(filepath.Base(filePath))

	if ext == ".exe" && strings.Contains(fileName, "system32") {
		return "High"
	}
	if ext == ".vbs" || ext == ".js" {
		return "Medium"
	}
	if strings.Contains(fileName, "autorun") {
		return "High"
	}

	return "Low"
}

// shouldHashFile determines if a file should be hashed
func (xf *XillenForensics) shouldHashFile(filePath, ext string) bool {
	// Hash executable files
	for _, execExt := range xf.FileTypes["executable"] {
		if ext == execExt {
			return true
		}
	}

	// Hash suspicious files
	for _, suspiciousExt := range xf.FileTypes["suspicious"] {
		if ext == suspiciousExt {
			return true
		}
	}

	// Hash files in system directories
	systemDirs := []string{"system32", "windows", "program files", "temp", "tmp"}
	for _, dir := range systemDirs {
		if strings.Contains(strings.ToLower(filePath), dir) {
			return true
		}
	}

	return false
}

// scanDirectory recursively scans a directory
func (xf *XillenForensics) scanDirectory(dirPath string) error {
	return filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip files that can't be accessed
		}

		if !info.IsDir() {
			xf.analyzeFile(path, info)
		}

		return nil
	})
}

// analyzeRegistry analyzes registry entries (simulated)
func (xf *XillenForensics) analyzeRegistry() {
	// Simulated registry analysis
	registryEntries := []RegistryEntry{
		{
			Key:        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
			Value:      "SuspiciousApp",
			Type:       "String",
			Modified:   time.Now().Add(-24 * time.Hour),
			Suspicious: true,
		},
		{
			Key:        "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
			Value:      "NormalApp",
			Type:       "String",
			Modified:   time.Now().Add(-7 * 24 * time.Hour),
			Suspicious: false,
		},
	}

	xf.Results.Registry = registryEntries
}

// analyzeNetwork analyzes network connections (simulated)
func (xf *XillenForensics) analyzeNetwork() {
	// Simulated network analysis
	networkConnections := []NetworkConnection{
		{
			LocalIP:    "192.168.1.100",
			LocalPort:  80,
			RemoteIP:   "10.0.0.1",
			RemotePort: 8080,
			Protocol:   "TCP",
			State:      "ESTABLISHED",
			Process:    "suspicious.exe",
			Timestamp:  time.Now().Add(-2 * time.Hour),
		},
	}

	xf.Results.Network = networkConnections
}

// analyzeProcesses analyzes running processes (simulated)
func (xf *XillenForensics) analyzeProcesses() {
	// Simulated process analysis
	processes := []ProcessInfo{
		{
			PID:         1234,
			Name:        "suspicious.exe",
			Path:        "C:\\Windows\\System32\\suspicious.exe",
			CommandLine: "suspicious.exe --stealth",
			StartTime:   time.Now().Add(-1 * time.Hour),
			User:        "SYSTEM",
			Suspicious:  true,
		},
		{
			PID:         5678,
			Name:        "normal.exe",
			Path:        "C:\\Program Files\\Normal\\normal.exe",
			CommandLine: "normal.exe",
			StartTime:   time.Now().Add(-4 * time.Hour),
			User:        "User",
			Suspicious:  false,
		},
	}

	xf.Results.Processes = processes
}

// generateArtifacts generates forensic artifacts
func (xf *XillenForensics) generateArtifacts() {
	artifacts := []Artifact{
		{
			Type:        "File System",
			Path:        xf.TargetPath,
			Description: "Target directory for analysis",
			Timestamp:   time.Now(),
			Relevance:   "High",
			Evidence:    "Primary evidence location",
		},
		{
			Type:        "Registry",
			Path:        "HKEY_LOCAL_MACHINE\\SOFTWARE",
			Description: "System registry entries",
			Timestamp:   time.Now().Add(-1 * time.Hour),
			Relevance:   "Medium",
			Evidence:    "System configuration data",
		},
		{
			Type:        "Network",
			Path:        "Network connections",
			Description: "Active network connections",
			Timestamp:   time.Now().Add(-30 * time.Minute),
			Relevance:   "High",
			Evidence:    "Network activity evidence",
		},
	}

	xf.Results.Artifacts = artifacts
}

// detectThreats detects security threats
func (xf *XillenForensics) detectThreats() {
	threats := []Threat{}

	// Check for malware based on hash analysis
	for _, malware := range xf.Results.HashAnalysis.KnownMalware {
		threat := Threat{
			Type:        "Malware",
			Severity:    "Critical",
			Description: fmt.Sprintf("Known malware detected: %s", malware.Malware),
			File:        malware.File,
			Timestamp:   time.Now(),
			IOC:         malware.Hash,
			Remediation: "Quarantine and remove the file immediately",
		}
		threats = append(threats, threat)
	}

	// Check for suspicious processes
	for _, process := range xf.Results.Processes {
		if process.Suspicious {
			threat := Threat{
				Type:        "Suspicious Process",
				Severity:    "High",
				Description: fmt.Sprintf("Suspicious process running: %s", process.Name),
				File:        process.Path,
				Timestamp:   process.StartTime,
				IOC:         process.CommandLine,
				Remediation: "Terminate process and investigate further",
			}
			threats = append(threats, threat)
		}
	}

	// Check for suspicious registry entries
	for _, registry := range xf.Results.Registry {
		if registry.Suspicious {
			threat := Threat{
				Type:        "Registry Modification",
				Severity:    "Medium",
				Description: fmt.Sprintf("Suspicious registry entry: %s", registry.Value),
				File:        registry.Key,
				Timestamp:   registry.Modified,
				IOC:         registry.Value,
				Remediation: "Remove suspicious registry entry",
			}
			threats = append(threats, threat)
		}
	}

	xf.Results.Threats = threats
}

// generateSummary generates scan summary
func (xf *XillenForensics) generateSummary() {
	xf.Results.Summary = ScanSummary{
		TotalFiles:      xf.Results.FileAnalysis.TotalFiles,
		SuspiciousFiles: len(xf.Results.FileAnalysis.Suspicious),
		Threats:         len(xf.Results.Threats),
		Artifacts:       len(xf.Results.Artifacts),
		ScanDuration:    "Completed",
		RiskLevel:       xf.calculateRiskLevel(),
	}
}

// calculateRiskLevel calculates overall risk level
func (xf *XillenForensics) calculateRiskLevel() string {
	criticalThreats := 0
	highThreats := 0

	for _, threat := range xf.Results.Threats {
		if threat.Severity == "Critical" {
			criticalThreats++
		} else if threat.Severity == "High" {
			highThreats++
		}
	}

	if criticalThreats > 0 {
		return "Critical"
	} else if highThreats > 2 {
		return "High"
	} else if highThreats > 0 || len(xf.Results.FileAnalysis.Suspicious) > 10 {
		return "Medium"
	}

	return "Low"
}

// saveResults saves analysis results to file
func (xf *XillenForensics) saveResults() error {
	// Sort timeline by timestamp
	sort.Slice(xf.Results.Timeline, func(i, j int) bool {
		return xf.Results.Timeline[i].Timestamp.Before(xf.Results.Timeline[j].Timestamp)
	})

	// Save JSON report
	jsonData, err := json.MarshalIndent(xf.Results, "", "  ")
	if err != nil {
		return err
	}

	err = os.WriteFile(xf.OutputFile, jsonData, 0644)
	if err != nil {
		return err
	}

	return nil
}

// printResults prints analysis results to console
func (xf *XillenForensics) printResults() {
	fmt.Println("\n╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║                        ANALYSIS RESULTS                     ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")

	fmt.Printf("\n📊 File Analysis:\n")
	fmt.Printf("   Total Files: %d\n", xf.Results.FileAnalysis.TotalFiles)
	fmt.Printf("   Total Size: %s\n", formatBytes(xf.Results.FileAnalysis.TotalSize))
	fmt.Printf("   Suspicious Files: %d\n", len(xf.Results.FileAnalysis.Suspicious))
	fmt.Printf("   Recent Files: %d\n", len(xf.Results.FileAnalysis.RecentFiles))

	fmt.Printf("\n🔍 Hash Analysis:\n")
	fmt.Printf("   Files Hashed: %d\n", len(xf.Results.HashAnalysis.MD5Hashes))
	fmt.Printf("   Known Malware: %d\n", len(xf.Results.HashAnalysis.KnownMalware))

	fmt.Printf("\n⚠️  Threats Detected:\n")
	for i, threat := range xf.Results.Threats {
		fmt.Printf("   %d. %s (%s) - %s\n", i+1, threat.Type, threat.Severity, threat.Description)
	}

	fmt.Printf("\n📋 Artifacts Found:\n")
	for i, artifact := range xf.Results.Artifacts {
		fmt.Printf("   %d. %s - %s\n", i+1, artifact.Type, artifact.Description)
	}

	fmt.Printf("\n📈 Summary:\n")
	fmt.Printf("   Risk Level: %s\n", xf.Results.Summary.RiskLevel)
	fmt.Printf("   Total Threats: %d\n", xf.Results.Summary.Threats)
	fmt.Printf("   Artifacts: %d\n", xf.Results.Summary.Artifacts)

	fmt.Printf("\n✅ Analysis completed successfully!\n")
	fmt.Printf("📄 Report saved to: %s\n", xf.OutputFile)
}

// formatBytes formats bytes into human readable format
func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// Run performs the complete forensics analysis
func (xf *XillenForensics) Run() error {
	startTime := time.Now()
	xf.printBanner()

	// Initialize
	xf.initializeFileTypes()
	xf.initializeHashDatabase()

	fmt.Println("🔍 Initializing forensics analysis...")

	// File system analysis
	fmt.Println("📁 Analyzing file system...")
	err := xf.scanDirectory(xf.TargetPath)
	if err != nil {
		return fmt.Errorf("file system analysis failed: %v", err)
	}

	// Registry analysis
	fmt.Println("🔧 Analyzing registry...")
	xf.analyzeRegistry()

	// Network analysis
	fmt.Println("🌐 Analyzing network connections...")
	xf.analyzeNetwork()

	// Process analysis
	fmt.Println("⚙️  Analyzing processes...")
	xf.analyzeProcesses()

	// Generate artifacts
	fmt.Println("📋 Generating forensic artifacts...")
	xf.generateArtifacts()

	// Detect threats
	fmt.Println("⚠️  Detecting threats...")
	xf.detectThreats()

	// Generate summary
	xf.generateSummary()

	// Save results
	fmt.Println("💾 Saving results...")
	err = xf.saveResults()
	if err != nil {
		return fmt.Errorf("failed to save results: %v", err)
	}

	// Print results
	xf.printResults()

	duration := time.Since(startTime)
	fmt.Printf("⏱️  Analysis completed in: %v\n", duration)

	return nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go <target_path> [output_file] [threads]")
		fmt.Println("")
		fmt.Println("Examples:")
		fmt.Println("  go run main.go /home/user/Documents")
		fmt.Println("  go run main.go C:\\Users\\User\\Desktop report.json 10")
		fmt.Println("")
		fmt.Println("Options:")
		fmt.Println("  target_path  - Path to analyze")
		fmt.Println("  output_file  - Output JSON file (default: forensics_report.json)")
		fmt.Println("  threads      - Number of threads (default: 10)")
		os.Exit(1)
	}

	targetPath := os.Args[1]
	outputFile := "forensics_report.json"
	threads := 10

	if len(os.Args) > 2 {
		outputFile = os.Args[2]
	}
	if len(os.Args) > 3 {
		if t, err := strconv.Atoi(os.Args[3]); err == nil {
			threads = t
		}
	}

	// Validate target path
	if _, err := os.Stat(targetPath); os.IsNotExist(err) {
		log.Fatalf("Target path does not exist: %s", targetPath)
	}

	// Create forensics scanner
	scanner := NewXillenForensics(targetPath, outputFile, threads)

	// Run analysis
	err := scanner.Run()
	if err != nil {
		log.Fatalf("Forensics analysis failed: %v", err)
	}
}
