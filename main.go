package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"

	"github.com/jcchavezs/mergefs/io"

	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/corazawaf/coraza/v3"
	txhttp "github.com/corazawaf/coraza/v3/http"
	"github.com/kardianos/service"
)

var (
	serviceFlag = flag.String("service", "", "Control the system service: install, uninstall, start, stop")
	listenPort  = flag.String("listen", "", "Port to listen on")
	targetPort  = flag.String("target", "", "Port to forward to")
	runMode     = flag.Bool("run", false, "Run directly (not as a service)")
	programData = filepath.Join(os.Getenv("ProgramData"), serviceName)
	logDir      = filepath.Join(programData, "logs")
	logger      service.Logger
	logFile     *os.File
)

const (
	serviceName = "CorazaWindowsWAFProxy"
	exeName     = "CorazaWindowsWAFProxy.exe"
	targetDir   = "C:\\Program Files\\CorazaWindowsWAFProxy"
)

type program struct {
	listenPort string
	targetPort string
}

func (p *program) Start(s service.Service) error {
	var err error
	logger, err = s.Logger(nil)
	if err != nil {
		return fmt.Errorf("failed to get logger: %v", err)
	}

	// Ensure directories exist
	if err := os.MkdirAll(logDir, 0755); err != nil {
		logger.Errorf("Failed to create log directory: %v", err)
		return err
	}

	// Try to load config if ports aren't specified
	if p.listenPort == "" || p.targetPort == "" {
		configPath := filepath.Join(programData, "config.json")
		data, err := os.ReadFile(configPath)
		if err == nil {
			var config Config
			if err := json.Unmarshal(data, &config); err == nil {
				p.listenPort = config.ListenPort
				p.targetPort = config.TargetPort
			}
		}
	}

	// Start the proxy
	go p.run()
	return nil
}

func (p *program) run() {
	// Initialize WAF
	waf, err := setupWAF()
	if err != nil {
		logger.Errorf("Failed to initialize WAF: %v", err)
		return
	}

	targetURL, err := url.Parse(fmt.Sprintf("http://localhost:%s", p.targetPort))
	if err != nil {
		logger.Errorf("Failed to parse target URL: %v", err)
		return
	}

	proxy := httputil.NewSingleHostReverseProxy(targetURL)

	// Add logging middleware
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		logger.Infof("Proxying request: %s %s -> %s", req.Method, req.URL.Path, targetURL.String())
	}

	// Add error handling with logging
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		logger.Errorf("Proxy error: %v", err)
		w.WriteHeader(http.StatusBadGateway)
	}

	handler := txhttp.WrapHandler(waf, proxy)

	server := &http.Server{
		Addr:    fmt.Sprintf(":%s", p.listenPort),
		Handler: handler,
	}

	logger.Infof("Starting proxy server on port %s, forwarding to port %s", p.listenPort, p.targetPort)
	if err := server.ListenAndServe(); err != nil {
		logger.Errorf("HTTP server failed: %v", err)
	}
}

func setupWAF() (coraza.WAF, error) {
	// Use the standard log package for early logging
	log.Println("Initializing WAF configuration...")

	customConfig := `
SecRuleEngine On
SecRequestBodyAccess On
SecResponseBodyAccess On
SecResponseBodyMimeType text/plain text/html application/json
SecAuditLogFormat JSON
SecAuditLogType Serial
SecAuditLog "` + filepath.Join(logDir, "secaudit.log") + `"
`

	crsPath := filepath.Join(programData, "owasp_crs")
	// Use the standard log package for early logging
	log.Printf("CRS Path: %s\n", crsPath)

	conf := coraza.NewWAFConfig().
		WithRootFS(io.OSFS).
		WithDirectives(customConfig).
		WithDirectives("Include " + filepath.Join(crsPath, "@crs-setup.conf.example")).
		WithDirectives("Include " + filepath.Join(crsPath, "@owasp_crs/REQUEST-901-INITIALIZATION.conf")).
		WithDirectives("Include " + filepath.Join(crsPath, "@owasp_crs/REQUEST-905-COMMON-EXCEPTIONS.conf")).
		WithDirectives("Include " + filepath.Join(crsPath, "@owasp_crs/REQUEST-911-METHOD-ENFORCEMENT.conf")).
		WithDirectives("Include " + filepath.Join(crsPath, "@owasp_crs/REQUEST-913-SCANNER-DETECTION.conf")).
		WithDirectives("Include " + filepath.Join(crsPath, "@owasp_crs/REQUEST-920-PROTOCOL-ENFORCEMENT.conf")).
		WithDirectives("Include " + filepath.Join(crsPath, "@owasp_crs/REQUEST-921-PROTOCOL-ATTACK.conf")).
		WithDirectives("Include " + filepath.Join(crsPath, "@owasp_crs/REQUEST-922-MULTIPART-ATTACK.conf")).
		WithDirectives("Include " + filepath.Join(crsPath, "@owasp_crs/REQUEST-930-APPLICATION-ATTACK-LFI.conf")).
		WithDirectives("Include " + filepath.Join(crsPath, "@owasp_crs/REQUEST-931-APPLICATION-ATTACK-RFI.conf")).
		WithDirectives("Include " + filepath.Join(crsPath, "@owasp_crs/REQUEST-932-APPLICATION-ATTACK-RCE.conf")).
		WithDirectives("Include " + filepath.Join(crsPath, "@owasp_crs/REQUEST-933-APPLICATION-ATTACK-PHP.conf")).
		WithDirectives("Include " + filepath.Join(crsPath, "@owasp_crs/REQUEST-934-APPLICATION-ATTACK-GENERIC.conf")).
		WithDirectives("Include " + filepath.Join(crsPath, "@owasp_crs/REQUEST-941-APPLICATION-ATTACK-XSS.conf")).
		WithDirectives("Include " + filepath.Join(crsPath, "@owasp_crs/REQUEST-942-APPLICATION-ATTACK-SQLI.conf")).
		WithDirectives("Include " + filepath.Join(crsPath, "@owasp_crs/REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf")).
		WithDirectives("Include " + filepath.Join(crsPath, "@owasp_crs/REQUEST-944-APPLICATION-ATTACK-JAVA.conf")).
		WithDirectives("Include " + filepath.Join(crsPath, "@owasp_crs/REQUEST-949-BLOCKING-EVALUATION.conf")).
		WithDirectives("Include " + filepath.Join(crsPath, "@owasp_crs/RESPONSE-950-DATA-LEAKAGES.conf")).
		WithDirectives("Include " + filepath.Join(crsPath, "@owasp_crs/RESPONSE-951-DATA-LEAKAGES-SQL.conf")).
		WithDirectives("Include " + filepath.Join(crsPath, "@owasp_crs/RESPONSE-952-DATA-LEAKAGES-JAVA.conf")).
		WithDirectives("Include " + filepath.Join(crsPath, "@owasp_crs/RESPONSE-953-DATA-LEAKAGES-PHP.conf")).
		WithDirectives("Include " + filepath.Join(crsPath, "@owasp_crs/RESPONSE-954-DATA-LEAKAGES-IIS.conf")).
		WithDirectives("Include " + filepath.Join(crsPath, "@owasp_crs/RESPONSE-955-WEB-SHELLS.conf")).
		WithDirectives("Include " + filepath.Join(crsPath, "@owasp_crs/RESPONSE-959-BLOCKING-EVALUATION.conf")).
		WithDirectives("Include " + filepath.Join(crsPath, "@owasp_crs/RESPONSE-980-CORRELATION.conf"))

	if conf == nil {
		log.Println("WAF configuration is nil")
		return nil, fmt.Errorf("WAF configuration is nil")
	}

	waf, err := coraza.NewWAF(conf)
	if err != nil {
		log.Printf("Failed to create WAF: %v\n", err)
		return nil, fmt.Errorf("failed to create WAF: %v", err)
	}

	log.Println("WAF initialized successfully.")
	return waf, nil
}

func copyFile(src, dst string) error {
	// Ensure the destination directory exists
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}

	input, err := os.ReadFile(src)
	if err != nil {
		return err
	}

	if err := os.WriteFile(dst, input, 0644); err != nil {
		return err
	}
	return nil
}

func (p *program) Stop(s service.Service) error {
	return nil
}

type Config struct {
	ListenPort string `json:"listen_port"`
	TargetPort string `json:"target_port"`
}

func initLogger() error {
	// Ensure the logs directory exists
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return fmt.Errorf("failed to create logs directory: %v", err)
	}

	logFilePath := filepath.Join(logDir, "proxy.log")
	var err error
	logFile, err = os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open log file: %v", err)
	}

	log.SetOutput(logFile)
	return nil
}

func moveExecutable() error {
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %v", err)
	}

	targetPath := filepath.Join(targetDir, exeName)

	// Ensure the target directory exists
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return fmt.Errorf("failed to create target directory: %v", err)
	}

	// Move the executable
	if err := os.Rename(exePath, targetPath); err != nil {
		return fmt.Errorf("failed to move executable: %v", err)
	}

	return nil
}

func main() {
	// Initialize logger
	if err := initLogger(); err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}
	defer logFile.Close()

	flag.Parse()

	// Direct run mode
	if *runMode {
		if *listenPort == "" || *targetPort == "" {
			log.Fatal("Listen port and target port must be specified with -listen and -target")
		}
		runProxy(*listenPort, *targetPort)
		return
	}

	// Ensure program data directory exists first
	if err := os.MkdirAll(programData, 0755); err != nil {
		log.Fatalf("Failed to create program data directory: %v", err)
	}

	// Move the executable to the target directory
	if err := moveExecutable(); err != nil {
		log.Fatalf("Failed to move executable: %v", err)
	}

	svcConfig := &service.Config{
		Name:        serviceName,
		DisplayName: "Coraza WAF Proxy Service",
		Description: "Coraza WAF Proxy Service",
		Executable:  filepath.Join(targetDir, exeName), // Specify the new executable path
	}

	prg := &program{
		listenPort: *listenPort,
		targetPort: *targetPort,
	}

	s, err := service.New(prg, svcConfig)
	if err != nil {
		log.Fatal(err)
	}

	if *serviceFlag != "" {
		// Save config before installing
		if *serviceFlag == "install" {
			config := Config{
				ListenPort: *listenPort,
				TargetPort: *targetPort,
			}
			data, _ := json.MarshalIndent(config, "", "  ")
			configPath := filepath.Join(programData, "config.json")
			if err := os.WriteFile(configPath, data, 0644); err != nil {
				log.Fatalf("Failed to save config: %v", err)
			}

			// Perform directory setup and file copying during installation
			if err := setupCRSFiles(); err != nil {
				log.Fatalf("Failed to setup CRS files: %v", err)
			}
		}

		switch *serviceFlag {
		case "install":
			err = s.Install()
		case "uninstall":
			err = s.Uninstall()
		case "start":
			err = s.Start()
		case "stop":
			err = s.Stop()
		}
		if err != nil {
			log.Fatalf("Failed to %s service: %v", *serviceFlag, err)
		}
		return
	}

	// If no ports specified, prompt for them
	if prg.listenPort == "" || prg.targetPort == "" {
		reader := bufio.NewReader(os.Stdin)

		fmt.Print("Enter port to listen on: ")
		prg.listenPort = strings.TrimSpace(readLine(reader))

		fmt.Print("Enter port to forward to: ")
		prg.targetPort = strings.TrimSpace(readLine(reader))
	}

	if err := s.Run(); err != nil {
		log.Fatal(err)
	}
}

func readLine(reader *bufio.Reader) string {
	line, _ := reader.ReadString('\n')
	return strings.TrimSpace(line)
}

func runProxy(listenPort, targetPort string) {
	waf, err := setupWAF()
	if err != nil {
		log.Fatalf("Failed to initialize WAF: %v", err)
	}

	targetURL, err := url.Parse(fmt.Sprintf("http://localhost:%s", targetPort))
	if err != nil {
		log.Fatalf("Failed to parse target URL: %v", err)
	}

	proxy := httputil.NewSingleHostReverseProxy(targetURL)

	// Add logging middleware
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		log.Printf("Proxying request: %s %s -> %s", req.Method, req.URL.Path, targetURL.String())
	}

	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("Proxy error: %v", err)
		w.WriteHeader(http.StatusBadGateway)
	}

	handler := txhttp.WrapHandler(waf, proxy)

	log.Printf("Starting proxy server on port %s, forwarding to port %s", listenPort, targetPort)
	if err := http.ListenAndServe(fmt.Sprintf(":%s", listenPort), handler); err != nil {
		log.Fatalf("HTTP server failed: %v", err)
	}
}

func setupCRSFiles() error {
	// Define the path to the CRS rules in the ProgramData directory
	crsPath := filepath.Join(programData, "owasp_crs")

	// Ensure the CRS directory exists
	if err := os.MkdirAll(crsPath, 0755); err != nil {
		return fmt.Errorf("failed to create CRS directory: %v", err)
	}

	// Define the source directory for the CRS files
	srcDir := "."

	// Use copyDir to copy all files and directories from srcDir to crsPath
	if err := copyDir(srcDir, crsPath); err != nil {
		return fmt.Errorf("failed to copy CRS files: %v", err)
	}

	return nil
}

func copyDir(src string, dst string) error {
	src = filepath.Clean(src)
	dst = filepath.Clean(dst)

	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("source is not a directory")
	}

	// Create the destination directory
	if err := os.MkdirAll(dst, info.Mode()); err != nil {
		return err
	}

	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())

		if entry.IsDir() {
			// Recursively copy subdirectories
			if err := copyDir(srcPath, dstPath); err != nil {
				return err
			}
		} else {
			// Copy files
			if err := copyFile(srcPath, dstPath); err != nil {
				return err
			}
		}
	}

	return nil
}
