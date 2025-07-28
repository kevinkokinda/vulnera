package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "spectre",
	Short: "Spectre - Decentralized Security Auditing",
	Long:  `Spectre is a decentralized security auditing tool for radical transparency.`,
}

var scanCmd = &cobra.Command{
	Use:   "scan [target]",
	Short: "Perform on-demand security scan",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := args[0]
		scanType, _ := cmd.Flags().GetString("type")

		fmt.Printf("Scanning %s (type: %s)...\n", target, scanType)
		
		task := map[string]interface{}{
			"type":   scanType,
			"target": target,
		}
		
		broadcastTask(task)
		fmt.Println("Scan task broadcasted to swarm")
	},
}

var scanAllCmd = &cobra.Command{
	Use:   "scan-all [target]",
	Short: "Perform all available security scans",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := args[0]
		fmt.Printf("Performing all scans on %s...\n", target)

		pluginTypes := []string{
			"cred_stuff", "git_leak", "s3_scan", "ssrf_scan",
			"lfi_scanner", "dependency_confusion", "sql_injector",
			"xss_hunter", "api_fuzzer",
		}

		for _, scanType := range pluginTypes {
			fmt.Printf("  -> Queuing %s scan\n", scanType)
			task := map[string]interface{}{
				"type":   scanType,
				"target": target,
			}
			broadcastTask(task)
		}
		fmt.Println("\nAll scan tasks broadcasted to swarm")
	},
}

var joinSwarmCmd = &cobra.Command{
	Use:   "join-swarm",
	Short: "Join the decentralized swarm",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Installing spectre-d daemon...")
		
		daemonPath := findDaemon()
		if daemonPath == "" {
			fmt.Println("Error: spectre-d daemon not found")
			os.Exit(1)
		}
		
		installService(daemonPath)
		fmt.Println("Successfully joined the swarm!")
	},
}

var tickerCmd = &cobra.Command{
	Use:   "ticker",
	Short: "Live feed of vulnerability disclosures",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Spectre Live Ticker - Vulnerability Disclosures")
		fmt.Println(strings.Repeat("=", 50))
		
		for {
			timestamp := time.Now().Format("2006-01-02 15:04:05Z")
			fmt.Printf("[%s] [192.168.1.100] [DEFAULT_CREDS] [Proof: a1b2c3...]\n", timestamp)
			time.Sleep(3 * time.Second)
		}
	},
}

var gitScanCmd = &cobra.Command{
	Use:   "git-scan [target]",
	Short: "Scan for exposed Git repositories",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := args[0]
		fmt.Printf("Scanning %s for exposed .git directories...\n", target)
		
		task := map[string]interface{}{
			"type":   "git_leak",
			"target": target,
		}
		
		broadcastTask(task)
		fmt.Println("Git scan task broadcasted to swarm")
	},
}

var s3ScanCmd = &cobra.Command{
	Use:   "s3-scan [target]",
	Short: "Scan for exposed S3 buckets",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := args[0]
		fmt.Printf("Scanning %s for exposed S3 buckets...\n", target)
		
		task := map[string]interface{}{
			"type":   "s3_scan",
			"target": target,
		}
		
		broadcastTask(task)
		fmt.Println("S3 scan task broadcasted to swarm")
	},
}

var searchCmd = &cobra.Command{
	Use:   "search [query]",
	Short: "Search vulnerability history",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		query := args[0]
		fmt.Printf("Searching Arweave ledger for: %s\n", query)
		fmt.Println("No results found (ledger query not implemented)")
	},
}

func broadcastTask(task map[string]interface{}) {
	taskJSON, _ := json.Marshal(task)
	
	conn, err := net.Dial("udp", "255.255.255.255:8888")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	defer conn.Close()
	
	conn.Write(taskJSON)
}

func findDaemon() string {
	candidates := []string{
		"./spectre-d",
		"../build/spectre-d/spectre-d",
		"/usr/local/bin/spectre-d",
	}
	
	for _, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return ""
}

func installService(daemonPath string) {
	switch runtime.GOOS {
	case "linux":
		fmt.Println("Installing systemd service...")
	case "windows":
		fmt.Println("Installing Windows service...")
	default:
		fmt.Println("Starting daemon in background...")
		cmd := exec.Command(daemonPath, "./plugins")
		cmd.Start()
	}
}

func generateUniqueID() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		panic(fmt.Sprintf("failed to generate random data for unique ID: %v", err))
	}
	return hex.EncodeToString(b)
}

func main() {
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(scanAllCmd)
	rootCmd.AddCommand(joinSwarmCmd)
	rootCmd.AddCommand(tickerCmd)
	rootCmd.AddCommand(s3ScanCmd)
	rootCmd.AddCommand(gitScanCmd)
	rootCmd.AddCommand(searchCmd)

	var crawlCmd = &cobra.Command{
		Use:   "crawl [target]",
		Short: "Crawl a website to discover all accessible URLs",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			target := args[0]
			fmt.Printf("Crawling %s to discover URLs...\n", target)

			task := map[string]interface{}{
				"type":   "crawler",
				"target": target,
			}

			broadcastTask(task)
			fmt.Println("Crawl task broadcasted to swarm")
		},
	}
	rootCmd.AddCommand(crawlCmd)

	var attackCmd = &cobra.Command{
		Use:   "attack [target]",
		Short: "Crawl a website and then run all scans on all discovered URLs",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			target := args[0]
			fmt.Printf("--- LAUNCHING FULL ATTACK ON %s ---\n", target)

			conn, _, err := websocket.DefaultDialer.Dial("ws://127.0.0.1:8889", nil)
			if err != nil {
				fmt.Printf("Error connecting to spectre-d WebSocket: %v\n", err)
				return
			}
			defer conn.Close()
			fmt.Println("[ATTACK] Connected to spectre-d event stream.")

			scanID := generateUniqueID()

			fmt.Println("[ATTACK] Deploying crawler to map the target...")
			crawlTask := map[string]interface{}{
				"type":   "crawler",
				"target": target,
				"id":     scanID,
			}
			broadcastTask(crawlTask)

			fmt.Println("[ATTACK] Awaiting sitemap from crawler... (This may take a moment)")
			var sitemap []string
			for {
				_, message, err := conn.ReadMessage()
				if err != nil {
					if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
						fmt.Printf("Error reading from WebSocket: %v\n", err)
					}
					return
				}

				var proof map[string]interface{}
				if err := json.Unmarshal(message, &proof); err == nil {
					if id, ok := proof["id"]; ok && id == scanID {
						if vtype, ok := proof["vuln_type"]; ok && vtype == "CRAWL_COMPLETE" {
							fmt.Println("[ATTACK] Sitemap received.")
							if evidence, ok := proof["evidence"].(map[string]interface{}); ok {
								if urls, ok := evidence["sitemap"].([]interface{}); ok {
									for _, url := range urls {
										sitemap = append(sitemap, url.(string))
									}
									break
								}
							}
						}
					}
				}
			}

			fmt.Printf("[ATTACK] Discovered %d URLs. Unleashing all scanners on each URL...\n", len(sitemap))
			pluginTypes := []string{
				"cred_stuffer", "git_leaker", "s3_scan", "ssrf_scanner",
				"lfi_scanner", "dependency_confusion", "sql_injector",
				"xss_hunter", "api_fuzzer",
			}
			for _, url := range sitemap {
				fmt.Printf("  -> Attacking %s\n", url)
				for _, scanType := range pluginTypes {
					task := map[string]interface{}{
						"type":   scanType,
						"target": url,
					}
					broadcastTask(task)
				}
			}
			fmt.Println("\n--- FULL ATTACK COMPLETE ---")
		},
	}
	rootCmd.AddCommand(attackCmd)

	scanCmd.Flags().String("type", "cred_stuff", "Type of scan to perform (e.g., git_leak, s3_scan)")

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
} 