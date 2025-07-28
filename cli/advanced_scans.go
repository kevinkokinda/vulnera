package main

import (
	"encoding/json"
	"fmt"
	"net"

	"github.com/spf13/cobra"
)

func broadcast(task map[string]interface{}) {
	data, _ := json.Marshal(task)
	conn, err := net.Dial("udp", "255.255.255.255:8888")
	if err != nil {
		fmt.Printf("broadcast error: %v\n", err)
		return
	}
	defer conn.Close()
	conn.Write(data)
	fmt.Println("task broadcasted")
}

var sqlScanCmd = &cobra.Command{
	Use:   "sql-scan [url]",
	Short: "Scan a URL for SQL-injection vulnerabilities",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		broadcast(map[string]interface{}{"type": "sql_scan", "url": args[0]})
	},
}

var xssScanCmd = &cobra.Command{
	Use:   "xss-scan [url]",
	Short: "Scan a URL for XSS vulnerabilities",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		broadcast(map[string]interface{}{"type": "xss_scan", "url": args[0]})
	},
}

var apiFuzzCmd = &cobra.Command{
	Use:   "api-fuzz [base-url]",
	Short: "Fuzz an API for common vulnerabilities",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		broadcast(map[string]interface{}{"type": "api_fuzz", "url": args[0]})
	},
}

func init() {
	rootCmd.AddCommand(sqlScanCmd)
	rootCmd.AddCommand(xssScanCmd)
	rootCmd.AddCommand(apiFuzzCmd)
}
