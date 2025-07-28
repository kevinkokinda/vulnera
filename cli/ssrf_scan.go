package main

import (
    "fmt"
    "github.com/spf13/cobra"
)

var ssrfScanCmd = &cobra.Command{
    Use:   "ssrf-scan [url]",
    Short: "Scan for Server-Side Request Forgery",
    Args:  cobra.ExactArgs(1),
    Run: func(cmd *cobra.Command, args []string) {
        url := args[0]
        fmt.Printf("Scanning %s for SSRF...\n", url)
        task := map[string]interface{}{
            "type": "ssrf_scan",
            "url":  url,
        }
        broadcastTask(task)
        fmt.Println("SSRF scan task broadcasted to swarm")
    },
}

func init() {
    rootCmd.AddCommand(ssrfScanCmd)
} 