package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func startSpectreDaemon(t *testing.T, ctx context.Context) (*exec.Cmd, *bytes.Buffer, func()) {
	spectreDPath := "../build/install/bin/spectre-d"
	pluginDir := "../build/install/lib"

	absSpectreDPath, err := filepath.Abs(spectreDPath)
	if err != nil {
		t.Fatalf("Failed to get absolute path for spectre-d: %v", err)
	}
	absPluginDir, err := filepath.Abs(pluginDir)
	if err != nil {
		t.Fatalf("Failed to get absolute path for plugin directory: %v", err)
	}

	cmd := exec.CommandContext(ctx, absSpectreDPath)
	cmd.Dir = filepath.Dir(absPluginDir)

	type tokenResp struct{ UUID string `json:"uuid"` }
	respToken, err := http.Post("https://webhook.site/token", "application/json", nil)
	if err != nil {
		t.Fatalf("Failed to create webhook token: %v", err)
	}
	defer respToken.Body.Close()
	var tr tokenResp
	if err := json.NewDecoder(respToken.Body).Decode(&tr); err != nil || tr.UUID == "" {
		t.Fatalf("Failed to parse webhook token response: %v", err)
	}
	targetURL := "https://webhook.site/" + tr.UUID
	apiURL := "https://webhook.site/token/" + tr.UUID + "/requests"

	cmd.Env = append(os.Environ(),
		"LD_LIBRARY_PATH="+absPluginDir,
		"CANARY_WEBHOOK_TARGET_URL="+targetURL,
		"CANARY_WEBHOOK_API_URL="+apiURL,
	)

	var daemonOutput bytes.Buffer
	cmd.Stdout = io.MultiWriter(os.Stdout, &daemonOutput)
	cmd.Stderr = io.MultiWriter(os.Stderr, &daemonOutput)

	if err := cmd.Start(); err != nil {
		t.Fatalf("Failed to start spectre-d: %v", err)
	}

	cancelFunc := func() {
		if err := cmd.Process.Kill(); err != nil {
			t.Logf("Failed to kill spectre-d process: %v", err)
		}
	}

	return cmd, &daemonOutput, cancelFunc
}

func TestEndToEnd_SSRFScanWithCanaryHit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	_, daemonOutput, cancelDaemon := startSpectreDaemon(t, ctx)
	defer cancelDaemon()

	time.Sleep(3 * time.Second)

	cliPath := "./spectre"
	ssrfCmd := exec.CommandContext(ctx, cliPath, "ssrf-scan", "http://127.0.0.1/trigger_ssrf?url=")
	if output, err := ssrfCmd.CombinedOutput(); err != nil {
		t.Fatalf("SSRF scan command failed: %v\nOutput: %s", err, string(output))
	}

	var canaryURL string
	for i := 0; i < 20; i++ {
		output := daemonOutput.String()
		if strings.Contains(output, "CANARY_URL:") {
			lines := strings.Split(output, "\n")
			for _, line := range lines {
				if strings.HasPrefix(line, "CANARY_URL:") {
					canaryURL = strings.TrimPrefix(line, "CANARY_URL:")
					break
				}
			}
		}
		if canaryURL != "" {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	if canaryURL == "" {
		log.Printf("Daemon output:\n%s", daemonOutput.String())
		t.Fatal("Failed to find canary URL in daemon output")
	}

	log.Printf("Captured canary URL: %s", canaryURL)
	log.Printf("Triggering canary URL: %s", canaryURL)

	resp, err := http.Get(canaryURL)
	if err != nil {
		t.Fatalf("Failed to trigger canary URL with HTTP GET: %v", err)
	}
	defer resp.Body.Close()

	hitDetected := false
	for i := 0; i < 20; i++ {
		if strings.Contains(daemonOutput.String(), "[canary_monitor] HIT DETECTED") {
			hitDetected = true
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	if !hitDetected {
		log.Printf("Daemon output:\n%s", daemonOutput.String())
		t.Fatal("FAILURE: Timeout waiting for canary hit detection.")
	}

	log.Println("SUCCESS: Canary hit was detected by the daemon.")
} 