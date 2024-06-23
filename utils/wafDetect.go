package utils

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"

	"github.com/fatih/color"
)

// DetectWAF wafw00f aracını kullanarak WAF tespiti yapar ve WAF markasını döner
func DetectWAF(domain string) (string, error) {
	// wafw00f komutunu hazırlayın
	cmd := exec.Command("wafw00f", domain)

	// Komutu çalıştırın ve çıktısını yakalayın
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf("error running wafw00f: %v", err)
	}

	// Çıktıyı işleyin
	output := out.String()
	if strings.Contains(output, "No WAF detected") {
		return fmt.Sprintf("\n%s\n%s", color.New(color.FgYellow, color.Bold).Sprint("WAF Detected:"), "No"), nil
	}

	// WAF markasını çıkartmak için çıktıdan satırları ayırın
	lines := strings.Split(output, "\n")
	var wafBrand string
	for _, line := range lines {
		if strings.Contains(line, "is behind") {
			wafBrand = strings.TrimSpace(line)
			break
		}
	}

	if wafBrand == "" {
		return fmt.Sprintf("\n%s\n%s", color.New(color.FgYellow, color.Bold).Sprint("WAF Detected:"), "Yes, but brand not identified"), nil
	}

	return fmt.Sprintf("\n%s\n%s", color.New(color.FgYellow, color.Bold).Sprint("WAF Detected:"), wafBrand), nil
}
