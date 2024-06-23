package utils

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"
)

// CheckURL tries to get a response from both http and https and returns the URL that works
func CheckURL(domain string) (string, error) {
	urls := []string{"https://" + domain, "http://" + domain}
	for _, url := range urls {
		resp, err := http.Get(url)
		if err == nil {
			resp.Body.Close()
			return url, nil
		}
	}
	return "", fmt.Errorf("invalid domain: %s", domain)
}

// GetSecurityHeadersInfo fetches security headers information for a domain
func GetSecurityHeadersInfo(domain string) (string, error) {
	url, err := CheckURL(domain)
	if err != nil {
		return "", err
	}

	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	securityHeaders := map[string]string{
		"Content-Security-Policy":   "default-src 'self'",
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY or SAMEORIGIN",
		"X-XSS-Protection":          "1; mode=block",
		"Referrer-Policy":           "no-referrer",
		"Feature-Policy":            "geolocation 'none'; microphone 'none'",
		"Permissions-Policy":        "fullscreen=(), geolocation=()",
	}

	var sb strings.Builder

	// Add colored header
	sb.WriteString(color.New(color.FgYellow, color.Bold).Sprintf("\nSecurity Headers for %s\n\n", domain))

	table := tablewriter.NewWriter(&sb)
	table.SetHeader([]string{"Header", "Status", "Value", "Suggestion"})
	table.SetBorder(false)
	table.SetRowLine(true)
	table.SetAutoWrapText(false)
	table.SetColMinWidth(0, 35)
	table.SetColMinWidth(1, 10)
	table.SetColMinWidth(2, 25)
	table.SetColMinWidth(3, 35)

	for header, suggestionValue := range securityHeaders {
		value := resp.Header.Get(header)
		if value == "" {
			table.Append([]string{header, color.RedString("Not Found"), "", suggestionValue})
		} else {
			table.Append([]string{header, color.GreenString("Found"), value, ""})
		}
	}

	table.Render()
	return sb.String(), nil
}
