package utils

import (
	"fmt"
	"io/ioutil"
	"net"
	"strings"
	"time"

	"github.com/fatih/color"
)

// GetWhoisInfo fetches the whois information for a domain and filters relevant information
func GetWhoisInfo(domain string) (string, error) {
	whoisServer := "whois.iana.org"
	info, err := fetchWhoisFromServer(domain, whoisServer)
	if err != nil {
		return "", err
	}

	actualServer := parseWhoisServer(info)
	if actualServer == "" {
		actualServer = "whois.verisign-grs.com"
	}

	info, err = fetchWhoisFromServer(domain, actualServer)
	if err != nil {
		return "", err
	}

	return filterWhoisData(info), nil
}

// fetchWhoisFromServer fetches whois information directly from the specified server
func fetchWhoisFromServer(domain, server string) (string, error) {
	conn, err := net.DialTimeout("tcp", server+":43", 10*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	fmt.Fprintf(conn, domain+"\r\n")

	resp, err := ioutil.ReadAll(conn)
	if err != nil {
		return "", err
	}

	return string(resp), nil
}

// parseWhoisServer parses the whois server from the initial IANA response
func parseWhoisServer(whoisData string) string {
	lines := strings.Split(whoisData, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "refer:") {
			parts := strings.Fields(line)
			if len(parts) > 1 {
				return parts[1]
			}
		}
	}
	return ""
}

// filterWhoisData filters relevant whois information
func filterWhoisData(whoisData string) string {
	lines := strings.Split(whoisData, "\n")
	var filteredLines []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Domain Name:") ||
			strings.HasPrefix(line, "Registrar:") ||
			strings.HasPrefix(line, "Creation Date:") ||
			strings.HasPrefix(line, "Registry Expiry Date:") ||
			strings.HasPrefix(line, "Updated Date:") ||
			strings.HasPrefix(line, "Registrar WHOIS Server:") ||
			strings.HasPrefix(line, "Registrar URL:") ||
			strings.HasPrefix(line, "Registrar Abuse Contact Email:") ||
			strings.HasPrefix(line, "Registrar Abuse Contact Phone:") ||
			strings.HasPrefix(line, "Name Server:") {
			filteredLines = append(filteredLines, line)
		}
	}

	if len(filteredLines) == 0 {
		return "No relevant whois information found."
	}

	return strings.Join(filteredLines, "\n")
}

// ColorizeWhoisInfo colorizes the whois information headers
func ColorizeWhoisInfo(whoisInfo string) string {
	lines := strings.Split(whoisInfo, "\n")
	for i, line := range lines {
		if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			lines[i] = color.New(color.FgYellow, color.Bold).Sprint(parts[0]) + ":" + parts[1]
		}
	}
	return strings.Join(lines, "\n")
}
