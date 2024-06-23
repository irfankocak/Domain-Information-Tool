package utils

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/fatih/color"
)

// SSLLabsReport represents the structure of the SSL Labs API response
type SSLLabsReport struct {
	Host            string     `json:"host"`
	Port            int        `json:"port"`
	Protocol        string     `json:"protocol"`
	IsPublic        bool       `json:"isPublic"`
	Status          string     `json:"status"`
	StartTime       int64      `json:"startTime"`
	TestTime        int64      `json:"testTime"`
	EngineVersion   string     `json:"engineVersion"`
	CriteriaVersion string     `json:"criteriaVersion"`
	Endpoints       []Endpoint `json:"endpoints"`
}

// Endpoint represents each endpoint in the SSL Labs report
type Endpoint struct {
	IPAddress     string `json:"ipAddress"`
	ServerName    string `json:"serverName"`
	StatusMessage string `json:"statusMessage"`
	Grade         string `json:"grade"`
}

// GetSSLInfo fetches SSL certificate information for a domain and formats it with colored headers
func GetSSLInfo(domain string) (string, error) {
	conn, err := tls.Dial("tcp", domain+":443", &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return "", err
	}
	defer conn.Close()

	if len(conn.ConnectionState().PeerCertificates) == 0 {
		return "", fmt.Errorf("no certificates found")
	}
	cert := conn.ConnectionState().PeerCertificates[0]
	sslInfo := fmt.Sprintf("%s\n%s %s\n%s %s - %s\n%s %s\n",
		color.New(color.FgYellow, color.Bold).Sprint("\nSSL Information:"),
		color.New(color.FgYellow, color.Bold).Sprint("Issuer:"),
		cert.Issuer,
		color.New(color.FgYellow, color.Bold).Sprint("Validity:"),
		cert.NotBefore,
		cert.NotAfter,
		color.New(color.FgYellow, color.Bold).Sprint("Common Name:"),
		cert.Subject.CommonName)

	return sslInfo, nil
}

// GetSSLLabsReport fetches the SSL Labs report for a given domain
func GetSSLLabsReport(domain string) (string, error) {
	apiURL := fmt.Sprintf("https://api.ssllabs.com/api/v3/analyze?host=%s", domain)
	var report SSLLabsReport

	timeout := time.After(5 * time.Minute)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			return "", fmt.Errorf("SSL Labs report timed out for domain: %s", domain)
		case <-ticker.C:
			resp, err := http.Get(apiURL)
			if err != nil {
				return "", fmt.Errorf("failed to fetch SSL Labs report: %v", err)
			}
			defer resp.Body.Close()

			if err := json.NewDecoder(resp.Body).Decode(&report); err != nil {
				return "", fmt.Errorf("failed to decode SSL Labs report: %v", err)
			}

			if report.Status == "READY" || report.Status == "ERROR" {
				if report.Status == "ERROR" {
					return "", fmt.Errorf("SSL Labs report returned error for domain: %s", domain)
				}
				return formatSSLLabsReport(report), nil
			}
		}
	}
}

func formatSSLLabsReport(report SSLLabsReport) string {
	sslLabsInfo := fmt.Sprintf("%s\n%s %s\n%s %d\n%s %s\n%s %s\n",
		color.New(color.FgYellow, color.Bold).Sprint("\nSSL Labs Information:"),
		color.New(color.FgYellow, color.Bold).Sprint("Host:"),
		report.Host,
		color.New(color.FgYellow, color.Bold).Sprint("Port:"),
		report.Port,
		color.New(color.FgYellow, color.Bold).Sprint("Protocol:"),
		report.Protocol,
		color.New(color.FgYellow, color.Bold).Sprint("Grade:"),
		report.Endpoints[0].Grade)

	if len(report.Endpoints) > 0 {
		sslLabsInfo += color.New(color.FgYellow, color.Bold).Sprint("Endpoint Information:\n")
		for _, endpoint := range report.Endpoints {
			sslLabsInfo += fmt.Sprintf("%s %s\n%s %s\n%s %s\n",
				color.New(color.FgYellow, color.Bold).Sprint("IP Address:"),
				endpoint.IPAddress,
				color.New(color.FgYellow, color.Bold).Sprint("Server Name:"),
				endpoint.ServerName,
				color.New(color.FgYellow, color.Bold).Sprint("Status Message:"),
				endpoint.StatusMessage)
		}
	}

	return sslLabsInfo
}
