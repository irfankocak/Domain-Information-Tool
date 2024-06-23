package utils

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"

	"github.com/fatih/color"
)

// DetectServerTechnologies detects technologies used by the server
func DetectServerTechnologies(domain string) (string, error) {
	// Create a custom HTTP client to handle both HTTP and HTTPS requests
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// Function to make a request and gather headers
	getHeaders := func(url string) (http.Header, error) {
		resp, err := client.Get(url)
		if err != nil {
			return nil, fmt.Errorf("could not make request to the domain: %w", err)
		}
		defer resp.Body.Close()
		return resp.Header, nil
	}

	// Attempt both HTTP and HTTPS
	headers, err := getHeaders("http://" + domain)
	if err != nil {
		headers, err = getHeaders("https://" + domain)
		if err != nil {
			return "", fmt.Errorf("could not make request to the domain using both HTTP and HTTPS: %w", err)
		}
	}

	var technologies []string
	var os string

	// Analyze the headers
	if server := headers.Get("Server"); server != "" {
		technologies = append(technologies, "Server: "+server)
		serverLower := strings.ToLower(server)
		if strings.Contains(serverLower, "apache") {
			technologies = append(technologies, "Technology: Apache")
			os = "Linux/Unix"
		} else if strings.Contains(serverLower, "nginx") {
			technologies = append(technologies, "Technology: Nginx")
			os = "Linux/Unix"
		} else if strings.Contains(serverLower, "microsoft-iis") {
			technologies = append(technologies, "Technology: IIS")
			os = "Windows"
		} else if strings.Contains(serverLower, "cloudflare") {
			technologies = append(technologies, "Technology: Cloudflare")
			os = "Unknown"
		}
	}

	if xPoweredBy := headers.Get("X-Powered-By"); xPoweredBy != "" {
		technologies = append(technologies, "X-Powered-By: "+xPoweredBy)
		xPoweredByLower := strings.ToLower(xPoweredBy)
		if strings.Contains(xPoweredByLower, "php") {
			technologies = append(technologies, "Technology: PHP")
		} else if strings.Contains(xPoweredByLower, "asp.net") {
			technologies = append(technologies, "Technology: ASP.NET")
			os = "Windows"
		} else if strings.Contains(xPoweredByLower, "node.js") {
			technologies = append(technologies, "Technology: Node.js")
		} else if strings.Contains(xPoweredByLower, "java") {
			technologies = append(technologies, "Technology: Java")
		}
	}

	if xAspNetVersion := headers.Get("X-AspNet-Version"); xAspNetVersion != "" {
		technologies = append(technologies, "X-AspNet-Version: "+xAspNetVersion)
		technologies = append(technologies, "Technology: ASP.NET")
		os = "Windows"
	}

	if len(technologies) == 0 {
		return "No specific technologies detected", nil
	}

	result := fmt.Sprintf("\n%s\n%s", color.New(color.FgYellow, color.Bold).Sprint("Server Technologies:"), strings.Join(technologies, "\n"))
	if os != "" {
		result += fmt.Sprintf("\n%s\n%s", color.New(color.FgYellow, color.Bold).Sprint("Operating System:"), os)
	}
	return result, nil
}
