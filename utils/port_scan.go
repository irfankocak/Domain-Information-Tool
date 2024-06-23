package utils

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// ScanPort checks if a port is open on a given hostname
func ScanPort(protocol, hostname string, port int, wg *sync.WaitGroup, results chan<- string, service string) {
	defer wg.Done()
	address := fmt.Sprintf("%s:%d", hostname, port)
	conn, err := net.DialTimeout(protocol, address, 500*time.Millisecond)
	if err == nil {
		results <- fmt.Sprintf("%d (%s)", port, service)
		conn.Close()
	}
}

// PortScan scans common ports on a given hostname and returns their services
func PortScan(hostname string) string {
	ports := map[int]string{
		21:    "FTP",
		22:    "SSH",
		25:    "SMTP",
		53:    "DNS",
		80:    "HTTP",
		110:   "POP3",
		143:   "IMAP",
		389:   "LDAP",
		443:   "HTTPS",
		465:   "SMTPS",
		587:   "SMTP",
		993:   "IMAPS",
		995:   "POP3S",
		1433:  "MSSQL",
		1521:  "Oracle DB",
		3306:  "MySQL",
		3389:  "RDP",
		5432:  "PostgreSQL",
		5900:  "VNC",
		6379:  "Redis",
		8000:  "HTTP-alt",
		8080:  "HTTP-proxy",
		8443:  "HTTPS-alt",
		9200:  "Elasticsearch",
		9300:  "Elasticsearch",
		27017: "MongoDB",
	}

	var wg sync.WaitGroup
	results := make(chan string, len(ports))

	concurrencyLimit := make(chan struct{}, 100) // Adjust the limit as needed

	for port, service := range ports {
		wg.Add(1)
		concurrencyLimit <- struct{}{} // Acquire a slot
		go func(port int, service string) {
			defer func() { <-concurrencyLimit }() // Release the slot
			ScanPort("tcp", hostname, port, &wg, results, service)
		}(port, service)
	}

	wg.Wait()
	close(results)

	var openPorts []string
	for result := range results {
		openPorts = append(openPorts, result)
	}

	return strings.Join(openPorts, "\n")
}
