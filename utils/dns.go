package utils

import (
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// IsValidDomain checks if the given domain is valid by performing a DNS lookup
func IsValidDomain(domain string) bool {
	_, err := net.LookupHost(domain)
	return err == nil
}

// GetDNSRecords fetches DNS records for a domain
func GetDNSRecords(domain string) (string, error) {
	recordTypes := []uint16{
		dns.TypeA, dns.TypeAAAA, dns.TypeMX, dns.TypeCNAME, dns.TypeTXT, dns.TypeNS,
	}

	servers := []string{"8.8.8.8:53", "1.1.1.1:53"}

	c := dns.Client{
		Timeout: 5 * time.Second,
	}

	var allRecords []string
	var lastErr error

	for _, server := range servers {
		for _, recordType := range recordTypes {
			m := dns.Msg{}
			m.SetQuestion(dns.Fqdn(domain), recordType)
			r, _, err := c.Exchange(&m, server)
			if err != nil {
				lastErr = err
				continue
			}
			for _, ans := range r.Answer {
				allRecords = append(allRecords, ans.String())
			}
		}
	}

	if len(allRecords) == 0 && lastErr != nil {
		return "", lastErr
	}

	return strings.Join(allRecords, "\n"), nil
}
