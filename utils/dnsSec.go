package utils

import (
	"fmt"
	"net"

	"github.com/fatih/color"
	"github.com/miekg/dns"
)

// CheckDNSSEC, belirtilen domain için DNSSEC desteğinin olup olmadığını kontrol eder
func CheckDNSSEC(domain string) (string, error) {
	domain = dns.Fqdn(domain)
	config, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return "", fmt.Errorf("error reading resolv.conf: %v", err)
	}

	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion(domain, dns.TypeDNSKEY)
	m.RecursionDesired = true

	r, _, err := c.Exchange(m, net.JoinHostPort(config.Servers[0], config.Port))
	if err != nil {
		return "", fmt.Errorf("error querying DNSKEY records: %v", err)
	}

	for _, answer := range r.Answer {
		if _, ok := answer.(*dns.DNSKEY); ok {
			return fmt.Sprintf("\n%s\n%s", color.New(color.FgYellow, color.Bold).Sprint("DNSSEC Support:"), "Yes"), nil
		}
	}

	return fmt.Sprintf("\n%s\n%s", color.New(color.FgYellow, color.Bold).Sprint("DNSSEC Support:"), "No"), nil
}
