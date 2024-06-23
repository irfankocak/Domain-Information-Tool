package utils

import (
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
)

// DNSZoneTransferCheck checks if DNS zone transfer is allowed for a given domain.
func DNSZoneTransferCheck(domain string) (string, error) {
	nameservers, err := net.LookupNS(domain)
	if err != nil {
		return "", fmt.Errorf("error: could not fetch nameservers for domain %s: %s", domain, err)
	}

	for _, ns := range nameservers {
		nsAddress := ns.Host

		// Attempt to perform a DNS zone transfer
		transfer, err := performZoneTransfer(domain, nsAddress)
		if err == nil {
			// Successful zone transfer
			return fmt.Sprintf("\nDNS Zone Transfer is enabled on nameserver %s for domain %s:\n%s", nsAddress, domain, transfer), nil
		}
	}

	return fmt.Sprintf("\nDNS Zone Transfer is not enabled for domain %s", domain), nil
}

func performZoneTransfer(domain, nameserver string) (string, error) {
	// Create DNS message for AXFR request
	m := new(dns.Msg)
	m.SetAxfr(domain)
	transfer := new(dns.Transfer)

	// Perform zone transfer
	env, err := transfer.In(m, nameserver)
	if err != nil {
		return "", err
	}

	var records strings.Builder
	for e := range env {
		if e.Error != nil {
			return "", e.Error
		}
		for _, rr := range e.RR {
			records.WriteString(rr.String() + "\n")
		}
	}

	return records.String(), nil
}
