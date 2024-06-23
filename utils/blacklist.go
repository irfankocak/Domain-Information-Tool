package utils

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/fatih/color"
)

// DNSBL listesi, kullanılan kara liste servislerini içerir
var DNSBL = map[string]string{
	"Composite Blocking":          "cbl.abuseat.org",
	"Barracuda Reputation Block":  "b.barracudacentral.org",
	"DNSBL SPFBL":                 "dnsbl.spfbl.net",
	"URIBL red":                   "red.uribl.com",
	"URIBL grey":                  "grey.uribl.com",
	"URIBL black":                 "black.uribl.com",
	"URIBL multi":                 "multi.uribl.com",
	"DroneBL":                     "dnsbl.dronebl.org",
	"abuse.ro RBL":                "rbl.abuse.ro",
	"anonmails.de DNSBL":          "spam.dnsbl.anonmails.de",
	"JIPPG`s Relay Blackhole":     "mail-abuse.blacklist.jippg.org",
	"BlockedServers":              "rbl.blockedservers.com",
	"BlockList.de":                "bl.blocklist.de",
	"Blog Spam Blacklist":         "list.blogspambl.com",
	"Calivent DNSBL":              "dnsbl.calivent.com.pe",
	"IBM DNS Blacklist":           "dnsbl.cobion.com",
	"Bogon":                       "bogons.cymru.com",
	"Torexit":                     "torexit.dan.me.uk",
	"Servicios RBL":               "rbl.dns-servicios.com",
	"DrMX":                        "bl.drmx.org",
	"EFnet - TOR":                 "rbl.efnetrbl.org",
	"SpamSources RBL":             "spamsources.fabel.dk",
	"ZapBL DNSRBL":                "dnsbl.zapbl.net",
	"Blog Spam Blocklist":         "bsb.empty.us",
	"Spam Lookup RBL":             "bsb.spamlookup.net",
	"Spam Eating Monkey":          "fresh.spameatingmonkey.net",
	"SURBL multi":                 "multi.surbl.org",
	"Woodys SMTP Blacklist URIBL": "uri.blacklist.woody.ch",
	"Dynip Rothen List":           "dynip.rothen.com",
	"ZoneEdit deny DNS ":          "ban.zebl.zoneedit.com",
	"The Day Old Bread List":      "dob.sibl.support-intelligence.net",
	"Rymshos RHSBL":               "rhsbl.rymsho.ru",
	"abuse.ro URI RBL":            "uribl.abuse.ro",
	"Zen DNSBL":                   "zen.spamhaus.org",
	"Spamcop BL":                  "bl.spamcop.net",
	"UceProtect DNSBL":            "dnsbl-1.uceprotect.net",
	"Surriel PSBL":                "psbl.surriel.com",
	"SpamHaus DNSBL":              "dnsbl.sbl.spamhaus.org",
	"SpamHaus PBL":                "pbl.spamhaus.org",
	"SpamHaus SBL":                "sbl-xbl.spamhaus.org",
	"SpamHaus XBL":                "xbl.spamhaus.org",
	"SORBS Spam":                  "spam.dnsbl.sorbs.net",
	"SpamRATS":                    "zen.spamrats.com",
	"SORBS Escalations":           "escalations.dnsbl.sorbs.net",
	"SORBS Safe":                  "safe.dnsbl.sorbs.net",
	"UCEPROTECT Level 1":          "dnsbl-1.uceprotect.net",
	"UCEPROTECT Level 2":          "dnsbl-2.uceprotect.net",
	"UCEPROTECT Level 3":          "dnsbl-3.uceprotect.net",
	"UCEPROTECT Level 4":          "dnsbl-4.uceprotect.net",
	"Team Cymru":                  "bogons.cymru.com",
	"Backscatterer":               "ips.backscatterer.org",
	"Abuseat":                     "truncate.gbudb.net",
	"Invaluement":                 "ubl.unsubscore.com",
	"Mailspike":                   "bl.mailspike.net",
	"Sorbs Zombie":                "zombie.dnsbl.sorbs.net",
	"Mail Spike":                  "z.mailspike.net",
	"Worm RBL":                    "wormrbl.imp.ch",
	"RBL.jp":                      "virus.rbl.jp",
	"Lash Hack UBL":               "ubl.lashback.com",
	"Abuse.ch":                    "spam.abuse.ch",
	"Spfbl DNSBL":                 "dnsbl.spfbl.net",
	"S5h ALL":                     "all.s5h.net",
	"Inps DNSBL":                  "dnsbl.inps.de",
	"Korea Services":              "korea.services.net",
	"0Spam Project":               "bl.0spam.org",
	"0spam DBL":                   "url.0spam.org",
	"Anonmails":                   "spam.dnsbl.anonmails.de",
	"JustSpam":                    "dnsbl.justspam.org",
}

// DNS İstemcisi (Resolver) tanımlama
var resolver = &net.Resolver{
	PreferGo: true,
	Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		d := net.Dialer{
			Timeout: time.Second * 5, // Zaman aşımı süresi
		}
		return d.DialContext(ctx, network, address)
	},
}

// CheckBlacklist, belirtilen domain ve IP adreslerinin kara listede olup olmadığını kontrol eder
func CheckBlacklist(domain string) (string, error) {
	var results []string

	// IP adresleri için kara liste kontrolü yap
	ips, err := net.LookupIP(domain)
	if err != nil {
		return "", fmt.Errorf("error resolving domain %s: %v", domain, err)
	}

	var wg sync.WaitGroup
	resultsChan := make(chan string, len(ips)*len(DNSBL))
	errChan := make(chan error, len(ips)*len(DNSBL))

	// Concurrency Limit: Limiting the number of concurrent goroutines
	concurrencyLimit := make(chan struct{}, 10) // Adjust the limit as needed

	for _, ip := range ips {
		// Sadece IPv4 adresleri üzerinde çalışalım
		if ip.To4() == nil {
			continue
		}
		ip := ip.String() // Capture loop variable
		for name, service := range DNSBL {
			name, service := name, service // Capture loop variables
			wg.Add(1)
			go func() {
				defer wg.Done()
				concurrencyLimit <- struct{}{}        // Acquire a slot
				defer func() { <-concurrencyLimit }() // Release the slot

				listed, err := checkBlacklistService(ip, service)
				if err != nil {
					errChan <- fmt.Errorf("error checking %s on %s: %v", ip, service, err)
					return
				}
				if listed {
					resultsChan <- fmt.Sprintf("%s\t%s: %s", ip, name, service)
				}
			}()
		}
	}

	go func() {
		wg.Wait()
		close(resultsChan)
		close(errChan)
	}()

	for res := range resultsChan {
		results = append(results, res)
	}

	if len(results) == 0 {
		return fmt.Sprintf("\n%s\n%s", color.New(color.FgYellow, color.Bold).Sprint("Blacklist Check:"), "No IP addresses are listed in any known blacklists"), nil
	}

	if len(errChan) > 0 {
		// Tüm hata mesajlarını döndürüyoruz
		for err := range errChan {
			fmt.Println(color.RedString("error: %v", err))
		}
	}

	return formatResults(results), nil
}

func checkBlacklistService(item, service string) (bool, error) {
	query := fmt.Sprintf("%s.%s", reverseIP(item), service)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := resolver.LookupIP(ctx, "ip", query)
	if err == nil {
		return true, nil
	}
	if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.Err == "no such host" {
		return false, nil
	}
	return false, err
}

func reverseIP(ip string) string {
	parts := strings.Split(ip, ".")
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	return strings.Join(parts, ".")
}

func formatResults(results []string) string {
	var sb strings.Builder
	w := tabwriter.NewWriter(&sb, 0, 0, 2, ' ', tabwriter.Debug)

	fmt.Fprintln(w, color.New(color.FgYellow, color.Bold).Sprint("\nBlacklist Check Results:"))
	fmt.Fprintln(w, "IP Address\tBlacklist Service")
	fmt.Fprintln(w, "----------\t----------------")

	blacklistMap := make(map[string][]string)
	for _, result := range results {
		parts := strings.SplitN(result, "\t", 2)
		ip := parts[0]
		service := parts[1]
		blacklistMap[ip] = append(blacklistMap[ip], service)
	}

	for ip, services := range blacklistMap {
		for _, service := range services {
			fmt.Fprintf(w, "%s\t%s\n", ip, service)
		}
	}

	w.Flush()
	return sb.String()
}
