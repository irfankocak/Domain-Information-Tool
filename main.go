package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"dominfo/utils"

	"github.com/briandowns/spinner"
	"github.com/fatih/color"
)

func main() {
	showBanner()
	for {
		showMenu()
		choice := getUserChoice()
		handleChoice(choice)
	}
}

func showBanner() {

	boldCyan := color.New(color.FgCyan, color.Bold)
	boldCyan.Println("\nWelcome to the Domain Information Tool v1.0")
}

func showMenu() {
	fmt.Println("\n=== Domain Information Tool ===")
	fmt.Println("1. Basic Scan (Whois,SSL-Lab,Dns Records,DnsSEC etc.)")
	fmt.Println("2. Multi Port Scanner (Web,Sql,Ftp,SSH etc.)")
	fmt.Println("3. Security Headers Detection")
	fmt.Println("4. Subdomain Scanner (Top 100 Subdomain)")
	fmt.Println("5. Waf Detection")
	fmt.Println("6. Blacklist Check")
	fmt.Println("7. Detect Server Technologies")
	fmt.Println("8. Full Scan (It may take time.)")
	fmt.Println("0. Exit")
	fmt.Print("\nPlease enter your choice: ")
}

func getUserChoice() int {
	reader := bufio.NewReader(os.Stdin)
	choiceStr, _ := reader.ReadString('\n')
	choiceStr = strings.TrimSpace(choiceStr)
	choice := -1
	fmt.Sscanf(choiceStr, "%d", &choice)
	return choice
}

func handleChoice(choice int) {
	switch choice {
	case 1:
		startBasicScan()
	case 2:
		startPortScan()
	case 3:
		startSecurityHeadersScan()
	case 4:
		startSubdomainScan()
	case 5:
		startWAFScan()
	case 6:
		startBlacklistCheck()
	case 7:
		startServerTechScan()
	case 8:
		startFullScan()
	case 0:
		fmt.Println("Exiting...")
		os.Exit(0)
	default:
		fmt.Println("Invalid choice, please try again.")
	}
}

func getDomainFromUser() string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("\nPlease enter the domain (e.g. example.com): ")
	domain, _ := reader.ReadString('\n')
	return strings.TrimSpace(domain)
}

func startBasicScan() {
	domain := getDomainFromUser()
	if !utils.IsValidDomain(domain) {
		color.Red("\nerror: invalid domain %s\n", domain)
		return
	}

	var wg sync.WaitGroup
	resultCh := make(chan string, 20)
	errorCh := make(chan error, 20)

	s := spinner.New(spinner.CharSets[9], 100*time.Millisecond)
	s.Start()
	color.New(color.FgGreen, color.Bold).Println("\nStarting Basic Scan...")
	time.Sleep(3 * time.Second) // Simulate scanning delay
	s.Stop()

	utils.ClearScreen()
	color.New(color.FgGreen, color.Bold).Println("Listed results...")

	scanFunctions := []func(){
		func() {
			defer wg.Done()
			info, err := utils.GetWhoisInfo(domain)
			if err != nil {
				errorCh <- fmt.Errorf("error: could not fetch whois info: %s", err)
				return
			}
			resultCh <- fmt.Sprintf("\n%s\n%s", color.New(color.FgYellow, color.Bold).Sprint("WHOIS Information:"), utils.ColorizeWhoisInfo(info))
		},
		func() {
			defer wg.Done()
			ssl, err := utils.GetSSLInfo(domain)
			if err != nil {
				errorCh <- fmt.Errorf("error: could not fetch SSL info: %s", err)
				return
			}
			resultCh <- ssl
		},
		func() {
			defer wg.Done()
			sslLabs, err := utils.GetSSLLabsReport(domain)
			if err != nil {
				errorCh <- fmt.Errorf("error: could not fetch SSL Labs report: %s", err)
				return
			}
			resultCh <- sslLabs
		},
		func() {
			defer wg.Done()
			records, err := utils.GetDNSRecords(domain)
			if err != nil {
				errorCh <- fmt.Errorf("error: could not fetch DNS records: %s", err)
				return
			}
			resultCh <- fmt.Sprintf("\n%s\n%s", color.New(color.FgYellow, color.Bold).Sprint("DNS Records:"), records)
		},
		func() {
			defer wg.Done()
			dnsZoneTransferCheck, err := utils.DNSZoneTransferCheck(domain)
			if err != nil {
				errorCh <- fmt.Errorf("error: could not perform DNS zone transfer check: %s", err)
				return
			}
			resultCh <- dnsZoneTransferCheck
		},
		func() {
			defer wg.Done()
			dnsSecCheck, err := utils.CheckDNSSEC(domain)
			if err != nil {
				errorCh <- fmt.Errorf("error: could not check DNSSEC support: %s", err)
				return
			}
			resultCh <- dnsSecCheck
		},
	}

	for _, scanFunc := range scanFunctions {
		wg.Add(1)
		go scanFunc()
	}

	go func() {
		wg.Wait()
		close(resultCh)
		close(errorCh)
	}()

	for res := range resultCh {
		color.New(color.FgYellow, color.Bold).Println(res)
	}
	for err := range errorCh {
		color.Red(err.Error())
	}
}

func startPortScan() {
	domain := getDomainFromUser()
	if !utils.IsValidDomain(domain) {
		color.Red("\nerror: invalid domain %s\n", domain)
		return
	}

	s := spinner.New(spinner.CharSets[9], 100*time.Millisecond)
	s.Start()
	color.New(color.FgGreen, color.Bold).Println("\nStarting Port scan...")
	time.Sleep(3 * time.Second)
	s.Stop()

	portScanResults := fmt.Sprintf("\n%s\n%s", color.New(color.FgYellow, color.Bold).Sprint("Open Ports:"), utils.PortScan(domain))

	utils.ClearScreen()
	fmt.Println(portScanResults)
}

func startSecurityHeadersScan() {
	domain := getDomainFromUser()
	if !utils.IsValidDomain(domain) {
		color.Red("\nerror: invalid domain %s\n", domain)
		return
	}

	s := spinner.New(spinner.CharSets[9], 100*time.Millisecond)
	s.Start()
	color.New(color.FgGreen, color.Bold).Println("\nStarting Security Headers scan...")
	time.Sleep(3 * time.Second)
	s.Stop()

	headers, err := utils.GetSecurityHeadersInfo(domain)
	if err != nil {
		color.Red("error: %s", err)
		return
	}

	utils.ClearScreen()
	fmt.Println(headers)
}

func startSubdomainScan() {
	domain := getDomainFromUser()
	if !utils.IsValidDomain(domain) {
		color.Red("\nerror: invalid domain %s\n", domain)
		return
	}

	s := spinner.New(spinner.CharSets[9], 100*time.Millisecond)
	s.Start()
	color.New(color.FgGreen, color.Bold).Println("\nStarting Subdomain scan...")
	time.Sleep(3 * time.Second)
	s.Stop()

	subdomains, err := utils.GetSubdomains(domain)
	if err != nil {
		color.Red("error: could not fetch subdomains: %s", err)
		return
	}

	subdomainsList := fmt.Sprintf("\n%s\n", color.New(color.FgYellow, color.Bold).Sprint("Subdomains:"))
	for _, subdomain := range subdomains {
		subdomainsList += subdomain + "\n"
	}

	utils.ClearScreen()
	fmt.Println(subdomainsList)
}

func startWAFScan() {
	domain := getDomainFromUser()
	if !utils.IsValidDomain(domain) {
		color.Red("\nerror: invalid domain %s\n", domain)
		return
	}

	s := spinner.New(spinner.CharSets[9], 100*time.Millisecond)
	s.Start()
	color.New(color.FgGreen, color.Bold).Println("\nStarting WAF scan...")
	time.Sleep(3 * time.Second)
	s.Stop()

	waf, err := utils.DetectWAF(domain)
	if err != nil {
		color.Red("error: could not detect WAF: %s", err)
		return
	}

	utils.ClearScreen()
	fmt.Println(waf)
}

func startBlacklistCheck() {
	domain := getDomainFromUser()
	if !utils.IsValidDomain(domain) {
		color.Red("\nerror: invalid domain %s\n", domain)
		return
	}

	s := spinner.New(spinner.CharSets[9], 100*time.Millisecond)
	s.Start()
	color.New(color.FgGreen, color.Bold).Println("\nStarting Blacklist check...")
	time.Sleep(3 * time.Second)
	s.Stop()

	blacklistCheck, err := utils.CheckBlacklist(domain)
	if err != nil {
		color.Red("error: could not check blacklist: %s", err)
		return
	}

	utils.ClearScreen()
	fmt.Println(blacklistCheck)
}

func startServerTechScan() {
	domain := getDomainFromUser()
	if !utils.IsValidDomain(domain) {
		color.Red("\nerror: invalid domain %s\n", domain)
		return
	}

	s := spinner.New(spinner.CharSets[9], 100*time.Millisecond)
	s.Start()
	color.New(color.FgGreen, color.Bold).Println("\nStarting Server Technologies scan...")
	time.Sleep(3 * time.Second)
	s.Stop()

	serverTech, err := utils.DetectServerTechnologies(domain)
	if err != nil {
		color.Red("error: could not detect server technologies: %s", err)
		return
	}

	utils.ClearScreen()
	fmt.Println(serverTech)
}

func startFullScan() {
	domain := getDomainFromUser()
	if !utils.IsValidDomain(domain) {
		color.Red("\nerror: invalid domain %s\n", domain)
		return
	}

	var wg sync.WaitGroup
	resultCh := make(chan string, 20)
	errorCh := make(chan error, 20)

	s := spinner.New(spinner.CharSets[9], 100*time.Millisecond)
	s.Start()
	color.New(color.FgGreen, color.Bold).Println("\nStarting Full Scan...")
	time.Sleep(3 * time.Second) // Simulate scanning delay
	s.Stop()

	utils.ClearScreen()
	color.New(color.FgGreen, color.Bold).Println("Listed results...")

	scanFunctions := []func(){
		func() {
			defer wg.Done()
			info, err := utils.GetWhoisInfo(domain)
			if err != nil {
				errorCh <- fmt.Errorf("error: could not fetch whois info: %s", err)
				return
			}
			resultCh <- fmt.Sprintf("\n%s\n%s", color.New(color.FgYellow, color.Bold).Sprint("WHOIS Information:"), utils.ColorizeWhoisInfo(info))
		},
		func() {
			defer wg.Done()
			ssl, err := utils.GetSSLInfo(domain)
			if err != nil {
				errorCh <- fmt.Errorf("error: could not fetch SSL info: %s", err)
				return
			}
			resultCh <- ssl
		},
		func() {
			defer wg.Done()
			sslLabs, err := utils.GetSSLLabsReport(domain)
			if err != nil {
				errorCh <- fmt.Errorf("error: could not fetch SSL Labs report: %s", err)
				return
			}
			resultCh <- sslLabs
		},
		func() {
			defer wg.Done()
			records, err := utils.GetDNSRecords(domain)
			if err != nil {
				errorCh <- fmt.Errorf("error: could not fetch DNS records: %s", err)
				return
			}
			resultCh <- fmt.Sprintf("\n%s\n%s", color.New(color.FgYellow, color.Bold).Sprint("DNS Records:"), records)
		},
		func() {
			defer wg.Done()
			portScanResults := fmt.Sprintf("\n%s\n%s", color.New(color.FgYellow, color.Bold).Sprint("Open Ports:"), utils.PortScan(domain))
			resultCh <- portScanResults
		},
		func() {
			defer wg.Done()
			headers, err := utils.GetSecurityHeadersInfo(domain)
			if err != nil {
				errorCh <- fmt.Errorf("error: %s", err)
				return
			}
			resultCh <- headers
		},
		func() {
			defer wg.Done()
			subdomains, err := utils.GetSubdomains(domain)
			if err != nil {
				errorCh <- fmt.Errorf("error: could not fetch subdomains: %s", err)
				return
			}
			subdomainsList := fmt.Sprintf("\n%s\n", color.New(color.FgYellow, color.Bold).Sprint("Subdomains:"))
			for _, subdomain := range subdomains {
				subdomainsList += subdomain + "\n"
			}
			resultCh <- subdomainsList
		},
		func() {
			defer wg.Done()
			waf, err := utils.DetectWAF(domain)
			if err != nil {
				errorCh <- fmt.Errorf("error: could not detect WAF: %s", err)
				return
			}
			resultCh <- waf
		},
		func() {
			defer wg.Done()
			dnsZoneTransferCheck, err := utils.DNSZoneTransferCheck(domain)
			if err != nil {
				errorCh <- fmt.Errorf("error: could not perform DNS zone transfer check: %s", err)
				return
			}
			resultCh <- dnsZoneTransferCheck
		},
		func() {
			defer wg.Done()
			dnsSecCheck, err := utils.CheckDNSSEC(domain)
			if err != nil {
				errorCh <- fmt.Errorf("error: could not check DNSSEC support: %s", err)
				return
			}
			resultCh <- dnsSecCheck
		},
		func() {
			defer wg.Done()
			blacklistCheck, err := utils.CheckBlacklist(domain)
			if err != nil {
				errorCh <- fmt.Errorf("error: could not check blacklist: %s", err)
				return
			}
			resultCh <- blacklistCheck
		},
		func() {
			defer wg.Done()
			serverTech, err := utils.DetectServerTechnologies(domain)
			if err != nil {
				errorCh <- fmt.Errorf("error: could not detect server technologies: %s", err)
				return
			}
			resultCh <- serverTech
		},
	}

	for _, scanFunc := range scanFunctions {
		wg.Add(1)
		go scanFunc()
	}

	go func() {
		wg.Wait()
		close(resultCh)
		close(errorCh)
	}()

	for res := range resultCh {
		color.New(color.FgYellow, color.Bold).Println(res)
	}
	for err := range errorCh {
		color.Red(err.Error())
	}
}
