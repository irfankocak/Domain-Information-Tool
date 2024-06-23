package utils

import (
	"bufio"
	"net/http"
	"os"
	"sync"
)

const workerCount = 20

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
	"Mozilla/5.0 (Windows NT 10.0; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.1.1 Safari/605.1.15",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 11_0 like Mac OS X) AppleWebKit/604.1.38 (KHTML, like Gecko) Version/11.0 Mobile/15A372 Safari/604.1",
}

func worker(subdomainsChan <-chan string, resultsChan chan<- string, wg *sync.WaitGroup) {
	defer wg.Done()
	for subdomain := range subdomainsChan {
		for _, userAgent := range userAgents {
			client := &http.Client{}
			req, err := http.NewRequest("GET", "http://"+subdomain, nil)
			if err != nil {
				continue
			}
			req.Header.Set("User-Agent", userAgent)

			resp, err := client.Do(req)
			if err == nil && resp.StatusCode == http.StatusOK {
				resultsChan <- subdomain
				break
			}
		}
	}
}

func GetSubdomains(domain string) ([]string, error) {
	file, err := os.Open("subdomains.txt") // Subdomain wordlist file
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var subdomains []string
	scanner := bufio.NewScanner(file)

	subdomainsChan := make(chan string, workerCount)
	resultsChan := make(chan string, workerCount)

	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go worker(subdomainsChan, resultsChan, &wg)
	}

	// Send subdomains to workers
	go func() {
		for scanner.Scan() {
			subdomain := scanner.Text() + "." + domain
			subdomainsChan <- subdomain
		}
		close(subdomainsChan)
	}()

	// Collect results in a separate goroutine
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// Collect results from resultsChan
	for result := range resultsChan {
		subdomains = append(subdomains, result)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return subdomains, nil
}
