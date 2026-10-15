```go
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/likexian/whois"
)

const (
	version       = "2.0.0"
	defaultTimeout = 10 * time.Second
	cacheTTL       = 10 * time.Minute
	cacheCleanup   = time.Minute
	defaultWorkers = 5
	maxWorkers     = 20
)

type CacheItem struct {
	Data      string
	ExpiresAt time.Time
}

type Cache struct {
	data map[string]CacheItem
	mu   sync.RWMutex
}

func NewCache() *Cache {
	cache := &Cache{
		data: make(map[string]CacheItem),
	}
	go cache.cleanupLoop()
	return cache
}

func (c *Cache) Get(key string) (string, bool) {
	c.mu.RLock()
	item, exists := c.data[key]
	c.mu.RUnlock()

	if !exists || time.Now().After(item.ExpiresAt) {
		return "", false
	}

	return item.Data, true
}

func (c *Cache) Set(key, value string) {
	c.mu.Lock()
	c.data[key] = CacheItem{
		Data:      value,
		ExpiresAt: time.Now().Add(cacheTTL),
	}
	c.mu.Unlock()
}

func (c *Cache) Clear() {
	c.mu.Lock()
	clear(c.data)
	c.mu.Unlock()
}

func (c *Cache) cleanupLoop() {
	ticker := time.NewTicker(cacheCleanup)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()

		c.mu.Lock()
		for key, item := range c.data {
			if now.After(item.ExpiresAt) {
				delete(c.data, key)
			}
		}
		c.mu.Unlock()
	}
}

type WhoisResult struct {
	Target    string `json:"target"`
	Success   bool   `json:"success"`
	Cached    bool   `json:"cached"`
	Data      string `json:"data,omitempty"`
	Error     string `json:"error,omitempty"`
	QueriedAt string `json:"queried_at,omitempty"`
}

type WhoisService struct {
	cache   *Cache
	timeout time.Duration
}

func NewWhoisService(cache *Cache, timeout time.Duration) *WhoisService {
	return &WhoisService{
		cache:   cache,
		timeout: timeout,
	}
}

func normalizeTarget(target string) (string, error) {
	target = strings.TrimSpace(target)
	target = strings.TrimSuffix(target, ".")

	if target == "" {
		return "", errors.New("target cannot be empty")
	}

	if len(target) > 253 {
		return "", errors.New("domain name is too long")
	}

	target = strings.ToLower(target)

	if net.ParseIP(target) != nil {
		return target, nil
	}

	labelPattern := regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$`)

	if !strings.Contains(target, ".") {
		return "", errors.New("provide a fully qualified domain name")
	}

	for _, label := range strings.Split(target, ".") {
		if len(label) > 63 || !labelPattern.MatchString(label) {
			return "", errors.New("invalid domain name format")
		}
	}

	return target, nil
}

func (w *WhoisService) Lookup(ctx context.Context, target string) WhoisResult {
	normalized, err := normalizeTarget(target)
	if err != nil {
		return WhoisResult{
			Target:  target,
			Success: false,
			Error:   err.Error(),
		}
	}

	if cached, exists := w.cache.Get("whois:" + normalized); exists {
		return WhoisResult{
			Target:    normalized,
			Success:   true,
			Cached:    true,
			Data:      cached,
			QueriedAt: time.Now().UTC().Format(time.RFC3339),
		}
	}

	queryCtx, cancel := context.WithTimeout(ctx, w.timeout)
	defer cancel()

	resultChannel := make(chan struct {
		data string
		err  error
	}, 1)

	go func() {
		data, err := whois.Whois(normalized)
		resultChannel <- struct {
			data string
			err  error
		}{data: data, err: err}
	}()

	select {
	case <-queryCtx.Done():
		return WhoisResult{
			Target:  normalized,
			Success: false,
			Error:   "WHOIS query timed out or was canceled",
		}

	case result := <-resultChannel:
		if result.err != nil {
			return WhoisResult{
				Target:  normalized,
				Success: false,
				Error:   result.err.Error(),
			}
		}

		w.cache.Set("whois:"+normalized, result.data)

		return WhoisResult{
			Target:    normalized,
			Success:   true,
			Cached:    false,
			Data:      result.data,
			QueriedAt: time.Now().UTC().Format(time.RFC3339),
		}
	}
}

type DNSResult struct {
	Target    string              `json:"target"`
	Success   bool                `json:"success"`
	Records   map[string][]string `json:"records"`
	Errors    map[string]string   `json:"errors"`
	QueriedAt string              `json:"queried_at"`
}

func resolveDNS(ctx context.Context, domain string, timeout time.Duration) DNSResult {
	normalized, err := normalizeTarget(domain)
	if err != nil {
		return DNSResult{
			Target:  domain,
			Success: false,
			Errors:  map[string]string{"validation": err.Error()},
		}
	}

	if net.ParseIP(normalized) != nil {
		return DNSResult{
			Target:  normalized,
			Success: false,
			Errors:  map[string]string{"validation": "DNS queries require a domain name"},
		}
	}

	queryCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	result := DNSResult{
		Target:    normalized,
		Success:   true,
		Records:   make(map[string][]string),
		Errors:    make(map[string]string),
		QueriedAt: time.Now().UTC().Format(time.RFC3339),
	}

	resolver := net.DefaultResolver

	ips, err := resolver.LookupIPAddr(queryCtx, normalized)
	if err != nil {
		result.Errors["A/AAAA"] = err.Error()
	} else {
		for _, entry := range ips {
			if entry.IP.To4() != nil {
				result.Records["A"] = append(result.Records["A"], entry.IP.String())
			} else {
				result.Records["AAAA"] = append(result.Records["AAAA"], entry.IP.String())
			}
		}
	}

	mxRecords, err := resolver.LookupMX(queryCtx, normalized)
	if err != nil {
		result.Errors["MX"] = err.Error()
	} else {
		for _, entry := range mxRecords {
			result.Records["MX"] = append(
				result.Records["MX"],
				fmt.Sprintf("%d %s", entry.Pref, strings.TrimSuffix(entry.Host, ".")),
			)
		}
	}

	nsRecords, err := resolver.LookupNS(queryCtx, normalized)
	if err != nil {
		result.Errors["NS"] = err.Error()
	} else {
		for _, entry := range nsRecords {
			result.Records["NS"] = append(
				result.Records["NS"],
				strings.TrimSuffix(entry.Host, "."),
			)
		}
	}

	txtRecords, err := resolver.LookupTXT(queryCtx, normalized)
	if err != nil {
		result.Errors["TXT"] = err.Error()
	} else {
		result.Records["TXT"] = txtRecords
	}

	cname, err := resolver.LookupCNAME(queryCtx, normalized)
	if err != nil {
		result.Errors["CNAME"] = err.Error()
	} else if cname != normalized+"." {
		result.Records["CNAME"] = []string{
			strings.TrimSuffix(cname, "."),
		}
	}

	if len(result.Errors) > 0 && len(result.Records) == 0 {
		result.Success = false
	}

	return result
}

type PTRResult struct {
	Target    string   `json:"target"`
	Success   bool     `json:"success"`
	PTR       []string `json:"ptr,omitempty"`
	Error     string   `json:"error,omitempty"`
	QueriedAt string   `json:"queried_at,omitempty"`
}

func reverseDNS(ctx context.Context, address string, timeout time.Duration) PTRResult {
	ip := net.ParseIP(strings.TrimSpace(address))
	if ip == nil {
		return PTRResult{
			Target:  address,
			Success: false,
			Error:   "invalid IP address",
		}
	}

	queryCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	names, err := net.DefaultResolver.LookupAddr(queryCtx, ip.String())
	if err != nil {
		return PTRResult{
			Target:  ip.String(),
			Success: false,
			Error:   err.Error(),
		}
	}

	for i, name := range names {
		names[i] = strings.TrimSuffix(name, ".")
	}

	return PTRResult{
		Target:    ip.String(),
		Success:   true,
		PTR:       names,
		QueriedAt: time.Now().UTC().Format(time.RFC3339),
	}
}

func readTargets(path string) ([]string, error) {
	file, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var targets []string
	seen := make(map[string]struct{})

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		target := strings.TrimSpace(scanner.Text())

		if target == "" || strings.HasPrefix(target, "#") {
			continue
		}

		if _, exists := seen[target]; exists {
			continue
		}

		seen[target] = struct{}{}
		targets = append(targets, target)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return targets, nil
}

func exportJSON(data any, path string) error {
	if path == "" {
		return errors.New("output path cannot be empty")
	}

	outputPath := filepath.Clean(path)

	if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
		return err
	}

	content, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(outputPath, append(content, '\n'), 0644)
}

func printJSON(data any) {
	output, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		log.Printf("JSON encoding error: %v", err)
		return
	}

	fmt.Println(string(output))
}

func runBulk(
	ctx context.Context,
	targets []string,
	service *WhoisService,
	workers int,
) []WhoisResult {
	if workers < 1 {
		workers = defaultWorkers
	}
	if workers > maxWorkers {
		workers = maxWorkers
	}
	if workers > len(targets) {
		workers = len(targets)
	}
	if len(targets) == 0 {
		return []WhoisResult{}
	}

	jobs := make(chan string)
	results := make(chan WhoisResult, len(targets))

	var wg sync.WaitGroup

	for id := 1; id <= workers; id++ {
		wg.Add(1)

		go func(workerID int) {
			defer wg.Done()

			for target := range jobs {
				log.Printf("[Worker %d] Querying %s", workerID, target)
				results <- service.Lookup(ctx, target)
			}
		}(id)
	}

	go func() {
		defer close(jobs)

		for _, target := range targets {
			select {
			case jobs <- target:
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	output := make([]WhoisResult, 0, len(targets))

	for result := range results {
		status := "OK"
		if !result.Success {
			status = "ERROR"
		}

		log.Printf("[%s] %s", status, result.Target)
		output = append(output, result)
	}

	return output
}

func interactive(timeout time.Duration, workers int) {
	cache := NewCache()
	service := NewWhoisService(cache, timeout)
	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Println("\nWHOIS & DNS CLI")
		fmt.Println("1) WHOIS lookup")
		fmt.Println("2) Bulk WHOIS lookup")
		fmt.Println("3) DNS lookup")
		fmt.Println("4) Reverse DNS lookup")
		fmt.Println("5) Clear cache")
		fmt.Println("6) Exit")
		fmt.Print("Select an option: ")

		choice, err := reader.ReadString('\n')
		if err != nil {
			fmt.Println("\nExiting.")
			return
		}

		switch strings.TrimSpace(choice) {
		case "1":
			fmt.Print("Domain/IP: ")
			target, _ := reader.ReadString('\n')

			ctx := context.Background()
			printJSON(service.Lookup(ctx, strings.TrimSpace(target)))

		case "2":
			fmt.Print("Target file: ")
			path, _ := reader.ReadString('\n')

			targets, err := readTargets(strings.TrimSpace(path))
			if err != nil {
				log.Printf("File error: %v", err)
				continue
			}

			results := runBulk(context.Background(), targets, service, workers)

			fmt.Print("Export results to JSON? [y/N]: ")
			answer, _ := reader.ReadString('\n')

			if strings.EqualFold(strings.TrimSpace(answer), "y") {
				fmt.Print("Output file: ")
				output, _ := reader.ReadString('\n')

				if err := exportJSON(results, strings.TrimSpace(output)); err != nil {
					log.Printf("Export error: %v", err)
				} else {
					fmt.Println("Results exported successfully.")
				}
			}

		case "3":
			fmt.Print("Domain: ")
			domain, _ := reader.ReadString('\n')

			result := resolveDNS(
				context.Background(),
				strings.TrimSpace(domain),
				timeout,
			)
			printJSON(result)

			fmt.Print("Export results to JSON? [y/N]: ")
			answer, _ := reader.ReadString('\n')

			if strings.EqualFold(strings.TrimSpace(answer), "y") {
				fmt.Print("Output file: ")
				output, _ := reader.ReadString('\n')

				if err := exportJSON(result, strings.TrimSpace(output)); err != nil {
					log.Printf("Export error: %v", err)
				} else {
					fmt.Println("Results exported successfully.")
				}
			}

		case "4":
			fmt.Print("IP address: ")
			address, _ := reader.ReadString('\n')

			printJSON(reverseDNS(
				context.Background(),
				strings.TrimSpace(address),
				timeout,
			))

		case "5":
			cache.Clear()
			fmt.Println("Cache cleared.")

		case "6":
			fmt.Println("Exiting.")
			return

		default:
			fmt.Println("Invalid option.")
		}
	}
}

func main() {
	log.SetFlags(log.LstdFlags)
	log.SetOutput(os.Stdout)

	timeoutFlag := flag.Int("timeout", int(defaultTimeout.Seconds()), "Lookup timeout in seconds")
	workersFlag := flag.Int("workers", defaultWorkers, "Number of concurrent workers")
	whoisFlag := flag.String("whois", "", "Perform a WHOIS lookup")
	dnsFlag := flag.String("dns", "", "Perform a DNS lookup")
	ptrFlag := flag.String("ptr", "", "Perform a reverse DNS lookup")
	fileFlag := flag.String("file", "", "Read targets from a file")
	outputFlag := flag.String("output", "", "Export results to a JSON file")
	versionFlag := flag.Bool("version", false, "Display version information")

	flag.Parse()

	if *versionFlag {
		fmt.Println(version)
		return
	}

	if *timeoutFlag < 1 || *timeoutFlag > 120 {
		log.Fatal("--timeout must be between 1 and 120 seconds")
	}

	if *workersFlag < 1 || *workersFlag > maxWorkers {
		log.Fatalf("--workers must be between 1 and %d", maxWorkers)
	}

	operations := 0
	for _, selected := range []bool{
		*whoisFlag != "",
		*dnsFlag != "",
		*ptrFlag != "",
		*fileFlag != "",
	} {
		if selected {
			operations++
		}
	}

	if operations > 1 {
		log.Fatal("Choose only one operation at a time")
	}

	timeout := time.Duration(*timeoutFlag) * time.Second
	cache := NewCache()
	service := NewWhoisService(cache, timeout)
	ctx := context.Background()

	var result any

	switch {
	case *whoisFlag != "":
		result = service.Lookup(ctx, *whoisFlag)

	case *dnsFlag != "":
		result = resolveDNS(ctx, *dnsFlag, timeout)

	case *ptrFlag != "":
		result = reverseDNS(ctx, *ptrFlag, timeout)

	case *fileFlag != "":
		targets, err := readTargets(*fileFlag)
		if err != nil {
			log.Fatal(err)
		}

		result = runBulk(ctx, targets, service, *workersFlag)

	default:
		interactive(timeout, *workersFlag)
		return
	}

	if *outputFlag != "" {
		if err := exportJSON(result, *outputFlag); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Results saved to %s\n", *outputFlag)
	} else {
		printJSON(result)
	}
}
```
