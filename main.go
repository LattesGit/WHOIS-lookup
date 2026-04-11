// KOD LATENT TARAFINDAN YAPILDI İLLEGAL ŞEYLER İÇİN KULLANILIRSA KULLANAN KİŞİ SORUMLUDUR
// LATENT BU KONUDA SORUMLU TUTULMAZ
// KOD:

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/likexian/whois"
)

// ================= CONFIG =================

const (
	defaultTimeout = 10 * time.Second
	cacheTTL       = 10 * time.Minute
	cacheCleanup   = 1 * time.Minute
	workerCount    = 5
)

// ================= CACHE =================

type CacheItem struct {
	Data      string
	ExpiresAt time.Time
}

type Cache struct {
	data map[string]CacheItem
	mu   sync.RWMutex
}

func NewCache() *Cache {
	c := &Cache{data: make(map[string]CacheItem)}
	go c.cleanupLoop()
	return c
}

func (c *Cache) Get(key string) (string, bool) {
	c.mu.RLock()
	item, ok := c.data[key]
	c.mu.RUnlock()

	if !ok || time.Now().After(item.ExpiresAt) {
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

func (c *Cache) cleanupLoop() {
	for {
		time.Sleep(cacheCleanup)
		c.mu.Lock()
		for k, v := range c.data {
			if time.Now().After(v.ExpiresAt) {
				delete(c.data, k)
			}
		}
		c.mu.Unlock()
	}
}

// ================= WHOIS =================

type WhoisService struct {
	cache *Cache
}

func NewWhoisService(cache *Cache) *WhoisService {
	return &WhoisService{cache: cache}
}

func (w *WhoisService) Lookup(ctx context.Context, target string) (string, error) {
	if target == "" {
		return "", errors.New("boş target")
	}

	if data, ok := w.cache.Get(target); ok {
		return data, nil
	}

	resultChan := make(chan string, 1)
	errChan := make(chan error, 1)

	go func() {
		res, err := whois.Raw(target)
		if err != nil {
			errChan <- err
			return
		}
		resultChan <- res
	}()

	select {
	case <-ctx.Done():
		return "", errors.New("timeout")
	case err := <-errChan:
		return "", err
	case res := <-resultChan:
		w.cache.Set(target, res)
		return res, nil
	}
}

// ================= WORKER POOL =================

type Job struct {
	Target string
}

func worker(ctx context.Context, id int, jobs <-chan Job, svc *WhoisService, wg *sync.WaitGroup) {
	defer wg.Done()

	for job := range jobs {
		log.Printf("[Worker %d] Sorgu: %s", id, job.Target)

		res, err := svc.Lookup(ctx, job.Target)
		if err != nil {
			log.Printf("[Worker %d] Hata: %v", id, err)
			continue
		}

		printPreview(res)
	}
}

func runBulk(targets []string, svc *WhoisService) {
	jobs := make(chan Job)
	var wg sync.WaitGroup

	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go worker(ctx, i, jobs, svc, &wg)
	}

	for _, t := range targets {
		jobs <- Job{Target: t}
	}
	close(jobs)

	wg.Wait()
}

// ================= DNS =================

type DNSResult struct {
	IPs []string `json:"ips"`
	MX  []string `json:"mx"`
	NS  []string `json:"ns"`
}

func resolveDNS(domain string) (*DNSResult, error) {
	if domain == "" {
		return nil, errors.New("boş domain")
	}

	result := &DNSResult{}

	ips, err := net.LookupIP(domain)
	if err == nil {
		for _, ip := range ips {
			result.IPs = append(result.IPs, ip.String())
		}
	}

	mx, err := net.LookupMX(domain)
	if err == nil {
		for _, m := range mx {
			result.MX = append(result.MX, m.Host)
		}
	}

	ns, err := net.LookupNS(domain)
	if err == nil {
		for _, n := range ns {
			result.NS = append(result.NS, n.Host)
		}
	}

	return result, nil
}

// ================= UTIL =================

func readFile(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var targets []string
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			targets = append(targets, line)
		}
	}

	return targets, nil
}

func exportJSON(data interface{}, filename string) error {
	file, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, file, 0644)
}

func printPreview(data string) {
	if len(data) > 120 {
		fmt.Println(data[:120] + "...")
	} else {
		fmt.Println(data)
	}
}

// ================= MAIN =================

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	cache := NewCache()
	svc := NewWhoisService(cache)

	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Println("\n1) Tek sorgu")
		fmt.Println("2) Toplu sorgu")
		fmt.Println("3) DNS sorgu")
		fmt.Println("4) Çıkış")

		fmt.Print("Seçim: ")
		choice, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(choice)

		switch choice {

		case "1":
			fmt.Print("Domain/IP: ")
			target, _ := reader.ReadString('\n')
			target = strings.TrimSpace(target)

			ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
			res, err := svc.Lookup(ctx, target)
			cancel()

			if err != nil {
				log.Println("Hata:", err)
				continue
			}

			fmt.Println(res)

		case "2":
			fmt.Print("Dosya yolu: ")
			path, _ := reader.ReadString('\n')
			path = strings.TrimSpace(path)

			targets, err := readFile(path)
			if err != nil {
				log.Println("Dosya hatası:", err)
				continue
			}

			runBulk(targets, svc)

		case "3":
			fmt.Print("Domain: ")
			domain, _ := reader.ReadString('\n')
			domain = strings.TrimSpace(domain)

			res, err := resolveDNS(domain)
			if err != nil {
				log.Println(err)
				continue
			}

			out, _ := json.MarshalIndent(res, "", "  ")
			fmt.Println(string(out))

		case "4":
			return
		}
	}
}
