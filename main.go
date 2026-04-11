// THANKS FOR USİNG
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
	whoisparser "github.com/likexian/whois-parser"
)

var (
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

	// Context timeout channel
	done := make(chan struct{})
	go func() {
		defer close(done)
		select {
		case <-ctx.Done():
			return
		case <-time.After(defaultTimeout):
			return
		}
	}()

	// Whois goroutine
	resultChan := make(chan string, 1)
	errChan := make(chan error, 1)

	go func() {
		res, err := whois.Whois(target)
		if err != nil {
			errChan <- err
			return
		}
		resultChan <- res
	}()

	select {
	case <-done:
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
	jobs := make(chan Job, len(targets))
	var wg sync.WaitGroup

	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout*2)
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
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	// IPs
	ips, err := net.LookupIPContext(ctx, domain)
	if err == nil {
		for _, ip := range ips {
			result.IPs = append(result.IPs, ip.String())
		}
	}

	// MX
	mx, err := net.LookupMX(domain)
	if err == nil {
		for _, m := range mx {
			result.MX = append(result.MX, m.Host)
		}
	}

	// NS
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

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return targets, nil
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
	log.SetOutput(os.Stdout)

	cache := NewCache()
	svc := NewWhoisService(cache)

	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Println("\n=== WHOIS & DNS TOOL ===")
		fmt.Println("1) Tek sorgu")
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

			if target == "" {
				log.Println("Hata: Domain boş olamaz")
				continue
			}

			ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
			defer cancel()

			res, err := svc.Lookup(ctx, target)
			if err != nil {
				log.Println("Hata:", err)
				continue
			}

			fmt.Println("\n=== SONUÇ ===")
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

			if len(targets) == 0 {
				log.Println("Dosya boş veya geçersiz")
				continue
			}

			fmt.Printf("Toplam %d hedef bulundu. İşleniyor...\n", len(targets))
			runBulk(targets, svc)

		case "3":
			fmt.Print("Domain: ")
			domain, _ := reader.ReadString('\n')
			domain = strings.TrimSpace(domain)

			res, err := resolveDNS(domain)
			if err != nil {
				log.Println("Hata:", err)
				continue
			}

			out, _ := json.MarshalIndent(res, "", "  ")
			fmt.Println("\n=== DNS SONUÇLARI ===")
			fmt.Println(string(out))

		case "4":
			fmt.Println("Çıkış yapılıyor...")
			return

		default:
			fmt.Println("Geçersiz seçim!")
		}
	}
}
