# WHOIS & DNS CLI Tool

Minimal, hızlı ve concurrency destekli bir WHOIS ve DNS sorgu aracıdır.
Go ile yazılmıştır ve bulk işlemler için optimize edilmiştir.
WHOIS sorgusunu okunabilir halde yapmıştır.
iyi kullanımlar dileriz

## Özellikler

* WHOIS sorgulama (tekli ve toplu)
* DNS kayıtlarını çözümleme (A, MX, NS) // daha fazla ekelyeceğim üşenmessem:D3
* Worker pool ile paralel işlem
* TTL destekli in-memory cache
* Otomatik cache temizleme
* Timeout kontrolü (context tabanlı)
* JSON export desteği (opsiyonel)
* Basit ve hızlı CLI arayüzü

## Kurulum

```bash
git clone https://github.com/kullaniciadi/whois-tool.git
cd whois-tool
go mod tidy
go build -o whois-tool
```

## Kullanım

Programı çalıştır:

```bash
./whois-tool
```

### Menü

```
1) Tek sorgu
2) Toplu sorgu
3) DNS sorgu
4) Çıkış
```

---

## 1. Tek Sorgu

Tek bir domain veya IP için WHOIS sorgusu yapar.

```
Domain/IP: example.com
```

Cache varsa direkt cache’den döner.

---

## 2. Toplu Sorgu

Bir dosya içindeki domain/IP listesini paralel şekilde işler.

### Örnek dosya:

```
example.com
google.com
github.com
```

```
Dosya yolu: targets.txt
```

* 5 worker ile paralel çalışır
* Cache otomatik kullanılır

---

## 3. DNS Sorgu

Bir domain için DNS kayıtlarını getirir.

Çıktı JSON formatındadır:

```json
{
  "ips": ["1.1.1.1"],
  "mx": ["mail.example.com"],
  "ns": ["ns1.example.com"]
}
```

---

## Mimari

Proje basit ama ölçeklenebilir bir yapı kullanır:

```
Cache (TTL + cleanup goroutine)
        ↓
WhoisService (business logic)
        ↓
Worker Pool (concurrency control)
        ↓
CLI (input/output)
```

---

## Teknik Detaylar

* **Timeout:** 10 saniye (context ile kontrol edilir)
* **Cache TTL:** 10 dakika
* **Cleanup:** Her 1 dakikada expired veriler silinir
* **Worker sayısı:** 5

---

## Önemli Notlar

* WHOIS sunucuları rate limit uygulayabilir
* Çok büyük bulk listelerde timeout yaşanabilir
* whois kütüphanesi context desteklemediği için timeout sonrası goroutine çalışmaya devam edebilir

---

## Geliştirme Fikirleri

* Retry mekanizması ekleme
* Custom DNS resolver
* CLI flag desteği (cobra)
* Disk tabanlı cache
* Subdomain enumeration (passive + brute)
* Output format seçenekleri (txt/json)

---

## Lisans

MIT

---

## Amaç

Bu proje:

* Öğrenme & test
* Pentest yardımcı araç geliştirme
* Basit ama etkili CLI tool yazımı
* whois sorgusunu okunaklı hale getirme

amacıyla geliştirilmiştir.
illegal kullanım sonrasında yapımcı değil kullanan sorumlu tutulur.
