[[🔍 WHOIS-Lookup

**En iyi terminal WHOIS sorgusu aracı.** Clean output, %100 okunabilirlik, txt dosyasına otomatik kayıt, hatasız çalışma. WHOIS sorgusunu ChatGPT'ye Claude'a atmadan anlamak istiyorsan — bu kesinlikle aradığın tool'dur.

## Nedir?

**WHOIS-Lookup**, WHOIS sorgularını terminal menüsüyle kolay bir şekilde yapmanı sağlayan bir Go uygulamasıdır. Hedef domain/IP'yi gir, ve detaylı bilgileri al — parse edilmiş, renkli, okunabilir format'ta. Sonuçlar otomatik olarak temiz TXT dosyasına kaydedilir.

## Özellikler

```
[✓] Single domain/IP lookup
[✓] Bulk file processing (satır satır hedefler)
[✓] Renkli & formatted terminal çıktısı
[✓] Domain, nameserver, registrar, owner bilgileri
[✓] Sonuçları TXT dosyaya kaydetme
[✓] Custom dosya yolu belirleme
[✓] Error handling & rate limiting
[✓] Standalone binary (dependency yok)
```

## Kullanım Senaryoları

- **Reconnaissance**: Hedef domain'in whois bilgisini topla
- **Enumeration**: Nameserver'ları, registrar'ı ve sahibi tespit et
- **Bulk Analysis**: Birden çok domain'i organize şekilde sorgula
- **Osint**: Domain yaşı, oluşturma tarihi, güncellenme tarihi gibi metadata topla

## Kurulum

### Gereksinimler
- Go 1.21 veya üstü
- Internet bağlantısı (WHOIS server'larına erişim için)

### From Source

```bash
git clone https://github.com/yourusername/whois-lookup.git
cd whois-lookup

go mod download
go build -o whois-lookup main.go
```

### Binary Kullanımı

```bash
./whois-lookup
```

## Kullanım

### Tek Domain/IP Sorgusu

```bash
./whois-lookup
```

Menu açılacak:
```
┌─────────────────────────────────────┐
│  WHOIS-LOOKUP - Domain/IP Recon     │
├─────────────────────────────────────┤
│ [1] Single Domain/IP Lookup         │
│ [2] Bulk File Lookup                │
│ [3] Exit                            │
└─────────────────────────────────────┘

Seçim yap: 1
Domain/IP gir: github.com
```

### Bulk Lookup

Bir metin dosyasını hazırla (domains.txt):
```
github.com
google.com
192.168.1.1
scanme.nmap.org
```

Sonra:
```
Seçim yap: 2
Dosya yolunu gir: domains.txt
```

Tool tüm hedefleri sorgulayıp sonuçları gösterir.

### Çıktı Kaydetme

Sorgu tamamlandıktan sonra:
```
Sonuçları dosyaya kaydet? (e/h): e
Dosya yolu [whois-github.com-1712345678.txt]: ./results/github-whois.txt
[✓] Kaydedildi: ./results/github-whois.txt
```

## Çıktı Formatı

```
╔════════════════════════════════════════════╗
║          WHOIS LOOKUP SONUÇLARI            ║
╚════════════════════════════════════════════╝

┌─ Domain Bilgileri ─┐
  Domain        : github.com
  Oluşturma      : 2007-10-29
  Güncelleme     : 2024-03-12
  Bitiş Tarihi   : 2025-10-29
  Nameserverlar  : 
                   • ns1.p16.dynect.net
                   • ns2.p16.dynect.net
  Status         : clientDeleteProhibited

┌─ Kayıtçı Bilgileri ─┐
  İsim           : NameCheap, Inc.
  WHOIS Server   : whois.namecheap.com
  URL            : http://www.namecheap.com

┌─ Sahibi Bilgileri ─┐
  İsim           : GitHub, Inc.
  Kuruluş        : GitHub, Inc.
  Ülke           : US
```

## Teknoloji

- **Dil**: Go 1.21+
- **WHOIS**: `github.com/likexian/whois`
- **Parsing**: `github.com/likexian/whois-parser`
- **UI**: `github.com/fatih/color` (terminal renkli çıktı)

## Performans

- **Single Query**: < 2 saniye
- **Bulk (10 domain)**: ~10-15 saniye (rate limiting dahil)
- **Binary Size**: ~5MB (UPX ile sıkıştırılabilir)

## Sınırlamalar

- Bazı WHOIS server'ları rate limiting yapabilir
- Private domain'ler tam bilgi göstermeyebilir
- IPv6 IP'ler bazı registrar'larda detay olmayabilir

## İyileştirme Fikirleri

- [ ] Proxy/VPN support
- [ ] Caching mechanism
- [ ] JSON output format
- [ ] DNS query integration
- [ ] Subdomain enumeration
- [ ] Export formats (CSV, JSON)

## ⚠️ Yasal Uyarı

Bu araç yalnızca **izinli/authorized** sistemlerde ve **eğitim amaçlı** kullanım içindir. 

- WHOIS sorgusu kendisi legal'dir (public bilgi)
- Ancak bulk/otomatik sorgular WHOIS ToS'u ihlal edebilir
- İzinsiz sistem'e erişim girişimi yasa dışıdır

**Sorumlu ve yasa uyumlu kullan.**

## License

MIT

## Credits & Author

**Original Concept**: LatenT (@HargosAktif) — Terminal WHOIS sorgusu için en clean aracı oluşturmak amacıyla.

**Implementation & Development**: 
- **Miraç Akkuş** (@HargosAktif) — Projeyi oluşturan. Pentester olma yolundaki
- 

---

**Katkılar kabul ediyoruz!** Fork → Feature Branch → Pull Request

**Not**: Bu tool, pentest recon'unda işe yaramak için tasarlanmıştır. Clean output, %100 okunabilirlik ve hatasız çalışma — kesinlikle önerilen bir araç.
](https://img.shields.io/badge/Go-1.21%2B-blue.svg)](https://img.shields.io/badge/Go-1.21%2B-blue.svg)
