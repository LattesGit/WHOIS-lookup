#!/usr/bin/env python3
# KOD LATENT TARAFINDAN YAPILDI İLLEGAL ŞEYLER İÇİN KULLANILIRSA KULLANAN KİŞİ SORUMLUDUR
# LATENT BU KONUDA SORUMLU TUTULMAZ
# KOD:

import asyncio
import json
import os
import sys
import time
import threading
import whois
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from typing import Dict, Optional, List
import dns.resolver
import dns.reversename
from pathlib import Path

# ================= CONFIG =================
DEFAULT_TIMEOUT = 10
CACHE_TTL = 10 * 60  # 10 minutes
CACHE_CLEANUP = 60   # 1 minute
WORKER_COUNT = 5

# ================= CACHE =================
class CacheItem:
    def __init__(self, data: str, expires_at: float):
        self.data = data
        self.expires_at = expires_at

class Cache:
    def __init__(self):
        self._data: Dict[str, CacheItem] = {}
        self._lock = threading.RLock()
        self._cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self._cleanup_thread.start()

    def get(self, key: str) -> Optional[str]:
        with self._lock:
            item = self._data.get(key)
            if not item or time.time() > item.expires_at:
                return None
            return item.data

    def set(self, key: str, value: str):
        with self._lock:
            self._data[key] = CacheItem(value, time.time() + CACHE_TTL)

    def _cleanup_loop(self):
        while True:
            time.sleep(CACHE_CLEANUP)
            with self._lock:
                expired_keys = [
                    k for k, v in self._data.items()
                    if time.time() > v.expires_at
                ]
                for key in expired_keys:
                    del self._data[key]

# ================= WHOIS =================
class WhoisService:
    def __init__(self, cache: Cache):
        self.cache = cache

    def lookup(self, target: str, timeout: int = DEFAULT_TIMEOUT) -> tuple[str, Exception]:
        if not target:
            return "", Exception("Boş target")

        cached = self.cache.get(target)
        if cached:
            return cached, None

        try:
            # Timeout ile whois sorgusu
            w = whois.whois(target)
            result = str(w)
            self.cache.set(target, result)
            return result, None
        except Exception as e:
            return "", e

# ================= WORKER POOL =================
def worker(worker_id: int, jobs: List[str], svc: WhoisService):
    for target in jobs:
        print(f"[Worker {worker_id}] Sorgu: {target}")
        result, error = svc.lookup(target)
        if error:
            print(f"[Worker {worker_id}] Hata: {error}")
            continue
        print_preview(result)

def run_bulk(targets: List[str], svc: WhoisService):
    chunk_size = len(targets) // WORKER_COUNT + 1
    chunks = [targets[i:i + chunk_size] for i in range(0, len(targets), chunk_size)]
    
    with ThreadPoolExecutor(max_workers=WORKER_COUNT) as executor:
        futures = [
            executor.submit(worker, i, chunk, svc)
            for i, chunk in enumerate(chunks)
        ]
        for future in futures:
            future.result()

# ================= DNS =================
class DNSResult:
    def __init__(self):
        self.ips = []
        self.mx = []
        self.ns = []

def resolve_dns(domain: str) -> tuple[DNSResult, Exception]:
    if not domain:
        return None, Exception("Boş domain")
    
    result = DNSResult()
    
    try:
        # A Records (IPs)
        resolver = dns.resolver.Resolver()
        resolver.timeout = DEFAULT_TIMEOUT
        resolver.lifetime = DEFAULT_TIMEOUT
        
        # IPs
        try:
            answers = resolver.resolve(domain, 'A')
            result.ips.extend([str(rdata) for rdata in answers])
        except:
            pass
        
        try:
            answers = resolver.resolve(domain, 'AAAA')
            result.ips.extend([str(rdata) for rdata in answers])
        except:
            pass
        
        # MX Records
        try:
            answers = resolver.resolve(domain, 'MX')
            result.mx.extend([str(rdata.exchange).rstrip('.') for rdata in answers])
        except:
            pass
        
        # NS Records
        try:
            answers = resolver.resolve(domain, 'NS')
            result.ns.extend([str(rdata.target).rstrip('.') for rdata in answers])
        except:
            pass
            
    except Exception as e:
        return None, e
    
    return result, None

# ================= UTIL =================
def read_file(path: str) -> tuple[List[str], Exception]:
    try:
        with open(path, 'r', encoding='utf-8') as f:
            targets = [line.strip() for line in f if line.strip()]
        return targets, None
    except Exception as e:
        return [], e

def export_json(data, filename: str) -> bool:
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return True
    except:
        return False

def print_preview(data: str):
    if len(data) > 120:
        print(data[:120] + "...")
    else:
        print(data)

# ================= MAIN =================
def main():
    cache = Cache()
    svc = WhoisService(cache)
    
    while True:
        print("\n1) Tek sorgu")
        print("2) Toplu sorgu")
        print("3) DNS sorgu")
        print("4) Çıkış")
        
        choice = input("Seçim: ").strip()
        
        if choice == "1":
            target = input("Domain/IP: ").strip()
            result, error = svc.lookup(target)
            
            if error:
                print(f"Hata: {error}")
            else:
                print(result)
                
        elif choice == "2":
            path = input("Dosya yolu: ").strip()
            targets, error = read_file(path)
            
            if error:
                print(f"Dosya hatası: {error}")
                continue
            
            print(f"{len(targets)} hedef bulundu. İşleniyor...")
            run_bulk(targets, svc)
            
        elif choice == "3":
            domain = input("Domain: ").strip()
            result, error = resolve_dns(domain)
            
            if error:
                print(f"Hata: {error}")
                continue
            
            print(json.dumps(result.__dict__, indent=2, ensure_ascii=False))
            
        elif choice == "4":
            print("Çıkış yapılıyor...")
            break
        else:
            print("Geçersiz seçim!")

if __name__ == "__main__":
    # Gerekli kütüphaneleri kontrol et
    try:
        import whois
        import dnspython3 as dns
    except ImportError:
        print("Gerekli kütüphaneler yüklenmedi!")
        print("Kurulum: pip install python-whois dnspython")
        sys.exit(1)
    
    main()
