#!/usr/bin/env python3

import argparse
import ipaddress
import json
import re
import socket
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import dns.resolver
import whois


VERSION = "2.0.0"
DEFAULT_TIMEOUT = 10
CACHE_TTL = 600
DEFAULT_WORKERS = 5
MAX_WORKERS = 20

DNS_RECORDS = ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA")


def timestamp():
    return datetime.now(timezone.utc).isoformat()


def normalize_target(value):
    value = value.strip()

    if not value:
        raise ValueError("Target cannot be empty.")

    if "://" in value:
        parsed = urlsplit(value)

        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError("Invalid URL.")

        value = parsed.hostname

    value = value.rstrip(".")

    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass

    if len(value) > 253:
        raise ValueError("Domain name is too long.")

    try:
        value = value.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("Invalid domain name.") from exc

    labels = value.split(".")

    for label in labels:
        if (
            not label
            or len(label) > 63
            or not re.fullmatch(
                r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?",
                label,
            )
        ):
            raise ValueError("Invalid domain name format.")

    if "." not in value:
        raise ValueError("Please provide a fully qualified domain name.")

    return value


class Cache:
    def __init__(self, ttl=CACHE_TTL):
        self.ttl = ttl
        self._data = {}
        self._lock = threading.Lock()

    def get(self, key):
        with self._lock:
            item = self._data.get(key)

            if item is None:
                return None

            expires, value = item

            if time.monotonic() >= expires:
                del self._data[key]
                return None

            return value

    def set(self, key, value):
        with self._lock:
            self._data[key] = (
                time.monotonic() + self.ttl,
                value,
            )

    def clear(self):
        with self._lock:
            self._data.clear()


class WhoisService:
    def __init__(self, cache, timeout=DEFAULT_TIMEOUT):
        self.cache = cache
        self.timeout = timeout

    def lookup(self, target):
        original = target.strip()

        try:
            target = normalize_target(original)
        except ValueError as exc:
            return {
                "target": original,
                "success": False,
                "error": str(exc),
            }

        key = f"whois:{target}"
        cached = self.cache.get(key)

        if cached is not None:
            return {**cached, "cached": True}

        try:
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(whois.whois, target)

                try:
                    data = future.result(timeout=self.timeout)
                except TimeoutError:
                    future.cancel()
                    return {
                        "target": target,
                        "success": False,
                        "error": f"WHOIS query timed out after {self.timeout} seconds.",
                    }

            result = {
                "target": target,
                "success": True,
                "cached": False,
                "data": str(data),
                "queried_at": timestamp(),
            }

            self.cache.set(key, result)
            return result

        except Exception as exc:
            return {
                "target": target,
                "success": False,
                "cached": False,
                "error": f"{type(exc).__name__}: {exc}",
            }


def resolve_dns(domain, timeout=DEFAULT_TIMEOUT):
    original = domain.strip()

    try:
        domain = normalize_target(original)

        try:
            ipaddress.ip_address(domain)
        except ValueError:
            pass
        else:
            raise ValueError("DNS queries require a domain name.")

    except ValueError as exc:
        return {
            "target": original,
            "success": False,
            "error": str(exc),
        }

    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    result = {
        "target": domain,
        "success": True,
        "records": {},
        "errors": {},
        "queried_at": timestamp(),
    }

    for record_type in DNS_RECORDS:
        try:
            answers = resolver.resolve(domain, record_type)

            if record_type == "MX":
                values = [
                    {
                        "priority": answer.preference,
                        "exchange": str(answer.exchange).rstrip("."),
                    }
                    for answer in answers
                ]

            elif record_type == "NS":
                values = [
                    str(answer.target).rstrip(".")
                    for answer in answers
                ]

            elif record_type == "SOA":
                values = [
                    {
                        "mname": str(answer.mname).rstrip("."),
                        "rname": str(answer.rname).rstrip("."),
                        "serial": answer.serial,
                        "refresh": answer.refresh,
                        "retry": answer.retry,
                        "expire": answer.expire,
                        "minimum": answer.minimum,
                    }
                    for answer in answers
                ]

            elif record_type == "TXT":
                values = [
                    [
                        part.decode("utf-8", errors="replace")
                        for part in answer.strings
                    ]
                    for answer in answers
                ]

            elif record_type == "CNAME":
                values = [
                    str(answer.target).rstrip(".")
                    for answer in answers
                ]

            else:
                values = [str(answer) for answer in answers]

            result["records"][record_type] = values

        except dns.resolver.NoAnswer:
            result["records"][record_type] = []

        except dns.resolver.NXDOMAIN:
            result["success"] = False
            result["errors"][record_type] = "Domain does not exist."
            break

        except Exception as exc:
            result["records"][record_type] = []
            result["errors"][record_type] = (
                f"{type(exc).__name__}: {exc}"
            )

    return result


def reverse_dns(address, timeout=DEFAULT_TIMEOUT):
    try:
        ip = ipaddress.ip_address(address.strip())
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout

        reverse_name = ip.reverse_pointer
        answers = resolver.resolve(reverse_name, "PTR")

        return {
            "target": str(ip),
            "success": True,
            "ptr": [str(answer.target).rstrip(".") for answer in answers],
            "queried_at": timestamp(),
        }

    except Exception as exc:
        return {
            "target": address,
            "success": False,
            "error": f"{type(exc).__name__}: {exc}",
        }


def read_targets(filename):
    with Path(filename).expanduser().open(
        "r",
        encoding="utf-8-sig",
    ) as file:
        targets = [
            line.strip()
            for line in file
            if line.strip() and not line.lstrip().startswith("#")
        ]

    return list(dict.fromkeys(targets))


def export_json(data, filename):
    path = Path(filename).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")

    try:
        with temporary.open("w", encoding="utf-8") as file:
            json.dump(data, file, indent=2, ensure_ascii=False)
            file.write("\n")

        temporary.replace(path)

    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def print_result(result):
    print(json.dumps(result, indent=2, ensure_ascii=False))


def run_bulk(targets, service, workers=DEFAULT_WORKERS):
    targets = list(dict.fromkeys(targets))

    if not targets:
        print("No targets found.")
        return []

    workers = max(1, min(workers, MAX_WORKERS, len(targets)))
    results = []

    print(f"Processing {len(targets)} targets with {workers} workers.")

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(service.lookup, target): target
            for target in targets
        }

        for completed, future in enumerate(as_completed(futures), 1):
            try:
                result = future.result()
            except Exception as exc:
                result = {
                    "target": futures[future],
                    "success": False,
                    "error": f"{type(exc).__name__}: {exc}",
                }

            results.append(result)

            status = "OK" if result["success"] else "ERROR"
            print(
                f"[{completed}/{len(targets)}] "
                f"[{status}] {result['target']}"
            )

    return results


def interactive(timeout, workers):
    cache = Cache()
    service = WhoisService(cache, timeout)

    while True:
        print(
            f"\nOSINT CLI v{VERSION}\n"
            "1) WHOIS lookup\n"
            "2) Bulk WHOIS lookup\n"
            "3) DNS lookup\n"
            "4) Reverse DNS lookup\n"
            "5) Clear cache\n"
            "6) Exit"
        )

        try:
            choice = input("Select an option: ").strip()

            if choice == "1":
                print_result(service.lookup(input("Domain/IP: ")))

            elif choice == "2":
                filename = input("Target file: ").strip()

                try:
                    targets = read_targets(filename)
                    results = run_bulk(targets, service, workers)

                    if results and input(
                        "Export results to JSON? [y/N]: "
                    ).strip().lower() == "y":
                        output = input("Output file: ").strip()
                        export_json(results, output)
                        print(f"Results saved to {output}")

                except OSError as exc:
                    print(f"File error: {exc}")

            elif choice == "3":
                result = resolve_dns(input("Domain: "), timeout)
                print_result(result)

                if input(
                    "Export results to JSON? [y/N]: "
                ).strip().lower() == "y":
                    output = input("Output file: ").strip()
                    export_json(result, output)
                    print(f"Results saved to {output}")

            elif choice == "4":
                print_result(reverse_dns(input("IP address: "), timeout))

            elif choice == "5":
                cache.clear()
                print("Cache cleared.")

            elif choice == "6":
                print("Exiting.")
                break

            else:
                print("Invalid option.")

        except (KeyboardInterrupt, EOFError):
            print("\nExiting.")
            break

        except (OSError, ValueError) as exc:
            print(f"Error: {exc}")


def main():
    parser = argparse.ArgumentParser(
        description="WHOIS and DNS reconnaissance utility."
    )

    parser.add_argument("--version", action="version", version=VERSION)
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS)
    parser.add_argument("--whois", metavar="TARGET")
    parser.add_argument("--dns", metavar="DOMAIN")
    parser.add_argument("--ptr", metavar="IP_ADDRESS")
    parser.add_argument("--file", metavar="PATH")
    parser.add_argument("--output", metavar="JSON_PATH")

    args = parser.parse_args()

    if not 1 <= args.timeout <= 120:
        parser.error("--timeout must be between 1 and 120.")

    if not 1 <= args.workers <= MAX_WORKERS:
        parser.error(f"--workers must be between 1 and {MAX_WORKERS}.")

    selected = sum(
        bool(value)
        for value in (args.whois, args.dns, args.ptr, args.file)
    )

    if selected > 1:
        parser.error("Choose only one operation at a time.")

    service = WhoisService(Cache(), args.timeout)

    try:
        if args.whois:
            result = service.lookup(args.whois)

        elif args.dns:
            result = resolve_dns(args.dns, args.timeout)

        elif args.ptr:
            result = reverse_dns(args.ptr, args.timeout)

        elif args.file:
            result = run_bulk(
                read_targets(args.file),
                service,
                args.workers,
            )

        else:
            interactive(args.timeout, args.workers)
            return 0

        if args.output:
            export_json(result, args.output)
            print(f"Results saved to {args.output}")
        else:
            print_result(result)

        if isinstance(result, list):
            return 0 if all(item["success"] for item in result) else 1

        return 0 if result["success"] else 1

    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
