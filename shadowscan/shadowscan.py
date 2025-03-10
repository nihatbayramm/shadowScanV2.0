import re
import requests
import sys
import os
import argparse
import threading
import queue
import time
from colorama import Fore, Style, init
from datetime import datetime
from tqdm import tqdm 
import json

init()

PATTERNS = {
    "API Key": r"(?i)(api[-_]?key|access[-_]?token)[:=]\s*['\"]?([A-Za-z0-9-_]{20,})['\"]?",
    "Email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    "Password": r"(?i)(password|pass|pwd|secret)[-_]?[:=]\s*['\"]?([A-Za-z0-9!@#$%^&*()_+=-]{8,})['\"]?",
    "SSH Key": r"-----BEGIN (RSA|OPENSSH|EC|DSA|PRIVATE) KEY-----[\s\S]+?-----END (RSA|OPENSSH|EC|DSA|PRIVATE) KEY-----",
    "JWT Token": r"eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+",
    "IP Address": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
}

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Content-Security-Policy"
]

CONFIG = {
    "threads": 4,  
    "timeout": 5,  
    "extensions": [".txt", ".env", ".yaml", ".json", ".conf"]  
}

def load_config(config_file="config.json"):
    """Yapılandırma dosyasını yükler."""
    global CONFIG
    if os.path.exists(config_file):
        with open(config_file, "r") as f:
            CONFIG.update(json.load(f))

def log_findings(findings, output_file, context):
    """Bulunan sonuçları kaydeder."""
    if findings and output_file:
        with open(output_file, "a") as out:
            out.write(f"\n[{datetime.now()}] {context}:\n")
            out.write("\n".join(findings) + "\n")

def scan_file(file_path, output_file=None, patterns=PATTERNS):
    """Dosyada hassas bilgileri tarar."""
    if not os.path.exists(file_path) or os.path.splitext(file_path)[1] not in CONFIG["extensions"]:
        return
    
    findings = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line_no, line in enumerate(f, 1):
                for name, pattern in patterns.items():
                    matches = re.findall(pattern, line)
                    for match in matches:
                        findings.append(f"{Fore.RED}[!] {name} (satır {line_no}): {match}{Fore.RESET}")
        
        if findings:
            print(f"{Fore.CYAN}Tarama Sonuçları ({file_path}):{Fore.RESET}")
            for finding in findings:
                print(finding)
        log_findings(findings, output_file, file_path)
    except Exception as e:
        print(f"{Fore.YELLOW}[!] Dosya hatası ({file_path}): {e}{Fore.RESET}")

def scan_url(url, output_file=None):
    """URL'deki güvenlik açıklarını tarar."""
    try:
        response = requests.get(url, timeout=CONFIG["timeout"], headers={"User-Agent": "ShadowScan"})
        headers = response.headers
        content = response.text[:10000]  
        findings = []

        for header in SECURITY_HEADERS:
            if header not in headers:
                findings.append(f"{Fore.RED}[!] {header} eksik{Fore.RESET}")

        for name, pattern in PATTERNS.items():
            matches = re.findall(pattern, content)
            if matches:
                findings.append(f"{Fore.RED}[!] {name} bulundu: {matches}{Fore.RESET}")

        print(f"{Fore.CYAN}Tarama Sonuçları ({url}):{Fore.RESET}")
        if findings:
            for finding in findings:
                print(finding)
        else:
            print(f"{Fore.GREEN}[+] Temel güvenlik başlıkları mevcut{Fore.RESET}")
        print(f"{Fore.GREEN}Başlıklar:{Fore.RESET} {headers}")

        log_findings(findings, output_file, url)
    except requests.RequestException as e:
        print(f"{Fore.YELLOW}[!] URL tarama hatası: {e}{Fore.RESET}")

def scan_directory(directory, output_file=None):
    """Bir dizindeki tüm dosyaları çoklu iş parçacığı ile tarar."""
    file_queue = queue.Queue()
    for root, _, files in os.walk(directory):
        for file in files:
            if os.path.splitext(file)[1] in CONFIG["extensions"]:
                file_queue.put(os.path.join(root, file))

    def worker():
        while not file_queue.empty():
            try:
                file_path = file_queue.get()
                scan_file(file_path, output_file)
                file_queue.task_done()
            except Exception as e:
                print(f"{Fore.YELLOW}[!] İş parçacığı hatası: {e}{Fore.RESET}")

    threads = []
    for _ in range(min(CONFIG["threads"], file_queue.qsize())):
        t = threading.Thread(target=worker)
        t.start()
        threads.append(t)

    with tqdm(total=file_queue.qsize(), desc="Dizin taranıyor", unit="dosya") as pbar:
        while not file_queue.empty():
            time.sleep(0.1)
            pbar.update(file_queue.qsize() - pbar.n)
        pbar.update(file_queue.qsize() - pbar.n)

    for t in threads:
        t.join()

def print_banner():
    """Araç için bir banner gösterir."""
    banner = f"""
    {Fore.CYAN}=== ShadowScan v2.1 ===
    {Fore.GREEN}Gizli bilgi ve güvenlik açığı tarayıcı
    {Fore.YELLOW}Kullanım: python shadowscan.py [seçenekler]
    {Fore.RESET}"""
    print(banner)

def main():
    parser = argparse.ArgumentParser(description="ShadowScan - Hassas bilgi ve güvenlik tarayıcı")
    parser.add_argument("-f", "--file", help="Taranacak dosya yolu")
    parser.add_argument("-u", "--url", help="Taranacak URL")
    parser.add_argument("-d", "--directory", help="Taranacak dizin yolu")
    parser.add_argument("-o", "--output", help="Sonuçları kaydedecek dosya")
    parser.add_argument("-t", "--threads", type=int, default=CONFIG["threads"], help="Kullanılacak iş parçacığı sayısı")
    parser.add_argument("-c", "--config", default="config.json", help="Yapılandırma dosyası")
    args = parser.parse_args()

    load_config(args.config)
    CONFIG["threads"] = args.threads

    print_banner()

    if not any([args.file, args.url, args.directory]):
        parser.print_help()
        sys.exit(1)

    start_time = time.time()
    if args.file:
        print(f"{Fore.CYAN}Dosya tarama başlatılıyor...{Fore.RESET}")
        scan_file(args.file, args.output)
    if args.url:
        print(f"{Fore.CYAN}URL tarama başlatılıyor...{Fore.RESET}")
        scan_url(args.url, args.output)
    if args.directory:
        print(f"{Fore.CYAN}Dizin tarama başlatılıyor...{Fore.RESET}")
        scan_directory(args.directory, args.output)
    
    print(f"{Fore.GREEN}Tarama tamamlandı. Süre: {time.time() - start_time:.2f} saniye{Fore.RESET}")

if __name__ == "__main__":
    main()
