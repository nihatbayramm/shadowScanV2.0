import re
from shadowscan.config import Config
from shadowscan.logger import Logger
import os
from colorama import Fore

class FileScanner:
    def __init__(self, config: Config, logger: Logger):
        self.config = config
        self.logger = logger

    def scan_file(self, file_path, output_file=None, patterns):
        if not os.path.exists(file_path) or os.path.splitext(file_path)[1] not in self.config.get("extensions"):
            return
        
        findings = []
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
        self.logger.log_findings(findings, output_file, file_path) 