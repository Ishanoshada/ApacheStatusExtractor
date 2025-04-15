# Apache server-status URL monitor and URL extractor
# Author: Ishan Oshada (github.com/ishanoshada)
# Version: 1.0.5

import time
import argparse
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from colorama import init, Fore, Style
import re
import os

init(autoreset=True)

# Argument parser setup
parser = argparse.ArgumentParser(
    description=f"{Fore.CYAN}Apache Status URL Monitor by Ishan Oshada{Style.RESET_ALL}",
    epilog="Examples:\n"
           "  python tol.py -u http://example.com/server-status -o urls.txt\n"
           "  python tol.py --input domains.txt -o urls.txt --debug",
    formatter_class=argparse.RawDescriptionHelpFormatter
)
parser.add_argument("--input", help="File with URLs to check (e.g., vulnerable_domains.txt)")
parser.add_argument("-u", "--url", help="Single Apache server-status URL (overrides --input)")
parser.add_argument("--sleep", type=int, default=10, help="Delay between requests for monitoring (default: 10)")
parser.add_argument("-o", "--output", help="Save extracted URLs to a file")
parser.add_argument("--debug", action="store_true", help="Enable debug messages")

def print_banner():
    print(f"""{Fore.MAGENTA}
    ┌──────────────────────────────────────────────────┐
    │   Apache Server-Status URL Extractor 🕵️‍♂️        │
    │   Author: Ishan Oshada (github.com/ishanoshada)  │
    │   Version: 1.0.5                                   │
    └──────────────────────────────────────────────────┘
    {Style.RESET_ALL}""")

def clean_url(url):
    """Ensure URL has a scheme and append /server-status if needed."""
    parsed = urlparse(url)
    if not parsed.scheme:
        url = f"http://{url}"
        parsed = urlparse(url)
    if not parsed.path.endswith("/server-status"):
        url = f"{parsed.scheme}://{parsed.netloc}/server-status"
    return url

def debug(msg, debug_enabled):
    """Print debug message if debug mode is enabled."""
    if debug_enabled:
        print(f"{Fore.LIGHTBLACK_EX}[DEBUG]{Style.RESET_ALL} {msg}")

class Requester:
    def __init__(self):
        self.headers = {
            "User-Agent": "ApacheStatusMonitor/1.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Connection": "keep-alive"
        }

    def fetch(self, url, debug_enabled):
        """Fetch URL, trying HTTP and HTTPS, with retries."""
        schemes = ["http", "https"] if not urlparse(url).scheme else [urlparse(url).scheme]
        max_retries = 3
        for attempt in range(max_retries):
            for scheme in schemes:
                target_url = url if urlparse(url).scheme else f"{scheme}://{urlparse(url).netloc}{urlparse(url).path}"
                try:
                    response = requests.get(
                        target_url,
                        headers=self.headers,
                        timeout=10,
                        verify=True,
                        allow_redirects=True
                    )
                    debug(f"Fetched {target_url}: Status {response.status_code}", debug_enabled)
                    return response.text, response.status_code
                except requests.exceptions.SSLError as e:
                    debug(f"SSL error for {target_url}: {str(e)}", debug_enabled)
                    try:
                        response = requests.get(
                            target_url,
                            headers=self.headers,
                            timeout=10,
                            verify=False,
                            allow_redirects=True
                        )
                        debug(f"Fetched {target_url} (no verify): Status {response.status_code}", debug_enabled)
                        return response.text, response.status_code
                    except Exception as e:
                        debug(f"Failed {target_url} (no verify): {str(e)}", debug_enabled)
                except Exception as e:
                    debug(f"Failed {target_url}: {str(e)}", debug_enabled)
            if attempt < max_retries - 1:
                debug(f"Retrying {url} (attempt {attempt + 2}/{max_retries})", debug_enabled)
                time.sleep(1)
        return '', None

class Parser:
    def is_valid(self, html):
        """Check if HTML is a valid Apache server-status page."""
        if not html:
            return False
        soup = BeautifulSoup(html, "lxml")
        indicators = [
            soup.title and "Apache Status" in soup.title.string,
            any("Apache Server Status" in h1.text for h1 in soup.find_all("h1")),
            "<h1>Apache Server Status for" in html,
            "<th>Srv</th><th>PID</th>" in html
        ]
        return any(indicators)

    def extract_urls(self, html, debug_enabled):
        """Extract PID, VHost, Request, and Method to form URLs."""
        urls = []
        try:
            soup = BeautifulSoup(html, "lxml")
            tables = soup.find_all("table")
            if not tables:
                debug("No tables found in HTML", debug_enabled)
                return urls
            rows = tables[0].find_all("tr")[1:]  # Skip header
            for row in rows:
                cols = row.find_all("td")
                if len(cols) < 15:
                    debug(f"Row too short, has {len(cols)} columns", debug_enabled)
                    continue
                try:
                    pid = cols[1].get_text().strip()
                    vhost = cols[13].get_text().strip()
                    request_full = cols[14].get_text().strip()
                    match = re.match(r"(\w+)\s+([^\s]+)(?:\s+HTTP/\d\.\d)?", request_full)
                    if not match:
                        debug(f"Invalid request format: {request_full}", debug_enabled)
                        continue
                    method, request_uri = match.groups()
                    if vhost and request_uri:
                        full_url = f"http://{vhost}{request_uri}"
                        urls.append({
                            "pid": pid,
                            "method": method,
                            "url": full_url
                        })
                    else:
                        debug(f"Empty vhost or URI: {vhost}, {request_uri}", debug_enabled)
                except Exception as e:
                    debug(f"Error parsing row: {str(e)}", debug_enabled)
        except Exception as e:
            debug(f"Error parsing HTML: {str(e)}", debug_enabled)
        return urls

def save_line(text, output_file):
    """Save text to output file."""
    if output_file:
        try:
            with open(output_file, 'a') as f:
                f.write(text + '\n')
        except Exception as e:
            print(f"{Fore.RED}[!] Failed to write to file: {str(e)}{Style.RESET_ALL}")
            debug(f"Write error: {str(e)}", True)  # Always debug file errors

def process_url(url, requester, parser_obj, seen_urls, debug_enabled, output_file):
    """Check a single URL for vulnerability and extract data."""
    url = clean_url(url)
    print(f"{Fore.CYAN}[*] Checking: {url}{Style.RESET_ALL}")
    html, status_code = requester.fetch(url, debug_enabled)
    if not parser_obj.is_valid(html):
        print(f"{Fore.RED}[!] NOT VULNERABLE (Status: {status_code or 'None'}).{Style.RESET_ALL}")
        debug(f"Response snippet: {html[:200]}...", debug_enabled)
        return False
    entries = parser_obj.extract_urls(html, debug_enabled)
    if not entries:
        print(f"{Fore.YELLOW}[*] VULNERABLE but no URLs found.{Style.RESET_ALL}")
    for entry in entries:
        url = entry["url"]
        if url not in seen_urls:
            seen_urls.add(url)
            print(f"{Fore.YELLOW}[+] PID: {entry['pid']}, Method: {entry['method']}, URL: {Fore.GREEN}{url}{Style.RESET_ALL}")
            save_line(url, output_file)
    if entries:
        print(f"{Fore.GREEN}[*] VULNERABLE: Found {len(entries)} entries.{Style.RESET_ALL}")
    return True

def main():
    print_banner()

    try:
        args = parser.parse_args()
    except Exception as e:
        print(f"{Fore.RED}[!] Argument parsing error: {str(e)}{Style.RESET_ALL}")
        parser.print_help()
        return

    # Check if no URL or input file is provided
    if not args.url and not args.input:
        parser.print_help()
        return

    requester = Requester()
    parser_obj = Parser()
    seen_urls = set()

    # Determine URLs to process
    urls = []
    if args.url:
        urls = [args.url]
        print(f"{Fore.CYAN}[*] Processing single URL: {args.url}{Style.RESET_ALL}")
    else:
        input_file = args.input
        if not os.path.isfile(input_file):
            print(f"{Fore.RED}[!] Input file {input_file} not found.{Style.RESET_ALL}")
            return
        try:
            with open(input_file, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
            print(f"{Fore.CYAN}[*] Loaded {len(urls)} URLs from {input_file}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error reading {input_file}: {str(e)}{Style.RESET_ALL}")
            return

    if not urls:
        print(f"{Fore.RED}[!] No URLs to process.{Style.RESET_ALL}")
        return

    # Process each URL
    vulnerable_count = 0
    for i, url in enumerate(urls, 1):
        print(f"{Fore.CYAN}[*] Processing URL {i}/{len(urls)}{Style.RESET_ALL}")
        if process_url(url, requester, parser_obj, seen_urls, args.debug, args.output):
            vulnerable_count += 1
        # Sleep only if monitoring a single URL
        if args.url:
            for j in range(args.sleep, 0, -1):
                print(f"{Fore.CYAN}↻ Refresh in {j}s...{Style.RESET_ALL}\r", end="", flush=True)
                time.sleep(1)
            print(" " * 50 + "\r", end="", flush=True)
        elif i < len(urls):
            time.sleep(1)  # Brief delay between bulk URLs

    print(f"\n{Fore.CYAN}[*] Checked {len(urls)} URLs. Vulnerable: {vulnerable_count}, Not Vulnerable: {len(urls) - vulnerable_count}{Style.RESET_ALL}")
    if seen_urls:
        print(f"{Fore.CYAN}[*] Total unique URLs extracted: {len(seen_urls)}{Style.RESET_ALL}")
        if args.output:
            print(f"{Fore.CYAN}[*] Saved to {args.output}{Style.RESET_ALL}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.LIGHTRED_EX}[✘] Interrupted by user. Exiting...{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}[!] Unexpected error: {str(e)}{Style.RESET_ALL}")
        # Debug output only if explicitly enabled is handled within functions