# ApacheStatusExtractor

**Apache Server-Status URL Extractor** is a Python tool designed to monitor Apache `server-status` pages, extract key information, and identify vulnerabilities. It extracts `PID`, `Method`, `VHost`, and `Request` from status pages, constructs URLs, and supports bulk URL checking from files (e.g., `vulnerable_domains.txt`). Ideal for security researchers and system administrators analyzing Apache web servers.


## Features
- Monitors Apache `server-status` pages for real-time data.
- Extracts:
  - `PID`: Process ID of the server worker.
  - `Method`: HTTP method (e.g., `GET`, `POST`).
  - `VHost`: Virtual host name.
  - `Request`: Request URI, used to build URLs (e.g., `http://{vhost}{request}`).
- Supports bulk URL checking from a file to identify vulnerable servers.
- Saves extracted URLs to an output file.
- Colorized console output with debug mode for troubleshooting.
- Robust error handling for invalid pages, network issues, and interrupts.

## Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/ishanoshada/ApacheStatusExtractor.git
   cd ApacheStatusExtractor
   ```

2. **Install Dependencies**:
   Requires Python 3.6+. Install required packages:
   ```bash
   pip install -r requirements.txt
   ```
   or
   ```bash
   pip install requests beautifulsoup4 colorama 
   ```

3. **Verify Setup**:
   Ensure `tool.py` is executable:
   ```bash
   chmod +x tool.py
   ```

## Usage

Run the tool with a single URL or a file containing URLs (e.g., `vulnerable_domains.txt`).

### Command-Line Options
- `--input <file>`: File with URLs to check (default: `vulnerable_domains.txt`).
- `-u/--url <url>`: Single Apache server-status URL (overrides `--input`).
- `--sleep <seconds>`: Delay between requests in single-URL mode (default: 10).
- `-o/--output <file>`: Save extracted URLs to a file.
- `--debug`: Enable debug messages for detailed logs.

### Examples

1. **Check a Single URL**:
   Monitor a single `server-status` page and save URLs to `urls.txt`:
   ```bash
   python tool.py -u http://example.com/server-status -o urls.txt
   ```

   Output:
   ```
   [+] PID: 1234, Method: GET, URL: http://example.com/index.php
   [+] PID: 1235, Method: POST, URL: http://example.com/login
   [*] VULNERABLE: Found 2 entries.
   ```

2. **Bulk Check from File**:
   Check multiple URLs from `vulnerable_domains.txt`:
   ```bash
   python tool.py --input vulnerable_domains.txt -o urls.txt
   ```

   Sample `vulnerable_domains.txt`:
   ```
   example.com
   test.org
   advancead.ca
   ```

   Output:
   ```
   [*] Loaded 3 URLs from vulnerable_domains.txt
   [*] Checking: http://example.com/server-status
   [+] PID: 1234, Method: GET, URL: http://example.com/index.php
   [*] VULNERABLE: Found 1 entry.
   [*] Checking: http://test.org/server-status
   [!] NOT VULNERABLE (Status: 404).
   [*] Checking: http://advancead.ca/server-status
   [!] NOT VULNERABLE (Status: 404).
   [*] Checked 3 URLs. Vulnerable: 1, Not Vulnerable: 2
   ```

3. **Debug Mode**:
   Enable debug output for troubleshooting:
   ```bash
   python tool.py -u advancead.ca --debug
   ```

   Output:
   ```
   [DEBUG] Fetched http://advancead.ca/server-status: Status 404
   [DEBUG] Response snippet: <!DOCTYPE html><head><title>404 Not Found...
   [!] NOT VULNERABLE (Status: 404).
   ```

## Notes
- **Input URLs**: Provide domains (e.g., `example.com`) or full URLs. The tool appends `/server-status` automatically.
- **Vulnerability**: A URL is considered vulnerable if it exposes a valid Apache `server-status` page (e.g., contains `<title>Apache Status</title>`).
- **Performance**: Bulk mode processes URLs sequentially with a 1-second delay to avoid rate-limiting. Single-URL mode loops with `--sleep` delay.
- **Dependencies**: Ensure `requests`, `beautifulsoup4`, and `colorama` are installed.

## Contributing
Contributions are welcome! Please:
1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/YourFeature`).
3. Commit changes (`git commit -m 'Add YourFeature'`).
4. Push to the branch (`git push origin feature/YourFeature`).
5. Open a pull request.

Report issues or suggestions on the [GitHub Issues page](https://github.com/ishanoshada/ApacheStatusExtractor/issues).


**Repository Views** ![Views](https://profile-counter.glitch.me/apache-status/count.svg)

## Acknowledgments
- Built with Python, leveraging `requests`, `BeautifulSoup`, and `colorama`.
---


