# MailGuard🔒



A comprehensive, high-performance email security vulnerability scanner that checks **MX**, **SPF**, **DKIM**, and **DMARC** records for misconfigurations and security issues.

## Features

- **MX Record Analysis**: Detects dangling MX records that could lead to email takeover
- **SPF Record Scanning**: Identifies weak SPF policies and dangling includes  
- **DKIM Validation**: Checks for missing or weak DKIM keys
- **DMARC Assessment**: Evaluates DMARC policy strength and reporting configuration
- **High Performance**: Async/concurrent scanning with configurable thread pools
- **Multiple DNS Sources**: Uses multiple DNS resolvers + DNS-over-HTTPS for accuracy
- **Progress Tracking**: Optional progress bars for large domain lists
- **Comprehensive Reporting**: Detailed vulnerability analysis with actionable insights

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/mak545/MailGuard.git
cd MailGuard

# Install dependencies
pip install -r requirements.txt

# Make executable (optional)
chmod +x emailsec_scanner.py
```

### Basic Usage

```bash
usage: mailguard.py [-h] [--mx] [--spf] [--dkim] [--dmarc] [--smtp] [--full] [--threads THREADS] [--timeout TIMEOUT]
                    [--dkim-selectors DKIM_SELECTORS] [--smtp-usernames SMTP_USERNAMES] [--no-open-relay-test]
                    [--no-cache] [--cache-ttl CACHE_TTL] [--cache-size CACHE_SIZE] [--cache-stats] [--verbose]
                    [--progress] [--json JSON] [--csv CSV] [--stdout-json] [--version]
                    domains

Professional Email Security Scanner with DNS Caching (MX, SPF, DKIM, DMARC, SMTP)

positional arguments:
  domains               Domain(s) to scan: single domain, comma-separated list, or file path

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit

Scan Types:
  --mx                  Scan MX records for dangling entries
  --spf                 Scan SPF records for misconfigurations
  --dkim                Scan DKIM records for weak keys
  --dmarc               Scan DMARC records for policy issues
  --smtp                Scan SMTP servers for vulnerabilities
  --full                Enable all security scans (MX + SPF + DKIM + DMARC + SMTP)

Configuration:
  --threads THREADS, --concurrency THREADS
                        Number of concurrent scans (default: 50)
  --timeout TIMEOUT     Timeout for DNS queries in seconds (default: 10)
  --dkim-selectors DKIM_SELECTORS
                        Comma-separated list of DKIM selectors to check (default: common selectors)
  --smtp-usernames SMTP_USERNAMES
                        Comma-separated list of usernames to test with VRFY command
  --no-open-relay-test  Disable open relay testing (enabled by default when SMTP scanning)

DNS Caching Options:
  --no-cache            Disable DNS response caching
  --cache-ttl CACHE_TTL
                        DNS cache TTL in seconds (default: 300)
  --cache-size CACHE_SIZE
                        Maximum DNS cache entries (default: 10000)
  --cache-stats         Show DNS cache performance statistics

Output Options:
  --verbose, -v         Enable verbose output
  --progress            Show progress bar during scanning
  --json JSON           Save results to JSON file
  --csv CSV             Save results to CSV file
  --stdout-json         Print raw JSON output to stdout (for CI/CD)

Examples:
  python mailguard.py example.com --full
  python mailguard.py "example.com,test.com" --spf --dmarc --smtp --cache-stats
  python mailguard.py domains.txt --mx --progress --no-cache
  python mailguard.py example.com --dkim --dkim-selectors default,google,mail
  python mailguard.py example.com --smtp --smtp-usernames admin,root,test
  python mailguard.py example.com --full --stdout-json > results.json
  python mailguard.py domains.txt --full --cache-ttl 600 --cache-size 5000
```


## Contributing to MailGuard

Thanks for your interest in contributing! Here's how you can help:

1. **Report Issues:** Open an issue if you find a bug or have a feature request.
2. **Submit Pull Requests:** Fork the repo, make your changes, and submit a PR.
3. **Improve Documentation:** Suggest edits or add examples to make it clearer.
4. **Test the Tool:** Try it on different domains and share your feedback.

Please follow code style and include clear commit messages.




## Legal & Ethical Use

This tool is designed for legitimate security assessments of domains you own or have explicit permission to test. Users are responsible for ensuring compliance with applicable laws and regulations.

**Intended Use Cases:**
- Security audits of your own domains
- Penetration testing with proper authorization  
- Academic research and education
- Compliance verification



## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.



**⭐ If this tool helped you secure your email infrastructure, please consider starring the repository!**
