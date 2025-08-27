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
# Quick scan of a single domain (MX only - backward compatible)
python mailguard.py example.com

# Full security scan (all checks)
python mailguard.py example.com --full

# Scan multiple domains with progress bar
python mailguard.py "example.com,test.com,corp.com" --full --progress

# Scan from file with custom output
python mailguard.py domains.txt --full --json results.json --csv report.csv
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
