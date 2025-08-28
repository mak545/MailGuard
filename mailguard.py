#!/usr/bin/env python3
"""
MailGuard - Comprehensive Email Security Vulnerability Scanner
Author: Mohamed Essam
License: MIT
Description: Scans MX, SPF, DKIM, and DMARC records for security vulnerabilities
"""

import asyncio
import aiohttp
import json
import csv
import argparse
import sys
import time
import re
import base64
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Any
from dataclasses import dataclass, asdict, field
from enum import Enum
import logging
from urllib.parse import urlencode
import whois
import dns.resolver
import dns.exception
from concurrent.futures import ThreadPoolExecutor
import ssl
import warnings
from tqdm import tqdm


warnings.filterwarnings("ignore", category=DeprecationWarning)

class VulnerabilityStatus(Enum):
    VULNERABLE = "VULNERABLE"
    WEAK = "WEAK"
    SAFE = "SAFE"
    ERROR = "ERROR"
    TIMEOUT = "TIMEOUT"
    MISSING = "MISSING"

@dataclass
class MXRecord:
    hostname: str
    priority: int
    
@dataclass
class SPFRecord:
    raw_record: str
    mechanism_count: int = 0
    includes: List[str] = field(default_factory=list)
    has_all: bool = False
    all_qualifier: str = ""
    dangling_includes: List[str] = field(default_factory=list)

@dataclass
class DKIMRecord:
    selector: str
    raw_record: str
    has_public_key: bool = False
    key_type: str = ""
    key_length: int = 0
    
@dataclass
class DMARCRecord:
    raw_record: str
    policy: str = ""
    subdomain_policy: str = ""
    percentage: int = 100
    has_rua: bool = False
    has_ruf: bool = False
    rua_addresses: List[str] = field(default_factory=list)

@dataclass
class EmailSecurityResult:
    domain: str
    
    
    mx_status: VulnerabilityStatus = VulnerabilityStatus.ERROR
    mx_records: List[MXRecord] = field(default_factory=list)
    vulnerable_mx: List[str] = field(default_factory=list)
    mx_message: str = ""

    spf_status: VulnerabilityStatus = VulnerabilityStatus.ERROR
    spf_record: Optional[SPFRecord] = None
    spf_message: str = ""
    

    dkim_status: VulnerabilityStatus = VulnerabilityStatus.ERROR
    dkim_records: List[DKIMRecord] = field(default_factory=list)
    dkim_message: str = ""
    

    dmarc_status: VulnerabilityStatus = VulnerabilityStatus.ERROR
    dmarc_record: Optional[DMARCRecord] = None
    dmarc_message: str = ""
    
    scan_time: float = 0.0
    details: Dict[str, Any] = field(default_factory=dict)

class EmailSecurityScanner:
    """Professional Email Security Scanner with comprehensive checks"""
    
    # many DNS resolvers for redundancy
    DNS_RESOLVERS = [
        "8.8.8.8",      # Google
        "1.1.1.1",      # Cloudflare
        "208.67.222.222", # OpenDNS
        "9.9.9.9",      # Quad9
        "8.26.56.26",   # Comodo
    ]
    
    # DNS-over-HTTPS
    DOH_ENDPOINTS = [
        "https://dns.google/resolve",
        "https://cloudflare-dns.com/dns-query",
        "https://dns.quad9.net/dns-query"
    ]
    
    # Common DKIM selectors to try
    DEFAULT_DKIM_SELECTORS = ['default', 'mail', 'k1', 'google', 'selector1', 'selector2', 'dkim']
    
    def __init__(self, concurrency: int = 50, timeout: int = 10, verbose: bool = False):
        self.concurrency = concurrency
        self.timeout = timeout
        self.verbose = verbose
        self.session: Optional[aiohttp.ClientSession] = None
        self.logger = self._setup_logger()
        self.executor = ThreadPoolExecutor(max_workers=concurrency)
        
    def _setup_logger(self) -> logging.Logger:
        """Setup logging configuration"""
        logger = logging.getLogger('email_scanner')
        logger.setLevel(logging.DEBUG if self.verbose else logging.INFO)
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        return logger
        
    async def __aenter__(self):
        """Async context manager entry"""
        connector = aiohttp.TCPConnector(
            limit=self.concurrency,
            ssl=ssl.create_default_context(),
            use_dns_cache=False,
            ttl_dns_cache=0
        )
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        self.session = aiohttp.ClientSession(
            connector=connector, 
            timeout=timeout,
            headers={'User-Agent': 'EmailSec-Scanner/2.0'}
        )
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
        self.executor.shutdown(wait=True)
        
    def _log_verbose(self, message: str, domain: str = ""):
        """Log verbose messages"""
        if self.verbose:
            prefix = f"[{domain}] " if domain else ""
            self.logger.debug(f"{prefix}{message}")
            
    async def _get_mx_records_dns(self, domain: str) -> List[MXRecord]:
        """Get MX records using multiple DNS resolvers - aggregate all results"""
        all_mx_records = {}
        
        for resolver_ip in self.DNS_RESOLVERS:
            try:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [resolver_ip]
                resolver.timeout = self.timeout / 2
                resolver.lifetime = self.timeout
                
                self._log_verbose(f"Querying MX records via {resolver_ip}", domain)
                
                loop = asyncio.get_event_loop()
                answers = await loop.run_in_executor(
                    self.executor,
                    lambda: resolver.resolve(domain, 'MX')
                )
                
                for rdata in answers:
                    hostname = str(rdata.exchange).rstrip('.')
                    priority = int(rdata.preference)
                    all_mx_records[hostname] = MXRecord(hostname=hostname, priority=priority)
                
                self._log_verbose(f"Found {len([r for r in answers])} MX records via {resolver_ip}", domain)
                    
            except (dns.exception.DNSException, Exception) as e:
                self._log_verbose(f"DNS resolver {resolver_ip} failed: {str(e)}", domain)
                continue
                
        return list(all_mx_records.values())
        
    async def _get_mx_records_doh(self, domain: str) -> List[MXRecord]:
        """Get MX records using DNS-over-HTTPS for verification"""
        if not self.session:
            return []
            
        all_mx_records = {}
        
        for doh_url in self.DOH_ENDPOINTS:
            try:
                params = {
                    'name': domain,
                    'type': 'MX'
                }
                
                self._log_verbose(f"Querying MX via DoH: {doh_url}", domain)
                
                async with self.session.get(
                    doh_url, 
                    params=params,
                    headers={'Accept': 'application/dns-json'}
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        if 'Answer' in data:
                            for answer in data['Answer']:
                                if answer.get('type') == 15: 
                                    mx_data = answer['data'].split(' ', 1)
                                    if len(mx_data) == 2:
                                        priority, hostname = mx_data
                                        hostname = hostname.rstrip('.')
                                        all_mx_records[hostname] = MXRecord(
                                            hostname=hostname,
                                            priority=int(priority)
                                        )
                            
            except Exception as e:
                self._log_verbose(f"DoH query failed for {doh_url}: {str(e)}", domain)
                continue
                
        return list(all_mx_records.values())
        
    async def _get_txt_records(self, domain: str, record_type: str = "TXT") -> List[str]:
        """Get TXT records using multiple DNS resolvers"""
        all_txt_records = set()
        
        for resolver_ip in self.DNS_RESOLVERS:
            try:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [resolver_ip]
                resolver.timeout = self.timeout / 2
                resolver.lifetime = self.timeout
                
                self._log_verbose(f"Querying {record_type} records via {resolver_ip} for {domain}", domain)
                
                loop = asyncio.get_event_loop()
                answers = await loop.run_in_executor(
                    self.executor,
                    lambda: resolver.resolve(domain, record_type)
                )
                
                for rdata in answers:
                    # Join
                    txt_data = ''.join([s.decode() if isinstance(s, bytes) else str(s) for s in rdata.strings])
                    all_txt_records.add(txt_data)
                
                self._log_verbose(f"Found {len([r for r in answers])} {record_type} records via {resolver_ip}", domain)
                    
            except (dns.exception.DNSException, Exception) as e:
                self._log_verbose(f"DNS resolver {resolver_ip} failed for {record_type}: {str(e)}", domain)
                continue
                
        return list(all_txt_records)
        
    async def _resolve_hostname(self, hostname: str) -> bool:
        """Check if hostname resolves to valid IP addresses"""
        for resolver_ip in self.DNS_RESOLVERS[:2]:
            try:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [resolver_ip]
                resolver.timeout = self.timeout / 2
                
                loop = asyncio.get_event_loop()
                
                
                try:
                    await loop.run_in_executor(
                        self.executor,
                        lambda: resolver.resolve(hostname, 'A')
                    )
                    return True
                except dns.exception.DNSException:
                    pass
                    
            
                try:
                    await loop.run_in_executor(
                        self.executor,
                        lambda: resolver.resolve(hostname, 'AAAA')
                    )
                    return True
                except dns.exception.DNSException:
                    pass
                    
            except Exception as e:
                continue
                
        return False
        
    async def _check_domain_availability_rdap(self, domain: str) -> Tuple[bool, str]:
        """Check domain availability using RDAP"""
        try:
            tld = domain.split('.')[-1]
            rdap_url = f"https://rdap.org/domain/{domain}"
            
            self._log_verbose(f"Checking RDAP for domain availability: {domain}", domain)
            
            if self.session:
                async with self.session.get(rdap_url) as response:
                    if response.status == 404:
                        return True, "Domain available (RDAP 404)"
                    elif response.status == 200:
                        data = await response.json()
                        if 'status' in data and any('active' in str(s).lower() for s in data['status']):
                            return False, "Domain registered (RDAP active)"
                        else:
                            return True, "Domain status unclear (RDAP)"
                    else:
                        return False, f"RDAP check failed (HTTP {response.status})"
        except Exception as e:
            self._log_verbose(f"RDAP check failed for {domain}: {str(e)}", domain)
            return False, f"RDAP error: {str(e)}"
            
    async def _check_domain_availability(self, domain: str) -> Tuple[bool, str]:
        """Check if domain is available for registration using WHOIS with RDAP fallback"""
        try:
            self._log_verbose(f"Checking WHOIS for domain availability: {domain}", domain)
            
            loop = asyncio.get_event_loop()
            whois_info = await loop.run_in_executor(
                self.executor,
                lambda: whois.whois(domain)
            )
            
            
            availability_indicators = [
                whois_info is None,
                not whois_info,
                not hasattr(whois_info, 'domain_name'),
                whois_info.domain_name is None,
                (hasattr(whois_info, 'status') and 
                 whois_info.status and 
                 any('available' in str(status).lower() for status in 
                     (whois_info.status if isinstance(whois_info.status, list) 
                      else [whois_info.status]))),
                (hasattr(whois_info, 'registrar') and whois_info.registrar is None)
            ]
            
            is_available = any(availability_indicators)
            
            if is_available:
                return True, "Domain available for registration (WHOIS)"
            else:
                return False, "Domain is registered (WHOIS)"
                
        except Exception as e:
            self._log_verbose(f"WHOIS failed for {domain}, trying RDAP: {str(e)}", domain)

            return await self._check_domain_availability_rdap(domain)
            
    async def _scan_mx_records(self, domain: str) -> Tuple[VulnerabilityStatus, List[MXRecord], List[str], str, Dict]:
        """Scan MX records for vulnerabilities"""
        self._log_verbose(f"Scanning MX records", domain)
        
        # get mx records
        mx_records_dns = await self._get_mx_records_dns(domain)
        mx_records_doh = await self._get_mx_records_doh(domain)
        
        # Combine and deduplicate
        all_mx_records = {}
        for mx in mx_records_dns + mx_records_doh:
            all_mx_records[mx.hostname] = mx
            
        mx_records = list(all_mx_records.values())
        
        if not mx_records:
            return VulnerabilityStatus.MISSING, [], [], "No MX records found", {"mx_count": 0}
        
        # Check each MX record for vulnerabilities
        vulnerable_mx = []
        details = {"mx_count": len(mx_records), "checks": []}
        
        for mx_record in mx_records:
            mx_hostname = mx_record.hostname
            check_detail = {
                "mx_hostname": mx_hostname,
                "priority": mx_record.priority,
                "resolves": False,
                "available": False,
                "vulnerable": False
            }
            

            resolves = await self._resolve_hostname(mx_hostname)
            check_detail["resolves"] = resolves
            
            if not resolves:

                is_available, availability_msg = await self._check_domain_availability(mx_hostname)
                check_detail["available"] = is_available
                check_detail["availability_message"] = availability_msg
                
                if is_available:
                    vulnerable_mx.append(mx_hostname)
                    check_detail["vulnerable"] = True
            
            details["checks"].append(check_detail)
        

        if vulnerable_mx:
            status = VulnerabilityStatus.VULNERABLE
            message = f"Found {len(vulnerable_mx)} vulnerable MX record(s): {', '.join(vulnerable_mx)}"
        else:
            status = VulnerabilityStatus.SAFE
            message = "All MX records are properly configured"
        
        return status, mx_records, vulnerable_mx, message, details
        
    async def _scan_spf_record(self, domain: str) -> Tuple[VulnerabilityStatus, Optional[SPFRecord], str]:
        """Scan SPF record for vulnerabilities"""
        self._log_verbose(f"Scanning SPF record", domain)
        
        txt_records = await self._get_txt_records(domain)
        spf_records = [r for r in txt_records if r.startswith('v=spf1')]
        
        if not spf_records:
            return VulnerabilityStatus.MISSING, None, "No SPF record found"
        
        if len(spf_records) > 1:
            return VulnerabilityStatus.WEAK, None, f"Multiple SPF records found ({len(spf_records)})"
        
        spf_raw = spf_records[0]
        spf_record = SPFRecord(raw_record=spf_raw)
        
        
        mechanisms = spf_raw.split()
        spf_record.mechanism_count = len(mechanisms) - 1
        

        for mechanism in mechanisms:
            if mechanism.startswith('include:'):
                include_domain = mechanism[8:]  # Remove 'include:'
                spf_record.includes.append(include_domain)
        
        # Check for 'all' qualifier
        all_mechanisms = [m for m in mechanisms if m.endswith('all')]
        if all_mechanisms:
            spf_record.has_all = True
            spf_record.all_qualifier = all_mechanisms[-1]  # Take the last one
        
        # Check for dangling includes
        for include_domain in spf_record.includes:
            resolves = await self._resolve_hostname(include_domain)
            if not resolves:
                is_available, _ = await self._check_domain_availability(include_domain)
                if is_available:
                    spf_record.dangling_includes.append(include_domain)
        
        # Determine vulnerability status
        if spf_record.dangling_includes:
            status = VulnerabilityStatus.VULNERABLE
            message = f"Dangling SPF includes: {', '.join(spf_record.dangling_includes)}"
        elif spf_record.all_qualifier in ['+all', '?all']:
            status = VulnerabilityStatus.WEAK
            message = f"Weak SPF policy: {spf_record.all_qualifier}"
        elif not spf_record.has_all:
            status = VulnerabilityStatus.WEAK
            message = "SPF record missing 'all' mechanism"
        else:
            status = VulnerabilityStatus.SAFE
            message = f"SPF record properly configured: {spf_record.all_qualifier}"
        
        return status, spf_record, message
        
    def _extract_dkim_key_info(self, dkim_record: str) -> Tuple[str, int]:
        """Extract key type and length from DKIM record"""
        key_type = ""
        key_length = 0
        
        # Extract key type
        k_match = re.search(r'k=([^;]+)', dkim_record)
        if k_match:
            key_type = k_match.group(1).strip()
        else:
            key_type = "rsa"  # Default to RSA
            
        # Extract public key
        p_match = re.search(r'p=([^;]+)', dkim_record)
        if p_match:
            public_key_b64 = p_match.group(1).strip()
            try:
                # Decode base64 key to estimate length
                public_key_bytes = base64.b64decode(public_key_b64 + "==")  # Add padding
                # For RSA keys, rough estimate: byte_length * 8
                key_length = len(public_key_bytes) * 8
            except Exception:
                key_length = 0
                
        return key_type.lower(), key_length
        
    async def _scan_dkim_records(self, domain: str, selectors: List[str]) -> Tuple[VulnerabilityStatus, List[DKIMRecord], str]:
        """Scan DKIM records for vulnerabilities"""
        self._log_verbose(f"Scanning DKIM records with selectors: {', '.join(selectors)}", domain)
        
        dkim_records = []
        
        for selector in selectors:
            dkim_domain = f"{selector}._domainkey.{domain}"
            txt_records = await self._get_txt_records(dkim_domain)
            
            for txt_record in txt_records:
                if 'p=' in txt_record:  # DKIM record indicator
                    key_type, key_length = self._extract_dkim_key_info(txt_record)
                    
                    dkim_record = DKIMRecord(
                        selector=selector,
                        raw_record=txt_record,
                        has_public_key='p=' in txt_record and not txt_record.find('p=;') > -1,
                        key_type=key_type,
                        key_length=key_length
                    )
                    dkim_records.append(dkim_record)
                    self._log_verbose(f"Found DKIM record for selector '{selector}': {key_type} {key_length}bit", domain)
        
        if not dkim_records:
            return VulnerabilityStatus.MISSING, [], "No DKIM records found"
        
        # Check for vulnerabilities
        weak_keys = [r for r in dkim_records if r.key_type == 'rsa' and 0 < r.key_length < 1024]
        missing_keys = [r for r in dkim_records if not r.has_public_key]
        
        if missing_keys:
            status = VulnerabilityStatus.VULNERABLE
            message = f"DKIM records with missing public keys: {', '.join([r.selector for r in missing_keys])}"
        elif weak_keys:
            status = VulnerabilityStatus.WEAK
            message = f"Weak RSA keys (<1024 bit): {', '.join([f'{r.selector}({r.key_length}bit)' for r in weak_keys])}"
        else:
            status = VulnerabilityStatus.SAFE
            message = f"Found {len(dkim_records)} properly configured DKIM record(s)"
        
        return status, dkim_records, message
        
    async def _scan_dmarc_record(self, domain: str) -> Tuple[VulnerabilityStatus, Optional[DMARCRecord], str]:
        """Scan DMARC record for vulnerabilities"""
        self._log_verbose(f"Scanning DMARC record", domain)
        
        dmarc_domain = f"_dmarc.{domain}"
        txt_records = await self._get_txt_records(dmarc_domain)
        dmarc_records = [r for r in txt_records if r.startswith('v=DMARC1')]
        
        if not dmarc_records:
            return VulnerabilityStatus.MISSING, None, "No DMARC record found"
        
        if len(dmarc_records) > 1:
            return VulnerabilityStatus.WEAK, None, f"Multiple DMARC records found ({len(dmarc_records)})"
        
        dmarc_raw = dmarc_records[0]
        dmarc_record = DMARCRecord(raw_record=dmarc_raw)
        
        # Parse DMARC record
        # Extract policy
        p_match = re.search(r'p=([^;]+)', dmarc_raw)
        if p_match:
            dmarc_record.policy = p_match.group(1).strip()
        
        # Extract subdomain policy
        sp_match = re.search(r'sp=([^;]+)', dmarc_raw)
        if sp_match:
            dmarc_record.subdomain_policy = sp_match.group(1).strip()
        
        # Extract percentage
        pct_match = re.search(r'pct=(\d+)', dmarc_raw)
        if pct_match:
            dmarc_record.percentage = int(pct_match.group(1))
        
        # Check for reporting addresses
        rua_match = re.search(r'rua=([^;]+)', dmarc_raw)
        if rua_match:
            dmarc_record.has_rua = True
            dmarc_record.rua_addresses = [addr.strip() for addr in rua_match.group(1).split(',')]
        
        ruf_match = re.search(r'ruf=([^;]+)', dmarc_raw)
        if ruf_match:
            dmarc_record.has_ruf = True
        
        # Determine vulnerability status
        if dmarc_record.policy == 'none' and dmarc_record.percentage > 0:
            status = VulnerabilityStatus.WEAK
            message = "DMARC policy is 'none' - provides no protection"
        elif dmarc_record.policy in ['quarantine', 'reject']:
            status = VulnerabilityStatus.SAFE
            message = f"DMARC policy '{dmarc_record.policy}' provides good protection"
        else:
            status = VulnerabilityStatus.WEAK
            message = f"Unknown DMARC policy: {dmarc_record.policy}"
        
        return status, dmarc_record, message
        
    async def _scan_single_domain(self, domain: str, enable_mx: bool, enable_spf: bool, 
                                enable_dkim: bool, enable_dmarc: bool, 
                                dkim_selectors: List[str]) -> EmailSecurityResult:
        """Scan a single domain for email security vulnerabilities"""
        start_time = time.time()
        domain = domain.strip().lower()
        
        self._log_verbose(f"Starting comprehensive scan for domain: {domain}", domain)
        
        result = EmailSecurityResult(domain=domain)
        
        try:
            # Run all scans concurrently
            tasks = []
            
            if enable_mx:
                tasks.append(('mx', self._scan_mx_records(domain)))
            if enable_spf:
                tasks.append(('spf', self._scan_spf_record(domain)))
            if enable_dkim:
                tasks.append(('dkim', self._scan_dkim_records(domain, dkim_selectors)))
            if enable_dmarc:
                tasks.append(('dmarc', self._scan_dmarc_record(domain)))
            
            # Execute all scans
            scan_results = {}
            for scan_type, task in tasks:
                scan_results[scan_type] = await task
            
            # Process MX results
            if 'mx' in scan_results:
                mx_status, mx_records, vulnerable_mx, mx_message, mx_details = scan_results['mx']
                result.mx_status = mx_status
                result.mx_records = mx_records
                result.vulnerable_mx = vulnerable_mx
                result.mx_message = mx_message
                result.details['mx'] = mx_details
            
            # Process SPF results
            if 'spf' in scan_results:
                spf_status, spf_record, spf_message = scan_results['spf']
                result.spf_status = spf_status
                result.spf_record = spf_record
                result.spf_message = spf_message
            
            # Process DKIM results
            if 'dkim' in scan_results:
                dkim_status, dkim_records, dkim_message = scan_results['dkim']
                result.dkim_status = dkim_status
                result.dkim_records = dkim_records
                result.dkim_message = dkim_message
            
            # Process DMARC results
            if 'dmarc' in scan_results:
                dmarc_status, dmarc_record, dmarc_message = scan_results['dmarc']
                result.dmarc_status = dmarc_status
                result.dmarc_record = dmarc_record
                result.dmarc_message = dmarc_message
            
            result.scan_time = time.time() - start_time
            
            return result
            
        except asyncio.TimeoutError:
            result.scan_time = time.time() - start_time
            result.mx_status = VulnerabilityStatus.TIMEOUT
            result.mx_message = "Scan timeout"
            return result
            
        except Exception as e:
            result.scan_time = time.time() - start_time
            self.logger.error(f"Error scanning {domain}: {str(e)}")
            result.mx_status = VulnerabilityStatus.ERROR
            result.mx_message = f"Scan error: {str(e)}"
            result.details = {"error": str(e)}
            return result
            
    async def scan_domains(self, domains: List[str], enable_mx: bool = True, 
                          enable_spf: bool = False, enable_dkim: bool = False,
                          enable_dmarc: bool = False, dkim_selectors: List[str] = None,
                          show_progress: bool = False) -> List[EmailSecurityResult]:
        """Scan multiple domains concurrently"""
        semaphore = asyncio.Semaphore(self.concurrency)
        
        if dkim_selectors is None:
            dkim_selectors = self.DEFAULT_DKIM_SELECTORS
        
        async def scan_with_semaphore(domain: str) -> EmailSecurityResult:
            async with semaphore:
                return await self._scan_single_domain(
                    domain, enable_mx, enable_spf, enable_dkim, enable_dmarc, dkim_selectors
                )
        
        self.logger.info(f"Starting scan of {len(domains)} domains with concurrency {self.concurrency}")
        
        # Create progress bar if requested
        pbar = None
        if show_progress:
            pbar = tqdm(total=len(domains), desc="Scanning domains", unit="domain")
        
        async def scan_with_progress(domain: str) -> EmailSecurityResult:
            result = await scan_with_semaphore(domain)
            if pbar:
                pbar.update(1)
            return result
        
        tasks = [scan_with_progress(domain) for domain in domains]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        if pbar:
            pbar.close()
        
        # exceptions
        clean_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                self.logger.error(f"Exception scanning {domains[i]}: {str(result)}")
                clean_results.append(EmailSecurityResult(
                    domain=domains[i],
                    mx_status=VulnerabilityStatus.ERROR,
                    mx_message=f"Scan exception: {str(result)}",
                    scan_time=0.0,
                    details={"error": str(result)}
                ))
            else:
                clean_results.append(result)
        
        return clean_results

class OutputManager:
    """Handle various output formats"""
    
    @staticmethod
    def print_human_readable(results: List[EmailSecurityResult], verbose: bool = False):
        """Print results in human-readable format"""
        print(f"\nEmail Security Scanner Results ({len(results)} domains scanned)")
        print("=" * 80)
        
        # Count vulnerabilities by type
        mx_vulnerable = sum(1 for r in results if r.mx_status == VulnerabilityStatus.VULNERABLE)
        spf_issues = sum(1 for r in results if r.spf_status in [VulnerabilityStatus.VULNERABLE, VulnerabilityStatus.MISSING])
        dkim_issues = sum(1 for r in results if r.dkim_status in [VulnerabilityStatus.VULNERABLE, VulnerabilityStatus.MISSING])
        dmarc_issues = sum(1 for r in results if r.dmarc_status in [VulnerabilityStatus.VULNERABLE, VulnerabilityStatus.MISSING])
        
        print(f"Security Issues Found:")
        print(f"  MX Vulnerabilities: {mx_vulnerable}")
        print(f"  SPF Issues: {spf_issues}")
        print(f"  DKIM Issues: {dkim_issues}")
        print(f"  DMARC Issues: {dmarc_issues}\n")
        
        for result in results:
            print(f"Domain: {result.domain}")
            print("-" * 40)
            
            # MX Results
            if result.mx_status != VulnerabilityStatus.ERROR:
                status_color = OutputManager._get_status_color(result.mx_status)
                print(f"  [MX] {status_color}{result.mx_status.value}\033[0m - {result.mx_message}")
                if verbose and result.mx_records:
                    for mx in sorted(result.mx_records, key=lambda x: x.priority):
                        vulnerable_marker = " (VULNERABLE)" if mx.hostname in result.vulnerable_mx else ""
                        print(f"    {mx.priority}: {mx.hostname}{vulnerable_marker}")
            
            # SPF Results
            if result.spf_status != VulnerabilityStatus.ERROR:
                status_color = OutputManager._get_status_color(result.spf_status)
                print(f"  [SPF] {status_color}{result.spf_status.value}\033[0m - {result.spf_message}")
                if verbose and result.spf_record:
                    print(f"    Record: {result.spf_record.raw_record}")
                    if result.spf_record.includes:
                        print(f"    Includes: {', '.join(result.spf_record.includes)}")
            
            # DKIM Results
            if result.dkim_status != VulnerabilityStatus.ERROR:
                status_color = OutputManager._get_status_color(result.dkim_status)
                print(f"  [DKIM] {status_color}{result.dkim_status.value}\033[0m - {result.dkim_message}")
                if verbose and result.dkim_records:
                    for dkim in result.dkim_records:
                        print(f"    {dkim.selector}: {dkim.key_type} {dkim.key_length}bit")
            
            # DMARC Results
            if result.dmarc_status != VulnerabilityStatus.ERROR:
                status_color = OutputManager._get_status_color(result.dmarc_status)
                print(f"  [DMARC] {status_color}{result.dmarc_status.value}\033[0m - {result.dmarc_message}")
                if verbose and result.dmarc_record:
                    print(f"    Policy: {result.dmarc_record.policy}")
                    if result.dmarc_record.has_rua:
                        print(f"    Reporting: {', '.join(result.dmarc_record.rua_addresses)}")
            
            print(f"  Scan Time: {result.scan_time:.2f}s")
            print()
    
    @staticmethod
    def _get_status_color(status: VulnerabilityStatus) -> str:
        """Get ANSI color code for status"""
        return {
            VulnerabilityStatus.VULNERABLE: "\033[91m",  # Red
            VulnerabilityStatus.WEAK: "\033[93m",        # Yellow
            VulnerabilityStatus.SAFE: "\033[92m",        # Green
            VulnerabilityStatus.MISSING: "\033[95m",     # Magenta
            VulnerabilityStatus.ERROR: "\033[91m",       # Red
            VulnerabilityStatus.TIMEOUT: "\033[93m",     # Yellow
        }.get(status, "")
    
    @staticmethod
    def print_stdout_json(results: List[EmailSecurityResult]):
        """Print raw JSON output to stdout for CI/CD"""
        json_data = {
            "scan_timestamp": time.time(),
            "total_domains": len(results),
            "vulnerability_summary": {
                "mx_vulnerable": sum(1 for r in results if r.mx_status == VulnerabilityStatus.VULNERABLE),
                "spf_issues": sum(1 for r in results if r.spf_status in [VulnerabilityStatus.VULNERABLE, VulnerabilityStatus.MISSING]),
                "dkim_issues": sum(1 for r in results if r.dkim_status in [VulnerabilityStatus.VULNERABLE, VulnerabilityStatus.MISSING]),
                "dmarc_issues": sum(1 for r in results if r.dmarc_status in [VulnerabilityStatus.VULNERABLE, VulnerabilityStatus.MISSING])
            },
            "results": [asdict(result) for result in results]
        }
        print(json.dumps(json_data, indent=2, default=str))
    
    @staticmethod
    def save_json(results: List[EmailSecurityResult], filename: str):
        """Save results as JSON"""
        json_data = {
            "scan_timestamp": time.time(),
            "total_domains": len(results),
            "vulnerability_summary": {
                "mx_vulnerable": sum(1 for r in results if r.mx_status == VulnerabilityStatus.VULNERABLE),
                "spf_issues": sum(1 for r in results if r.spf_status in [VulnerabilityStatus.VULNERABLE, VulnerabilityStatus.MISSING]),
                "dkim_issues": sum(1 for r in results if r.dkim_status in [VulnerabilityStatus.VULNERABLE, VulnerabilityStatus.MISSING]),
                "dmarc_issues": sum(1 for r in results if r.dmarc_status in [VulnerabilityStatus.VULNERABLE, VulnerabilityStatus.MISSING])
            },
            "results": [asdict(result) for result in results]
        }
        
        with open(filename, 'w') as f:
            json.dump(json_data, f, indent=2, default=str)
        print(f"Results saved to {filename}")
    
    @staticmethod
    def save_csv(results: List[EmailSecurityResult], filename: str):
        """Save results as CSV"""
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                'Domain', 'MX_Status', 'MX_Message', 'SPF_Status', 'SPF_Message',
                'DKIM_Status', 'DKIM_Message', 'DMARC_Status', 'DMARC_Message', 'Scan_Time'
            ])
            
            for result in results:
                writer.writerow([
                    result.domain,
                    result.mx_status.value,
                    result.mx_message,
                    result.spf_status.value,
                    result.spf_message,
                    result.dkim_status.value,
                    result.dkim_message,
                    result.dmarc_status.value,
                    result.dmarc_message,
                    f"{result.scan_time:.2f}"
                ])
        print(f"Results saved to {filename}")

def parse_domains_input(domain_input: str) -> List[str]:
    """Parse domain input from various sources"""
    domains = []
    

    if Path(domain_input).is_file():
        try:
            with open(domain_input, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        domains.append(line)
        except Exception as e:
            print(f"Error reading file {domain_input}: {str(e)}", file=sys.stderr)
            sys.exit(1)
    else:

        for domain in domain_input.replace(',', ' ').replace(';', ' ').split():
            domain = domain.strip()
            if domain:
                domains.append(domain)
    
    return list(set(domains))

async def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description="Professional Email Security Scanner (MX, SPF, DKIM, DMARC)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python emailsec_scanner.py example.com --full
  python emailsec_scanner.py "example.com,test.com" --spf --dmarc
  python emailsec_scanner.py domains.txt --mx --progress
  python emailsec_scanner.py domains.txt --full --json results.json --csv results.csv
  python emailsec_scanner.py example.com --dkim --dkim-selectors default,google,mail
  python emailsec_scanner.py example.com --full --stdout-json > results.json
        """
    )
    
    parser.add_argument(
        'domains',
        help='Domain(s) to scan: single domain, comma-separated list, or file path'
    )
    
    # Scan type options
    scan_group = parser.add_argument_group('Scan Types')
    scan_group.add_argument(
        '--mx',
        action='store_true',
        help='Scan MX records for dangling entries'
    )
    scan_group.add_argument(
        '--spf',
        action='store_true',
        help='Scan SPF records for misconfigurations'
    )
    scan_group.add_argument(
        '--dkim',
        action='store_true',
        help='Scan DKIM records for weak keys'
    )
    scan_group.add_argument(
        '--dmarc',
        action='store_true',
        help='Scan DMARC records for policy issues'
    )
    scan_group.add_argument(
        '--full',
        action='store_true',
        help='Enable all security scans (MX + SPF + DKIM + DMARC)'
    )
    
    # Configuration options
    config_group = parser.add_argument_group('Configuration')
    config_group.add_argument(
        '--threads', '--concurrency',
        type=int,
        default=50,
        help='Number of concurrent scans (default: 50)'
    )
    config_group.add_argument(
        '--timeout',
        type=int,
        default=10,
        help='Timeout for DNS queries in seconds (default: 10)'
    )
    config_group.add_argument(
        '--dkim-selectors',
        help='Comma-separated list of DKIM selectors to check (default: common selectors)'
    )
    
    # Output options
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )
    output_group.add_argument(
        '--progress',
        action='store_true',
        help='Show progress bar during scanning'
    )
    output_group.add_argument(
        '--json',
        help='Save results to JSON file'
    )
    output_group.add_argument(
        '--csv',
        help='Save results to CSV file'
    )
    output_group.add_argument(
        '--stdout-json',
        action='store_true',
        help='Print raw JSON output to stdout (for CI/CD)'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='Email Security Scanner 2.0.0'
    )
    
    args = parser.parse_args()
    
    # Parse domains
    domains = parse_domains_input(args.domains)
    if not domains:
        print("Error: No valid domains found", file=sys.stderr)
        sys.exit(1)
    
    # Determine which scans to enable
    enable_mx = args.mx or args.full
    enable_spf = args.spf or args.full
    enable_dkim = args.dkim or args.full
    enable_dmarc = args.dmarc or args.full
    

    if not any([args.mx, args.spf, args.dkim, args.dmarc, args.full]):
        enable_mx = True
    

    dkim_selectors = None
    if args.dkim_selectors:
        dkim_selectors = [s.strip() for s in args.dkim_selectors.split(',')]
    
    if not args.stdout_json:
        scan_types = []
        if enable_mx: scan_types.append("MX")
        if enable_spf: scan_types.append("SPF")
        if enable_dkim: scan_types.append("DKIM")
        if enable_dmarc: scan_types.append("DMARC")
        
        print(f"Email Security Scanner v2.0.0")
        print(f"Scanning {len(domains)} domain(s) for: {', '.join(scan_types)}")
    
    #run
    async with EmailSecurityScanner(
        concurrency=args.threads,
        timeout=args.timeout,
        verbose=args.verbose
    ) as scanner:
        results = await scanner.scan_domains(
            domains,
            enable_mx=enable_mx,
            enable_spf=enable_spf,
            enable_dkim=enable_dkim,
            enable_dmarc=enable_dmarc,
            dkim_selectors=dkim_selectors,
            show_progress=args.progress
        )
    
    # Output results
    if args.stdout_json:
        OutputManager.print_stdout_json(results)
    else:
        OutputManager.print_human_readable(results, verbose=args.verbose)
    
    if args.json:
        OutputManager.save_json(results, args.json)
    
    if args.csv:
        OutputManager.save_csv(results, args.csv)
    
    # Exit code
    has_vulnerabilities = any(
        result.mx_status == VulnerabilityStatus.VULNERABLE or
        result.spf_status in [VulnerabilityStatus.VULNERABLE, VulnerabilityStatus.MISSING] or
        result.dkim_status in [VulnerabilityStatus.VULNERABLE, VulnerabilityStatus.MISSING] or
        result.dmarc_status in [VulnerabilityStatus.VULNERABLE, VulnerabilityStatus.MISSING]
        for result in results
    )
    
    if not args.stdout_json:
        if has_vulnerabilities:
            print("⚠️  Security vulnerabilities detected!")
        else:
            print("✅ No critical vulnerabilities found.")
    
    sys.exit(1 if has_vulnerabilities else 0)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"Fatal error: {str(e)}", file=sys.stderr)
        sys.exit(1)
