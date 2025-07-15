import argparse
import os
import sys
import json
import subprocess
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import logging
import socket
from typing import Dict, List
import csv

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('reconnaissance.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class Reconnaissance:
    def __init__(self, domain, output_dir, timeout=300, workers=20):
        self.domain = domain
        self.output_dir = output_dir
        self.timeout = timeout
        self.workers = workers
        self.subdomains = []
        self.active_subdomains = []
        self.results = {
            "domain": domain,
            "timestamp": datetime.now().isoformat(),
            "total_subdomains": 0,
            "active_subdomains": 0,
            "subdomains": [],
            "active_hosts": [],
            "errors": []
        }

        os.makedirs(output_dir, exist_ok=True)

    def run_amass(self, timeout: int) -> List[str]:
        try:
            # First check if amass is available (cross-platform)
            amass_check_cmd = ['where', 'amass'] if os.name == 'nt' else ['which', 'amass']
            amass_check = subprocess.run(amass_check_cmd, capture_output=True, text=True)
            if amass_check.returncode != 0:
                logger.warning("Amass not found, using fallback subdomain enumeration")
                return self.fallback_subdomain_enumeration()
            
            cmd = [
                'amass', 'enum',
                '-passive',
                '-d', self.domain,
                '-o', os.path.join(self.output_dir, f'{self.domain}_amass_results.text')
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

            if result.returncode == 0:
                results_file = os.path.join(self.output_dir, f'{self.domain}_amass_results.text')
                if os.path.exists(results_file):
                    with open(results_file, 'r') as f:
                        for line in f:
                            if line.strip():
                                subdomain = line.strip().split()[0]
                                self.subdomains.append(subdomain)
                    return self.subdomains
                else:
                    logger.warning("Amass results file not found, using fallback")
                    return self.fallback_subdomain_enumeration()
            else: 
                logger.error(f"Amass failed with return code: {result.returncode}")
                logger.error(f"Amass stderr: {result.stderr}")
                return self.fallback_subdomain_enumeration()
        except Exception as e:
            logger.error(f"Error running Amass: {e}")
            return self.fallback_subdomain_enumeration()
    
    def fallback_subdomain_enumeration(self) -> List[str]:
        """Fallback method when amass is not available"""
        logger.info("Using fallback subdomain enumeration method")
        
        # Common subdomains to test
        common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'api', 'app', 'dev', 'test', 'staging',
            'blog', 'shop', 'store', 'forum', 'support', 'help', 'docs', 'cdn',
            'static', 'assets', 'images', 'media', 'files', 'download', 'uploads'
        ]
        
        fallback_subdomains = []
        for subdomain in common_subdomains:
            full_subdomain = f"{subdomain}.{self.domain}"
            fallback_subdomains.append(full_subdomain)
        
        # Also add the main domain
        fallback_subdomains.append(self.domain)
        
        return fallback_subdomains
        
    def validate_subdomain_http(self, subdomain: str, timeout: int) -> Dict:
        result = {
            "subdomain": subdomain,
            "http_status": None,
            "https_status": None,
            "active": False,
            "redirects_to": None,
            "server": None, 
            "technologies": []
        }

        # HTTP
        try:
            response = requests.get(f"http://{subdomain}", timeout=timeout, allow_redirects=True)
            result["http_status"] = response.status_code
            result["active"] = True
            result["redirects_to"] = response.url
            result["server"] = response.headers.get("Server", None)

        except Exception:
            pass

        # HTTPS
        try:
            response = requests.get(f"https://{subdomain}", timeout=timeout, allow_redirects=True)
            result["https_status"] = response.status_code
            result["active"] = True
            result["redirects_to"] = response.url
            result["server"] = response.headers.get("Server", None)
        except Exception:
            pass

        return result

    def validate_subdomain_dns(self, subdomain: str) -> Dict:
        result = {
            "subdomain": subdomain,
            "ip_address": None, 
            "dns_active": False
        }

        try:
            ip_addresses = socket.gethostbyname_ex(subdomain)[2]
            result["ip_addresses"] = ip_addresses
            result["dns_active"] = True
        except Exception:
            pass

        return result
    
    def validate_subdomain(self, subdomains: List[str], max_worker: int) -> List[Dict]:
        validation_results = []

        with ThreadPoolExecutor(max_workers=max_worker) as executor:
            http_futures = {executor.submit(self.validate_subdomain_http, sub, 10): sub 
                           for sub in subdomains}
            
            # Submit DNS validation tasks
            dns_futures = {executor.submit(self.validate_subdomain_dns, sub): sub 
                          for sub in subdomains}
            
            http_results = {}
            for future in as_completed(http_futures):
                subdomain = http_futures[future]
                try: 
                    result = future.result()
                    http_results[subdomain] = result
                except Exception as e: 
                    logger.error(f"Error validating HTTP for {subdomain}: {e}")

            dns_results = {}
            for future in as_completed(dns_futures):
                subdomain = dns_futures[future]
                try:
                    result = future.result()
                    dns_results[subdomain] = result
                except Exception as e:
                    logger.error(f"Error validating DNS for {subdomain}: {e}")
            
            # Combine results
            for subdomain in subdomains:
                result = http_results.get(subdomain, {})
                dns_result = dns_results.get(subdomain, {})
                combined_result = {**result, **dns_result}
                validation_results.append(combined_result)
            
            return validation_results
        
    def save_json_report(self, filename: str = None) -> str:
        if not filename:
            filename = f"{self.domain}_reconnaissance_report.json"
        
        filepath = os.path.join(self.output_dir, filename)
        
        with open(filepath, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        
        return filepath
    
    def save_csv_report(self, filename: str = None) -> str:
        if not filename:
            filename = f"{self.domain}_subdomains.csv"

        filepath = os.path.join(self.output_dir, filename)

        if not self.results["subdomains"]:
            return filepath

        fieldnames = list(self.results["subdomains"][0].keys())

        with open(filepath, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

            for subdomain in self.results["subdomains"]:
                row = subdomain.copy()
                if isinstance(row.get("ip_addresses"), list):
                    row["ip_addresses"] = ", ".join(row["ip_addresses"])
                writer.writerow(row)

        return filepath


    def run_reconnaissance(self) -> Dict:
        try:
            subdomains = self.run_amass(self.timeout)
            if not subdomains:
                err_msg = f"No subdomains found for {self.domain}"
                self.results["errors"].append(err_msg)
                logger.warning(err_msg)
            else:
                self.results["total_subdomains"] = len(subdomains)

                valid_results = self.validate_subdomain(subdomains, self.workers)
                self.results["subdomains"] = valid_results

                active_results = [sub for sub in valid_results if sub.get("active")]
                self.results['active_hosts'] = active_results
                self.results['active_subdomains'] = len(active_results)

            # Always create output files, even if no results
            self.save_json_report()
            self.save_csv_report()

            return self.results
        
        except Exception as e:
            err_msg = f"Error during reconnaissance: {e}"
            self.results["errors"].append(err_msg)
            logger.error(err_msg)
            
            # Still try to save the results with error information
            try:
                self.save_json_report()
                self.save_csv_report()
            except Exception as save_error:
                logger.error(f"Error saving results: {save_error}")
            
            return self.results


    
def main():
    parser = argparse.ArgumentParser(description="Reconnaissance script for subdomains")
    parser.add_argument('domain', help='Target domain for reconnaissance')
    parser.add_argument('--output-dir', '-o', default='output',
                       help='Output directory for results (default: output)')
    parser.add_argument('--json-only', action='store_true',
                       help='Output only JSON format')
    parser.add_argument('--csv-only', action='store_true',
                       help='Output only CSV format')
    parser.add_argument('--timeout', '-t', type=int, default=300,
                       help='Amass timeout in seconds (default: 300)')
    parser.add_argument('--workers', '-w', type=int, default=20,
                       help='Number of validation workers (default: 20)')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')
    
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    recon = Reconnaissance(args.domain, args.output_dir, args.timeout, args.workers)

    results = recon.run_reconnaissance()

    print(json.dumps(results, indent=2, default=str))

if __name__ == '__main__':
    sys.exit(main())
