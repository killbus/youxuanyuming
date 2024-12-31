from collections.abc import Callable
import requests
from bs4 import BeautifulSoup
import re
import os
import ipaddress
import logging
from typing import List, Set
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

@dataclass
class URLConfig:
    url: str
    parser: Callable[[str, str], Set[str]]

@dataclass
class Config:
    urls: List[URLConfig]  # 使用结构化的 URL 配置
    output_file: str
    ip_pattern: str = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    timeout: int = 10
    max_workers: int = 3

def parse_table_ips(html: str, ip_pattern: str) -> Set[str]:
    """解析 HTML 表格中的 IP 地址."""
    soup = BeautifulSoup(html, 'html.parser')
    elements = soup.find_all('tr')
    ips = set()
    for element in elements:
        element_text = element.get_text()
        ip_matches = re.findall(ip_pattern, element_text)
        ips.update(ip_matches)
    return ips

def parse_comma_separated_ips(text: str, ip_pattern: str) -> Set[str]:
    """解析逗号分隔的 IP 地址."""
    ip_matches = re.findall(ip_pattern, text)
    return set(ip_matches)

class CloudflareIPScraper:
    def __init__(self, config: Config):
        self.config = config
        self.session = self._setup_session()
        self._setup_logging()
        
    def _setup_logging(self) -> None:
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    def _setup_session(self) -> requests.Session:
        session = requests.Session()
        retry = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry)
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        return session

    def get_cloudflare_ranges(self) -> Set[ipaddress.IPv4Network]:
        try:
            v4_ranges = self.session.get('https://www.cloudflare.com/ips-v4', 
                                       timeout=self.config.timeout).text.strip().split('\n')
            return {ipaddress.ip_network(network) for network in v4_ranges}
        except Exception as e:
            logging.error(f"Error fetching Cloudflare ranges: {e}")
            return set()

    def is_cloudflare_ip(self, ip: str, cf_ranges: Set[ipaddress.IPv4Network]) -> bool:
        try:
            ip_obj = ipaddress.ip_address(ip)
            return any(ip_obj in network for network in cf_ranges)
        except ValueError:
            return False

    def scrape_url(self, url: str, parser: Callable[[str, str], Set[str]]) -> Set[str]:
        try:
            response = self.session.get(url, timeout=self.config.timeout)
            response.raise_for_status()
            return parser(response.text, self.config.ip_pattern)
        except Exception as e:
            logging.error(f"Error scraping {url}: {e}")
            return set()

    def run(self) -> None:
        cf_ranges = self.get_cloudflare_ranges()
        if not cf_ranges:
            logging.error("Failed to fetch Cloudflare ranges. Exiting.")
            return

        all_ips = set()
        with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
            results = executor.map(
                lambda url_config: self.scrape_url(url_config.url, url_config.parser),
                self.config.urls
            )
            for ips in results:
                all_ips.update(ips)

        cloudflare_ips = {ip for ip in all_ips if self.is_cloudflare_ip(ip, cf_ranges)}
        
        if cloudflare_ips:
            try:
                with open(self.config.output_file, 'w') as f:
                    f.write('\n'.join(sorted(cloudflare_ips)) + '\n')
                logging.info(f"Saved {len(cloudflare_ips)} Cloudflare IPs to {self.config.output_file}")
            except IOError as e:
                logging.error(f"Error writing to file: {e}")
        else:
            logging.warning("No valid Cloudflare IPs found")

def main():
    config = Config(
        urls=[
            URLConfig(url="https://ip.164746.xyz/ipTop10.html", parser=parse_comma_separated_ips),
            URLConfig(url="https://cf.090227.xyz", parser=parse_table_ips)
        ],
        output_file='ip.txt'
    )
    
    scraper = CloudflareIPScraper(config)
    scraper.run()

if __name__ == "__main__":
    main()