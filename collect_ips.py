from collections.abc import Callable
import requests
from bs4 import BeautifulSoup
import re
import os
import ipaddress
import logging
import tempfile
import subprocess
from typing import List, Set
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor
from requests.adapters import HTTPAdapter
from urllib3.util import Retry
from enum import Enum, auto

class IPVersion(Enum):
    ALL = auto()
    IPV4 = auto()
    IPV6 = auto()
    
    @classmethod
    def from_string(cls, value: str) -> 'IPVersion':
        """从字符串转换为枚举值，无效值返回 ALL"""
        try:
            return {
                'all': cls.ALL,
                'ipv4': cls.IPV4,
                'ipv6': cls.IPV6
            }[value.lower()]
        except KeyError:
            return cls.ALL

@dataclass
class URLConfig:
    url: str
    parser: Callable[[str, str], Set[str]]

@dataclass
class Config:
    urls: List[URLConfig]
    output_file: str
    ipv4_pattern: str = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    ipv6_pattern: str = r'(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}'
    timeout: int = 10
    max_workers: int = 3
    v2dat_version: str = "20240712"
    ip_version: IPVersion = IPVersion.from_string(os.getenv('IP_VERSION', 'all'))

    def should_include_ipv4(self) -> bool:
        """是否应该包含 IPv4 地址"""
        return self.ip_version in (IPVersion.ALL, IPVersion.IPV4)
    
    def should_include_ipv6(self) -> bool:
        """是否应该包含 IPv6 地址"""
        return self.ip_version in (IPVersion.ALL, IPVersion.IPV6)

def parse_table_ips(html: str, ip_pattern: str) -> Set[str]:
    """解析 HTML 表格中的 IP 地址."""
    soup = BeautifulSoup(html, 'html.parser')
    elements = soup.find_all('tr')
    ips = set()
    for element in elements:
        element_text = element.get_text()
        ips.update(re.findall(ip_pattern, element_text))
    return ips

def parse_comma_separated_ips(text: str, ip_pattern: str) -> Set[str]:
    """解析逗号分隔的 IP 地址."""
    return set(re.findall(ip_pattern, text))

def parse_geoip_dat_file(filepath: str) -> Set[str]:
    """解析 geoip.dat 文件中的 IP 地址."""
    try:
        with open(filepath, 'r') as f:
            lines = {line.strip() for line in f if line.strip()}
            
            if Config.ip_version == IPVersion.IPV4:
                return {line for line in lines if ':' not in line}
            elif Config.ip_version == IPVersion.IPV6:
                return {line for line in lines if ':' in line}
            return lines
            
    except Exception as e:
        logging.error(f"Error parsing geoip dat file: {e}")
        return set()

class CloudflareIPScraper:
    def __init__(self, config: Config):
        self.config = config
        self.session = self._setup_session()
        self._setup_logging()
        self.temp_dir = tempfile.mkdtemp()
        
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

    def _download_file(self, url: str, output_path: str) -> bool:
        try:
            response = self.session.get(url, timeout=self.config.timeout)
            response.raise_for_status()
            with open(output_path, 'wb') as f:
                f.write(response.content)
            return True
        except Exception as e:
            logging.error(f"Error downloading {url}: {e}")
            return False

    def get_v2dat_cloudflare_ips(self) -> Set[str]:
        """从 geoip.dat 获取 Cloudflare IP 范围."""
        try:
            # 下载所需文件
            v2dat_url = f"https://github.com/m0xbf/v2dat/releases/download/v{self.config.v2dat_version}/v2dat_{self.config.v2dat_version}_amd64"
            geoip_url = "https://github.com/Loyalsoldier/geoip/raw/release/geoip.dat"
            
            v2dat_path = os.path.join(self.temp_dir, "v2dat")
            geoip_path = os.path.join(self.temp_dir, "geoip.dat")
            output_dir = os.path.join(self.temp_dir, "rules")
            os.makedirs(output_dir, exist_ok=True)

            if not all([
                self._download_file(v2dat_url, v2dat_path),
                self._download_file(geoip_url, geoip_path)
            ]):
                return set()

            # 设置执行权限
            os.chmod(v2dat_path, 0o755)

            # 解包 geoip.dat
            result = subprocess.run(
                [v2dat_path, "unpack", "geoip", "-o", output_dir, "-f", "cloudflare", geoip_path],
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                logging.error(f"v2dat execution failed: {result.stderr}")
                return set()

            # 解析结果文件
            cloudflare_file = os.path.join(output_dir, "geoip_cloudflare.txt")
            return parse_geoip_dat_file(cloudflare_file)

        except Exception as e:
            logging.error(f"Error in get_v2dat_cloudflare_ips: {e}")
            return set()
        finally:
            # 清理临时文件
            try:
                import shutil
                shutil.rmtree(self.temp_dir)
            except Exception as e:
                logging.error(f"Error cleaning up temporary files: {e}")

    def get_cloudflare_ranges(self) -> Set[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        """获取所有 Cloudflare IP 范围."""
        try:
            cf_ranges = set()
            
            # 获取 IPv4 范围
            if self.config.should_include_ipv4():
                v4_ranges = self.session.get('https://www.cloudflare.com/ips-v4', 
                                           timeout=self.config.timeout).text.strip().split('\n')
                for network in v4_ranges:
                    try:
                        cf_ranges.add(ipaddress.ip_network(network))
                    except ValueError:
                        continue
            
            # 获取 IPv6 范围
            if self.config.should_include_ipv6():
                v6_ranges = self.session.get('https://www.cloudflare.com/ips-v6',
                                           timeout=self.config.timeout).text.strip().split('\n')
                for network in v6_ranges:
                    try:
                        cf_ranges.add(ipaddress.ip_network(network))
                    except ValueError:
                        continue
            
            # 从 geoip.dat 获取额外的范围
            v2dat_ips = self.get_v2dat_cloudflare_ips()
            for ip_range in v2dat_ips:
                try:
                    network = ipaddress.ip_network(ip_range)
                    if ((self.config.ip_version == IPVersion.IPV4 and isinstance(network, ipaddress.IPv4Network)) or
                        (self.config.ip_version == IPVersion.IPV6 and isinstance(network, ipaddress.IPv6Network)) or
                        self.config.ip_version == IPVersion.ALL):
                        cf_ranges.add(network)
                except ValueError:
                    continue
                    
            return cf_ranges
        except Exception as e:
            logging.error(f"Error fetching Cloudflare ranges: {e}")
            return set()

    def is_cloudflare_ip(self, ip: str, cf_ranges: Set[ipaddress.IPv4Network | ipaddress.IPv6Network]) -> bool:
        try:
            ip_obj = ipaddress.ip_address(ip)
            return any(ip_obj in network for network in cf_ranges)
        except ValueError:
            return False

    def scrape_url(self, url: str, parser: Callable[[str, str], Set[str]]) -> Set[str]:
        try:
            response = self.session.get(url, timeout=self.config.timeout)
            response.raise_for_status()
            ips = set()
            if self.config.should_include_ipv4():
                ips.update(parser(response.text, self.config.ipv4_pattern))
            if self.config.should_include_ipv6():
                ips.update(parser(response.text, self.config.ipv6_pattern))
            return ips
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
        output_file='ip.txt',
        ip_version=IPVersion.from_string(os.getenv('IP_VERSION', 'all'))
    )
    
    scraper = CloudflareIPScraper(config)
    scraper.run()

if __name__ == "__main__":
    main()