import os
import requests
import logging
from typing import Tuple, List
from enum import Enum, auto

# 设置日志配置
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

class DNSRecordType(Enum):
    ALL = auto()
    A_ONLY = auto()
    AAAA_ONLY = auto()
    
    @classmethod
    def from_string(cls, value: str) -> 'DNSRecordType':
        """从字符串转换为枚举值，无效值返回 ALL"""
        try:
            return {
                'all': cls.ALL,
                'a': cls.A_ONLY,
                'ipv4': cls.A_ONLY,
                'aaaa': cls.AAAA_ONLY,
                'ipv6': cls.AAAA_ONLY
            }[value.lower()]
        except KeyError:
            return cls.ALL

def get_ip_list(url: str, record_type: DNSRecordType) -> Tuple[List[str], List[str]]:
    """获取 IP 列表，返回 (ipv4_list, ipv6_list)"""
    response = requests.get(url)
    response.raise_for_status()
    
    ip_list = response.text.strip().split('\n')
    ipv4_list = [ip for ip in ip_list if ':' not in ip]
    ipv6_list = [ip for ip in ip_list if ':' in ip]
    
    # 根据记录类型过滤
    if record_type == DNSRecordType.A_ONLY:
        ipv6_list = []
    elif record_type == DNSRecordType.AAAA_ONLY:
        ipv4_list = []
    
    return ipv4_list, ipv6_list

def get_auth_headers(api_token: str = None, email: str = None, api_key: str = None) -> dict:
    if api_token:
        return {
            'Authorization': f'Bearer {api_token}',
            'Content-Type': 'application/json',
        }
    return {
        'X-Auth-Email': email,
        'X-Auth-Key': api_key,
        'Content-Type': 'application/json',
    }

def get_cloudflare_zone(auth_params: dict, zone_name: str = None) -> Tuple[str, str]:
    headers = get_auth_headers(**auth_params)
    response = requests.get(
        'https://api.cloudflare.com/client/v4/zones',
        params={'name': zone_name, 'status': 'active', 'page': 1, 'per_page': 1},
        headers=headers
    )
    response.raise_for_status()
    zones = response.json().get('result', [])
    if not zones:
        raise Exception("No zones found")
    return zones[0]['id'], zones[0]['name']

def delete_existing_dns_records(auth_params: dict, zone_id: str, subdomain: str, domain: str, record_type: DNSRecordType = DNSRecordType.ALL) -> None:
    """删除现有的 DNS 记录"""
    headers = get_auth_headers(**auth_params)
    record_name = domain if subdomain == '@' else f'{subdomain}.{domain}'
    
    # 确定需要删除的记录类型
    record_types = []
    if record_type in [DNSRecordType.ALL, DNSRecordType.A_ONLY]:
        record_types.append("A")
    if record_type in [DNSRecordType.ALL, DNSRecordType.AAAA_ONLY]:
        record_types.append("AAAA")
    
    for dns_type in record_types:
        while True:
            response = requests.get(
                f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records',
                params={'type': dns_type, 'name': record_name},
                headers=headers
            )
            response.raise_for_status()
            records = response.json().get('result', [])
            if not records:
                break
                
            for record in records:
                delete_response = requests.delete(
                    f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record["id"]}',
                    headers=headers
                )
                delete_response.raise_for_status()
                logger.info(f"Deleted DNS record {subdomain}:{record['id']} ({dns_type})")

def update_cloudflare_dns(auth_params: dict, ip_lists: Tuple[List[str], List[str]], zone_id: str, subdomain: str, domain: str, record_type: DNSRecordType = DNSRecordType.ALL) -> None:
    """更新 DNS 记录"""
    headers = get_auth_headers(**auth_params)
    record_name = domain if subdomain == '@' else f'{subdomain}.{domain}'
    ipv4_list, ipv6_list = ip_lists
    
    def add_records(ips: List[str], dns_type: str) -> None:
        for ip in ips:
            data = {
                "type": dns_type,
                "name": record_name,
                "content": ip,
                "ttl": 1,
                "proxied": False
            }
            response = requests.post(
                f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records',
                json=data,
                headers=headers
            )
            if response.status_code == 200:
                logger.info(f"Added DNS record {subdomain}:{ip} ({dns_type})")
            else:
                logger.error(f"Failed to add {dns_type} record for IP {ip} to subdomain {subdomain}: {response.status_code} {response.text}")
    
    # 根据记录类型添加相应的记录
    if record_type in [DNSRecordType.ALL, DNSRecordType.A_ONLY]:
        add_records(ipv4_list, "A")
    if record_type in [DNSRecordType.ALL, DNSRecordType.AAAA_ONLY]:
        add_records(ipv6_list, "AAAA")

def batch_update_dns_records(
    auth_params: dict,
    ip_lists: Tuple[List[str], List[str]],
    zone_id: str,
    subdomain: str,
    domain: str,
    record_type: DNSRecordType
) -> None:
    """Update DNS records using the batch API endpoint."""
    headers = get_auth_headers(**auth_params)
    record_name = domain if subdomain == '@' else f'{subdomain}.{domain}'
    ipv4_list, ipv6_list = ip_lists
    
    # Constants
    BATCH_LIMIT = 200
    DEFAULT_TTL = 1
    DEFAULT_PROXIED = False
    
    def create_record_data(ip: str, record_name: str, record_id: str = None) -> dict:
        """Create DNS record data with consistent defaults"""
        record_type = "A" if ':' not in ip else "AAAA"
        data = {
            "type": record_type,
            "name": record_name,
            "content": ip,
            "ttl": DEFAULT_TTL,
            "proxied": DEFAULT_PROXIED
        }
        if record_id:
            data["id"] = record_id
        return data
    
    def process_ip_type(ip_list: List[str], record_type: str) -> Tuple[List[dict], List[dict], List[dict]]:
        """处理特定类型的 IP 地址记录"""
        # 获取现有记录
        response = requests.get(
            f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records',
            params={'type': record_type, 'name': record_name, 'per_page': 5000000},
            headers=headers
        )
        response.raise_for_status()
        existing_records = response.json().get('result', [])
        
        logger.info(f"\nProcessing {subdomain} {record_type} records:")
        logger.info(f"  Found {len(existing_records)} existing records")
        logger.info(f"  Target {len(ip_list)} IPs")
        
        patches = []
        posts = []
        used_records = set()
        
        existing_ip_map = {record["content"]: record for record in existing_records}
        existing_ips = set(existing_ip_map.keys())
        target_ips = set(ip_list)
        
        # 保留匹配的记录
        for ip in target_ips.intersection(existing_ips):
            record = existing_ip_map[ip]
            used_records.add(record["id"])
            logger.debug(f"  - Keeping {ip} (already exists)")
        
        # 处理新的 IP
        new_ips = target_ips - existing_ips
        available_records = [r for r in existing_records if r["id"] not in used_records]
        
        # 更新现有记录
        patched_ips = set()
        for ip, record in zip(new_ips, available_records):
            patches.append(create_record_data(ip, record_name, record_id=record["id"]))
            used_records.add(record["id"])
            patched_ips.add(ip)
            logger.debug(f"  - Patching {record['content']} -> {ip}")
        
        # 创建新记录
        for ip in (new_ips - patched_ips):
            posts.append(create_record_data(ip, record_name))
            logger.info(f"  - Adding new record for {ip}")
        
        # 删除未使用的记录
        deletes = [{"id": record["id"]} for record in existing_records 
                  if record["id"] not in used_records]
        
        return patches, posts, deletes
    
    # 处理 IPv4 和 IPv6 记录
    ipv4_patches, ipv4_posts, ipv4_deletes = ([], [], [])
    ipv6_patches, ipv6_posts, ipv6_deletes = ([], [], [])
    
    if record_type in [DNSRecordType.ALL, DNSRecordType.A_ONLY]:
        ipv4_patches, ipv4_posts, ipv4_deletes = process_ip_type(ipv4_list, "A")
        
    if record_type in [DNSRecordType.ALL, DNSRecordType.AAAA_ONLY]:
        ipv6_patches, ipv6_posts, ipv6_deletes = process_ip_type(ipv6_list, "AAAA")
    
    # 合并所有操作
    all_patches = ipv4_patches + ipv6_patches
    all_posts = ipv4_posts + ipv6_posts
    all_deletes = ipv4_deletes + ipv6_deletes
    
    total_operations = len(all_patches) + len(all_deletes) + len(all_posts)
    
    def process_batch(operations: list, batch_data: dict, operation_type: str, limit: int) -> tuple:
        """Process a batch of operations, returns (processed_count, operations_added)"""
        count = 0
        while operations and count < len(operations) and len(batch_data.get(operation_type, [])) < limit:
            batch_data.setdefault(operation_type, []).append(operations[count])
            count += 1
        return count

    # Process in batches if total operations exceed the limit
    if total_operations > BATCH_LIMIT:
        operation_types = [
            ("patches", all_patches),
            ("deletes", all_deletes),
            ("posts", all_posts)
        ]
        
        # Process all operations in batches of up to BATCH_LIMIT operations
        while any(ops for _, ops in operation_types):
            batch_data = {}  # Single batch containing multiple operation types
            remaining_limit = BATCH_LIMIT
            
            for op_type, ops in operation_types:
                if ops:
                    processed = process_batch(ops, batch_data, op_type, remaining_limit)
                    ops[:processed] = []  # Remove processed operations
                    remaining_limit -= processed

            # Execute this batch
            response = requests.post(
                f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/batch',
                json=batch_data,
                headers=headers
            )
            
            if response.status_code == 200:
                logger.info(f"Batch update successful for {subdomain}:")
                logger.info(f"  - Patched {len(batch_data['patches']) if 'patches' in batch_data else 0} records")
                logger.info(f"  - Deleted {len(batch_data['deletes']) if 'deletes' in batch_data else 0} records")
                logger.info(f"  - Added {len(batch_data['posts']) if 'posts' in batch_data else 0} records")
            else:
                raise Exception(f"Batch update failed for {subdomain}: {response.status_code} {response.text}")
    else:
        # All operations can fit in a single batch
        batch_data = {
            "patches": all_patches,
            "deletes": all_deletes,
            "posts": all_posts
        }
        batch_data = {k: v for k, v in batch_data.items() if v}
        
        if not batch_data:
            print(f"No operations to perform for {subdomain}")
            return

        response = requests.post(
            f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/batch',
            json=batch_data,
            headers=headers
        )
        
        if response.status_code == 200:
            logger.info(f"Batch update successful for {subdomain}:")
            logger.info(f"  - Patched {len(all_patches)} records")
            logger.info(f"  - Deleted {len(all_deletes)} records")
            logger.info(f"  - Added {len(all_posts)} records")
        else:
            raise Exception(f"Batch update failed for {subdomain}: {response.status_code} {response.text}")

def update_dns_records(
    auth_params: dict, 
    ip_lists: Tuple[List[str], List[str]], 
    zone_id: str, 
    subdomain: str, 
    domain: str, 
    use_batch: bool = True,
    record_type: DNSRecordType = DNSRecordType.ALL
) -> None:
    """Unified entry point for DNS updates."""
    if use_batch:
        try:
            batch_update_dns_records(auth_params, ip_lists, zone_id, subdomain, domain, record_type)
        except Exception as e:
            logger.warning(f"Batch update failed, falling back to individual updates: {e}")
            delete_existing_dns_records(auth_params, zone_id, subdomain, domain, record_type)
            update_cloudflare_dns(auth_params, ip_lists, zone_id, subdomain, domain, record_type)
    else:
        delete_existing_dns_records(auth_params, zone_id, subdomain, domain, record_type)
        update_cloudflare_dns(auth_params, ip_lists, zone_id, subdomain, domain, record_type)

if __name__ == "__main__":
    # Support both authentication methods
    auth_params = {}
    if os.getenv('CF_API_TOKEN'):
        auth_params['api_token'] = os.getenv('CF_API_TOKEN')
    else:
        auth_params['email'] = os.getenv('CF_API_EMAIL')
        auth_params['api_key'] = os.getenv('CF_API_KEY')
    
    zone_name = os.getenv('CF_ZONE_NAME')
    use_batch = os.getenv('USE_BATCH', 'true').lower() == 'true'
    record_type = DNSRecordType.from_string(os.getenv('DNS_RECORD_TYPE', 'all'))
    
    logger.info(f"DNS record type set to: {record_type.name}")
    
    subdomain_ip_mapping = {
        'bestcf.chore': 'https://raw.githubusercontent.com/killbus/youxuanyuming/refs/heads/data/ip.txt',
    }
    subdomain_ip_mapping_env = os.getenv('SUBDOMAIN_IP_MAPPING')
    if subdomain_ip_mapping_env:
        mappings = subdomain_ip_mapping_env.strip().split('\n')
        subdomain_ip_mapping.update({subdomain: url for mapping in mappings for subdomain, url in [mapping.split(',')]})

    try:
        zone_id, domain = get_cloudflare_zone(auth_params, zone_name)

        for subdomain, url in subdomain_ip_mapping.items():
            ipv4_list, ipv6_list = get_ip_list(url, record_type)
            # 限制每种类型的 IP 数量
            ipv4_list = ipv4_list[:10]
            ipv6_list = ipv6_list[:10]
            update_dns_records(
                auth_params, 
                (ipv4_list, ipv6_list), 
                zone_id, 
                subdomain, 
                domain, 
                use_batch,
                record_type
            )
            
    except Exception as e:
        logger.exception(f"Error: {e}")
