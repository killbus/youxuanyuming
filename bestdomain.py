import os
import requests
import logging
from typing import Tuple, List

# 设置日志配置
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

def get_ip_list(url: str) -> List[str]:
    response = requests.get(url)
    response.raise_for_status()
    return response.text.strip().split('\n')

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

def delete_existing_dns_records(auth_params: dict, zone_id: str, subdomain: str, domain: str) -> None:
    headers = get_auth_headers(**auth_params)
    record_name = domain if subdomain == '@' else f'{subdomain}.{domain}'
    
    while True:
        response = requests.get(
            f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records',
            params={'type': 'A', 'name': record_name},
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
            logger.info(f"Deleted DNS record {subdomain}:{record['id']}")

def update_cloudflare_dns(auth_params: dict, ip_list: List[str], zone_id: str, subdomain: str, domain: str) -> None:
    headers = get_auth_headers(**auth_params)
    record_name = domain if subdomain == '@' else f'{subdomain}.{domain}'
    
    for ip in ip_list:
        data = {
            "type": "A",
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
            logger.info(f"Added DNS record {subdomain}:{ip}")
        else:
            logger.error(f"Failed to add A record for IP {ip} to subdomain {subdomain}: {response.status_code} {response.text}")

def batch_update_dns_records(
    auth_params: dict,
    ip_list: List[str],
    zone_id: str,
    subdomain: str,
    domain: str
) -> None:
    """Update DNS records using the batch API endpoint.
    
    Args:
        auth_params: Authentication parameters for Cloudflare API
        ip_list: List of IP addresses to set
        zone_id: Cloudflare zone ID
        subdomain: Subdomain to update (use '@' for root domain)
        domain: Domain name
        
    Notes:
        - Free plan has a limit of 200 operations per batch
        - Operations are processed asynchronously by Cloudflare
        - Uses patches for existing records to minimize propagation delay
        - Ensures no overlap between patches and deletes
    """
    headers = get_auth_headers(**auth_params)
    record_name = domain if subdomain == '@' else f'{subdomain}.{domain}'
    
    # First get existing records for processing
    response = requests.get(
        f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records',
        params={'type': 'A', 'name': record_name, 'per_page': 5000000},
        headers=headers
    )
    response.raise_for_status()
    existing_records = response.json().get('result', [])
    
    # Constants
    BATCH_LIMIT = 200
    DEFAULT_TTL = 1
    DEFAULT_PROXIED = False
    
    def create_record_data(ip: str, record_name: str, record_id: str = None) -> dict:
        """Create DNS record data with consistent defaults"""
        data = {
            "type": "A",
            "name": record_name,
            "content": ip,
            "ttl": DEFAULT_TTL,
            "proxied": DEFAULT_PROXIED
        }
        if record_id:
            data["id"] = record_id
        return data
    
    logger.info(f"\nProcessing {subdomain}:")
    logger.info(f"  Found {len(existing_records)} existing records")
    logger.info(f"  Target {len(ip_list)} IPs")
    
    # Initialize operation lists
    patches = []
    posts = []
    used_records = set()
    
    # Create maps and sets for efficient lookups
    existing_ip_map = {record["content"]: record for record in existing_records}
    existing_ips = set(existing_ip_map.keys())
    target_ips = set(ip_list)
    
    # Keep existing records that match target IPs
    for ip in target_ips.intersection(existing_ips):
        record = existing_ip_map[ip]
        used_records.add(record["id"])
        logger.debug(f"  - Keeping {ip} (already exists)")
    
    # Handle new IPs using available records or create new ones
    new_ips = target_ips - existing_ips
    available_records = [r for r in existing_records if r["id"] not in used_records]
    
    # Update existing records where possible
    patched_ips = set()
    for ip, record in zip(new_ips, available_records):
        patches.append(create_record_data(ip, record_name, record_id=record["id"]))
        used_records.add(record["id"])
        patched_ips.add(ip)
        logger.debug(f"  - Patching {record['content']} -> {ip}")
    
    # Create new records for remaining IPs
    for ip in (new_ips - patched_ips):
        posts.append(create_record_data(ip, record_name))
        print(f"  - Adding new record for {ip}")
    
    # Remove any unused records
    deletes = [{"id": record["id"]} for record in existing_records 
               if record["id"] not in used_records]
    
    total_operations = len(patches) + len(deletes) + len(posts)
    
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
            ("patches", patches),
            ("deletes", deletes),
            ("posts", posts)
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
            "patches": patches,
            "deletes": deletes,
            "posts": posts
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
            logger.info(f"  - Patched {len(patches)} records")
            logger.info(f"  - Deleted {len(deletes)} records")
            logger.info(f"  - Added {len(posts)} records")
        else:
            raise Exception(f"Batch update failed for {subdomain}: {response.status_code} {response.text}")

def update_dns_records(auth_params: dict, ip_list: List[str], zone_id: str, subdomain: str, domain: str, use_batch: bool = True) -> None:
    """Unified entry point for DNS updates. Can use either batch or individual updates based on the use_batch parameter"""
    if use_batch:
        try:
            batch_update_dns_records(auth_params, ip_list, zone_id, subdomain, domain)
        except Exception as e:
            logger.warning(f"Batch update failed, falling back to individual updates: {e}")
            delete_existing_dns_records(auth_params, zone_id, subdomain, domain)
            update_cloudflare_dns(auth_params, ip_list, zone_id, subdomain, domain)
    else:
        delete_existing_dns_records(auth_params, zone_id, subdomain, domain)
        update_cloudflare_dns(auth_params, ip_list, zone_id, subdomain, domain)


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
            ip_list = get_ip_list(url)
            update_dns_records(auth_params, ip_list, zone_id, subdomain, domain, use_batch)
            
    except Exception as e:
        logger.exception(f"Error: {e}")
