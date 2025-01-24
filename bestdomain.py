import os
import requests
from typing import Tuple, List

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
            print(f"Del {subdomain}:{record['id']}")

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
            print(f"Add {subdomain}:{ip}")
        else:
            print(f"Failed to add A record for IP {ip} to subdomain {subdomain}: {response.status_code} {response.text}")

def batch_update_dns_records(auth_params: dict, ip_list: List[str], zone_id: str, subdomain: str, domain: str) -> None:
    """Update DNS records using the batch API endpoint, respecting plan limits
    
    Free plan has a limit of 200 operations per batch (deletes + posts + etc. combined)
    """
    headers = get_auth_headers(**auth_params)
    record_name = domain if subdomain == '@' else f'{subdomain}.{domain}'
    
    # First get existing records for deletion
    response = requests.get(
        f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records',
        params={'type': 'A', 'name': record_name},
        headers=headers
    )
    response.raise_for_status()
    existing_records = response.json().get('result', [])
    
    # Constants
    BATCH_LIMIT = 200
    total_deletes = len(existing_records)
    total_posts = len(ip_list)
    
    # If total operations exceed batch limit, we need to process in multiple batches
    if total_deletes + total_posts > BATCH_LIMIT:
        delete_index = 0
        post_index = 0
        
        while delete_index < total_deletes or post_index < total_posts:
            batch_data = {"deletes": [], "posts": []}
            operations_count = 0
            
            # Add deletes to this batch
            while delete_index < total_deletes and operations_count < BATCH_LIMIT:
                batch_data["deletes"].append({"id": existing_records[delete_index]["id"]})
                delete_index += 1
                operations_count += 1
            
            # Add posts to this batch
            while post_index < total_posts and operations_count < BATCH_LIMIT:
                batch_data["posts"].append({
                    "type": "A",
                    "name": record_name,
                    "content": ip_list[post_index],
                    "ttl": 1,
                    "proxied": False
                })
                post_index += 1
                operations_count += 1
            
            # Execute this batch
            response = requests.post(
                f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/batch',
                json=batch_data,
                headers=headers
            )
            
            if response.status_code == 200:
                print(f"Batch update successful for {subdomain}:")
                print(f"  - Deleted {len(batch_data['deletes'])} records")
                print(f"  - Added {len(batch_data['posts'])} records")
                print(f"  - Progress: {delete_index}/{total_deletes} deletes, {post_index}/{total_posts} posts")
            else:
                raise Exception(f"Batch update failed for {subdomain}: {response.status_code} {response.text}")
    else:
        # All operations can fit in a single batch
        batch_data = {
            "deletes": [{"id": record["id"]} for record in existing_records],
            "posts": [
                {
                    "type": "A",
                    "name": record_name,
                    "content": ip,
                    "ttl": 1,
                    "proxied": False
                }
                for ip in ip_list
            ]
        }
        
        response = requests.post(
            f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/batch',
            json=batch_data,
            headers=headers
        )
        
        if response.status_code == 200:
            print(f"Batch update successful for {subdomain}:")
            print(f"  - Deleted {len(batch_data['deletes'])} records")
            print(f"  - Added {len(batch_data['posts'])} records")
        else:
            raise Exception(f"Batch update failed for {subdomain}: {response.status_code} {response.text}")

def update_dns_records(auth_params: dict, ip_list: List[str], zone_id: str, subdomain: str, domain: str, use_batch: bool = True) -> None:
    """Unified entry point for DNS updates. Can use either batch or individual updates based on the use_batch parameter"""
    if use_batch:
        try:
            batch_update_dns_records(auth_params, ip_list, zone_id, subdomain, domain)
        except Exception as e:
            print(f"Batch update failed, falling back to individual updates: {e}")
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
        print(f"Error: {e}")
