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

if __name__ == "__main__":
    # Support both authentication methods
    auth_params = {}
    if os.getenv('CF_API_TOKEN'):
        auth_params['api_token'] = os.getenv('CF_API_TOKEN')
    else:
        auth_params['email'] = os.getenv('CF_API_EMAIL')
        auth_params['api_key'] = os.getenv('CF_API_KEY')
    
    zone_name = os.getenv('CF_ZONE_NAME')
    
    subdomain_ip_mapping = {
        'bestcf.chore': 'https://raw.githubusercontent.com/killbus/youxuanyuming/refs/heads/data/ip.txt',
    }
    
    try:
        zone_id, domain = get_cloudflare_zone(auth_params, zone_name)
        
        for subdomain, url in subdomain_ip_mapping.items():
            ip_list = get_ip_list(url)
            delete_existing_dns_records(auth_params, zone_id, subdomain, domain)
            update_cloudflare_dns(auth_params, ip_list, zone_id, subdomain, domain)
            
    except Exception as e:
        print(f"Error: {e}")
