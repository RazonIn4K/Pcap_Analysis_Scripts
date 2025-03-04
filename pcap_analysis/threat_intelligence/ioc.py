#!/usr/bin/env python3
import os
import json
import yaml
import requests
from datetime import datetime

def load_iocs_from_file(ioc_file):
    """Load indicators of compromise from a file (JSON or YAML)"""
    if not os.path.exists(ioc_file):
        print(f"Error: IOC file {ioc_file} not found")
        return None
        
    try:
        file_ext = os.path.splitext(ioc_file)[1].lower()
        
        if file_ext == '.json':
            with open(ioc_file, 'r') as f:
                iocs = json.load(f)
        elif file_ext in ['.yaml', '.yml']:
            with open(ioc_file, 'r') as f:
                iocs = yaml.safe_load(f)
        else:
            print(f"Error: Unsupported file format {file_ext}")
            return None
            
        # Validate IOC structure
        if not isinstance(iocs, dict):
            print("Error: IOC file must contain a JSON/YAML object")
            return None
            
        # Check for required fields
        required_fields = ['ip_addresses', 'domains', 'hashes']
        for field in required_fields:
            if field not in iocs:
                print(f"Warning: IOC file missing '{field}' field")
                iocs[field] = []
                
        return iocs
        
    except (json.JSONDecodeError, yaml.YAMLError) as e:
        print(f"Error parsing IOC file: {str(e)}")
        return None
    except Exception as e:
        print(f"Error loading IOC file: {str(e)}")
        return None

def save_iocs_to_file(iocs, output_file):
    """Save indicators of compromise to a file (JSON or YAML)"""
    try:
        file_ext = os.path.splitext(output_file)[1].lower()
        
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)
        
        if file_ext == '.json':
            with open(output_file, 'w') as f:
                json.dump(iocs, f, indent=4)
        elif file_ext in ['.yaml', '.yml']:
            with open(output_file, 'w') as f:
                yaml.dump(iocs, f, default_flow_style=False)
        else:
            print(f"Error: Unsupported file format {file_ext}")
            return False
            
        print(f"IOCs successfully saved to {output_file}")
        return True
        
    except Exception as e:
        print(f"Error saving IOC file: {str(e)}")
        return False

def fetch_iocs_from_api(api_url, api_key=None):
    """Fetch indicators of compromise from a threat intelligence API"""
    try:
        headers = {}
        if api_key:
            headers['Authorization'] = f'Bearer {api_key}'
            
        response = requests.get(api_url, headers=headers, timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            
            # Process and format the data into our IOC structure
            iocs = {
                'ip_addresses': [],
                'domains': [],
                'hashes': [],
                'metadata': {
                    'source': api_url,
                    'timestamp': datetime.now().isoformat()
                }
            }
            
            # This part depends on the API's response format
            # Adjust according to the specific API being used
            if 'indicators' in data:
                for indicator in data['indicators']:
                    if indicator.get('type') == 'ip':
                        iocs['ip_addresses'].append(indicator.get('value'))
                    elif indicator.get('type') == 'domain':
                        iocs['domains'].append(indicator.get('value'))
                    elif indicator.get('type') in ['md5', 'sha1', 'sha256']:
                        iocs['hashes'].append(indicator.get('value'))
            
            return iocs
        else:
            print(f"API request failed with status code {response.status_code}")
            return None
            
    except requests.exceptions.RequestException as e:
        print(f"Error fetching IOCs from API: {str(e)}")
        return None
    except json.JSONDecodeError:
        print("Error parsing API response as JSON")
        return None
    except Exception as e:
        print(f"Unexpected error fetching IOCs: {str(e)}")
        return None

def merge_ioc_sources(ioc_sources):
    """Merge multiple IOC sources into a single consolidated set"""
    if not ioc_sources:
        return None
        
    merged_iocs = {
        'ip_addresses': [],
        'domains': [],
        'hashes': [],
        'metadata': {
            'sources': [],
            'timestamp': datetime.now().isoformat()
        }
    }
    
    for source in ioc_sources:
        if not source:
            continue
            
        # Add unique IPs
        for ip in source.get('ip_addresses', []):
            if ip and ip not in merged_iocs['ip_addresses']:
                merged_iocs['ip_addresses'].append(ip)
                
        # Add unique domains
        for domain in source.get('domains', []):
            if domain and domain not in merged_iocs['domains']:
                merged_iocs['domains'].append(domain)
                
        # Add unique hashes
        for hash_value in source.get('hashes', []):
            if hash_value and hash_value not in merged_iocs['hashes']:
                merged_iocs['hashes'].append(hash_value)
                
        # Track source metadata
        if 'metadata' in source and 'source' in source['metadata']:
            merged_iocs['metadata']['sources'].append(source['metadata']['source'])
    
    # Add counts to metadata
    merged_iocs['metadata']['counts'] = {
        'ip_addresses': len(merged_iocs['ip_addresses']),
        'domains': len(merged_iocs['domains']),
        'hashes': len(merged_iocs['hashes'])
    }
    
    return merged_iocs

def extract_iocs_from_pcap(pcap_file, output_file=None):
    """Extract potential indicators of compromise from a PCAP file"""
    # This function would use tshark to extract potential IOCs
    # Implementation depends on specific requirements
    # For now, this is a placeholder
    print("IOC extraction from PCAP not yet implemented")
    return None 