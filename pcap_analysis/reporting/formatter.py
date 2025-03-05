#!/usr/bin/env python3
import os
import json
import csv
import yaml
from datetime import datetime
import matplotlib.pyplot as plt
import numpy as np

def format_json(results, output_file=None, pretty=True):
    """Format analysis results as JSON"""
    # Convert any non-serializable objects to strings
    def json_serializer(obj):
        if hasattr(obj, 'isoformat'):
            return obj.isoformat()
        return str(obj)
    
    # Format the JSON
    if pretty:
        json_data = json.dumps(results, indent=4, default=json_serializer)
    else:
        json_data = json.dumps(results, default=json_serializer)
    
    # Write to file if specified
    if output_file:
        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)
            
            with open(output_file, 'w') as f:
                f.write(json_data)
            print(f"Results saved to {output_file}")
        except Exception as e:
            print(f"Error saving JSON results: {str(e)}")
    
    return json_data

def format_yaml(results, output_file=None):
    """Format analysis results as YAML"""
    try:
        # Convert results to YAML
        yaml_data = yaml.dump(results, default_flow_style=False)
        
        # Write to file if specified
        if output_file:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)
            
            with open(output_file, 'w') as f:
                f.write(yaml_data)
            print(f"Results saved to {output_file}")
        
        return yaml_data
    except Exception as e:
        print(f"Error formatting results as YAML: {str(e)}")
        return None

def format_csv(results, output_file=None):
    """Format analysis results as CSV"""
    try:
        # Flatten nested results for CSV format
        flattened_data = []
        
        def flatten_dict(d, parent_key=''):
            items = []
            for k, v in d.items():
                new_key = f"{parent_key}.{k}" if parent_key else k
                if isinstance(v, dict):
                    items.extend(flatten_dict(v, new_key).items())
                elif isinstance(v, list):
                    # Convert lists to comma-separated strings
                    items.append((new_key, ','.join(str(x) for x in v)))
                else:
                    items.append((new_key, v))
            return dict(items)
        
        # Process each section of results
        for section, data in results.items():
            if isinstance(data, dict):
                flat_data = flatten_dict(data)
                flat_data['section'] = section
                flattened_data.append(flat_data)
            elif isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        flat_data = flatten_dict(item)
                        flat_data['section'] = section
                        flattened_data.append(flat_data)
        
        # Write to CSV file
        if output_file and flattened_data:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)
            
            # Get all possible fields
            fieldnames = set()
            for item in flattened_data:
                fieldnames.update(item.keys())
            
            with open(output_file, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=sorted(fieldnames))
                writer.writeheader()
                writer.writerows(flattened_data)
            
            print(f"Results saved to {output_file}")
            
        return flattened_data
    except Exception as e:
        print(f"Error formatting results as CSV: {str(e)}")
        return None

def generate_visualizations(results, output_dir):
    """Generate visualizations from analysis results"""
    try:
        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)
        
        # Track generated visualizations
        visualizations = []
        
        # Traffic volume over time (if available)
        if 'traffic_stats' in results and 'time_series' in results['traffic_stats']:
            time_data = results['traffic_stats']['time_series']
            if time_data:
                plt.figure(figsize=(12, 6))
                times = [item.get('time', i) for i, item in enumerate(time_data)]
                packets = [item.get('packets', 0) for item in time_data]
                
                plt.plot(times, packets)
                plt.title('Traffic Volume Over Time')
                plt.xlabel('Time')
                plt.ylabel('Packet Count')
                plt.grid(True)
                plt.xticks(rotation=45)
                plt.tight_layout()
                
                # Save the figure
                output_file = os.path.join(output_dir, 'traffic_volume.png')
                plt.savefig(output_file)
                plt.close()
                visualizations.append(output_file)
        
        # Protocol distribution (if available)
        if 'protocol_stats' in results and isinstance(results['protocol_stats'], dict):
            protocols = results['protocol_stats']
            if protocols:
                plt.figure(figsize=(10, 8))
                
                # Extract protocol names and counts
                labels = list(protocols.keys())
                sizes = list(protocols.values())
                
                # Sort by size
                sorted_data = sorted(zip(labels, sizes), key=lambda x: x[1], reverse=True)
                labels = [x[0] for x in sorted_data]
                sizes = [x[1] for x in sorted_data]
                
                # Limit to top 10 protocols
                if len(labels) > 10:
                    other_sum = sum(sizes[10:])
                    labels = labels[:10] + ['Other']
                    sizes = sizes[:10] + [other_sum]
                
                plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90)
                plt.axis('equal')
                plt.title('Protocol Distribution')
                plt.tight_layout()
                
                # Save the figure
                output_file = os.path.join(output_dir, 'protocol_distribution.png')
                plt.savefig(output_file)
                plt.close()
                visualizations.append(output_file)
        
        # Top talkers (if available)
        if 'top_talkers' in results and isinstance(results['top_talkers'], dict):
            talkers = results['top_talkers']
            if talkers:
                plt.figure(figsize=(12, 8))
                
                # Extract IP addresses and packet counts
                ips = list(talkers.keys())[:15]  # Limit to top 15
                counts = [talkers[ip] for ip in ips]
                
                # Sort by count
                sorted_data = sorted(zip(ips, counts), key=lambda x: x[1])
                ips = [x[0] for x in sorted_data]
                counts = [x[1] for x in sorted_data]
                
                plt.barh(ips, counts)
                plt.title('Top Talkers')
                plt.xlabel('Packet Count')
                plt.ylabel('IP Address')
                plt.grid(True, axis='x')
                plt.tight_layout()
                
                # Save the figure
                output_file = os.path.join(output_dir, 'top_talkers.png')
                plt.savefig(output_file)
                plt.close()
                visualizations.append(output_file)
        
        # Packet size distribution visualization
        if 'packet_size_distribution' in results and isinstance(results['packet_size_distribution'], dict):
            size_dist = results['packet_size_distribution']
            if size_dist:
                plt.figure(figsize=(10, 6))
                categories = list(size_dist.keys())
                counts = list(size_dist.values())

                plt.bar(categories, counts, color='skyblue')
                plt.title('Packet Size Distribution')
                plt.xlabel('Packet Size Category')
                plt.ylabel('Number of Packets')
                plt.xticks(rotation=45, ha='right')
                plt.tight_layout()

                # Save the figure
                output_file = os.path.join(output_dir, 'packet_size_distribution_bar.png')
                plt.savefig(output_file)
                plt.close()
                visualizations.append(output_file)
        
        return visualizations
    except Exception as e:
        print(f"Error generating visualizations: {str(e)}")
        return []

def generate_html_report(results, output_file, visualizations=None, title="PCAP Analysis Report"):
    """Generate an HTML report from analysis results"""
    try:
        # Create basic HTML structure
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; color: #333; }}
        h1, h2, h3 {{ color: #2c3e50; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .section {{ margin-bottom: 30px; border: 1px solid #ddd; padding: 20px; border-radius: 5px; }}
        .alert {{ background-color: #f8d7da; color: #721c24; padding: 10px; border-radius: 5px; margin-bottom: 10px; }}
        .warning {{ background-color: #fff3cd; color: #856404; padding: 10px; border-radius: 5px; margin-bottom: 10px; }}
        .info {{ background-color: #d1ecf1; color: #0c5460; padding: 10px; border-radius: 5px; margin-bottom: 10px; }}
        table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        tr:nth-child(even) {{ background-color: #f9f9f9; }}
        .timestamp {{ color: #6c757d; font-size: 0.9em; }}
        pre {{ background-color: #f8f9fa; padding: 10px; border-radius: 5px; overflow-x: auto; }}
        .visualizations {{ display: flex; flex-wrap: wrap; justify-content: space-around; }}
        .chart {{ margin: 15px; max-width: 100%; }}
        .chart img {{ max-width: 100%; height: auto; border: 1px solid #ddd; border-radius: 5px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>{title}</h1>
        <p class="timestamp">Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        
        <div class="section">
            <h2>Security Summary</h2>
            <div id="severity-chart">
                <canvas id="severityChart" width="400" height="200"></canvas>
            </div>
        </div>

        <div class="section">
            <h2>Visualizations</h2>
            <div id="visualizations-section"></div>
        </div>
"""
        
        # Add each section of results
        for section, data in results.items():
            html += f'<div class="section">\n'
            html += f'<h2>{section.replace("_", " ").title()}</h2>\n'
            
            if section == 'network_attacks' and 'correlated_attacks' in data:  # Special formatting for correlated_attacks
                correlated_attacks = data['correlated_attacks']
                if correlated_attacks:
                    html += '<div class="subsection">\n'
                    html += '<h3>Correlated Attack Sources</h3>\n'
                    
                    # Check if we have the new format with ip_attack_types
                    ip_attack_types = correlated_attacks.get('ip_attack_types', {})
                    correlation = correlated_attacks.get('correlation', "")
                    
                    # Format the correlation data
                    lines = correlation.strip().split('\n') if isinstance(correlation, str) else []
                    
                    if lines and lines[0].strip():
                        html += '<table>\n<tr><th>Count</th><th>IP Address</th><th>Attack Types</th></tr>\n'
                        for line in lines:
                            parts = line.split()
                            if len(parts) >= 2:
                                count = parts[0]
                                ip_address = parts[1]
                                
                                # Get attack types for this IP if available
                                attack_types_str = ""
                                if ip_address in ip_attack_types:
                                    attacks = []
                                    for attack_type, attack_count in ip_attack_types[ip_address].items():
                                        if attack_count > 0:
                                            attacks.append(f"{attack_type}: {attack_count}")
                                    attack_types_str = ", ".join(attacks) if attacks else "Unknown"
                                else:
                                    attack_types_str = "Multiple attack types detected"  # Default if not found
                                
                                html += f'<tr><td>{count}</td><td>{ip_address}</td><td>{attack_types_str}</td></tr>\n'
                        html += '</table>\n'
                    else:
                        html += "<p>No correlated attack sources found.</p>\n"
                    
                    html += '</div>\n'
                
                # Continue with other network attack sections
                for subsection, subdata in data.items():
                    if subsection != 'correlated_attacks':
                        html += f'<div class="subsection">\n'
                        html += f'<h3>{subsection.replace("_", " ").title()}</h3>\n'
                        
                        if isinstance(subdata, dict):
                            html += '<table>\n<tr><th>Key</th><th>Value</th></tr>\n'
                            for key, value in subdata.items():
                                html += f'<tr><td>{key}</td><td>{str(value)}</td></tr>\n'
                            html += '</table>\n'
                        else:
                            html += f'<pre>{subdata}</pre>\n'
                        
                        html += '</div>\n'
            
            elif isinstance(data, dict):
                html += '<table>\n<tr><th>Key</th><th>Value</th></tr>\n'
                for key, value in data.items():
                    html += f'<tr><td>{key}</td><td>'
                    if isinstance(value, list):
                        html += '<ul>\n'
                        for item in value[:20]:  # Limit long lists to display
                            html += f'<li>{item}</li>\n'
                        if len(value) > 20:
                            html += f'<li>... and {len(value) - 20} more items</li>\n'
                        html += '</ul>\n'
                    elif isinstance(value, dict):
                        html += '<pre>' + json.dumps(value, indent=2) + '</pre>'
                    else:
                        html += str(value)
                    html += '</td></tr>\n'
                html += '</table>\n'
            elif isinstance(data, list):
                html += f'<p>{len(data)} items found</p>\n'
                if data and isinstance(data[0], dict):
                    # Get all possible keys
                    keys = set()
                    for item in data:
                        keys.update(item.keys())
                    
                    html += '<table>\n<tr>'
                    for key in sorted(keys):
                        html += f'<th>{key}</th>'
                    html += '</tr>\n'
                    
                    for item in data[:100]:  # Limit very large datasets
                        html += '<tr>'
                        for key in sorted(keys):
                            value = item.get(key, '')
                            html += f'<td>{value}</td>'
                        html += '</tr>\n'
                    html += '</table>\n'
                    
                    if len(data) > 100:
                        html += f'<p>Showing 100 of {len(data)} items</p>\n'
                else:
                    html += '<ul>\n'
                    for item in data[:100]:
                        html += f'<li>{item}</li>\n'
                    if len(data) > 100:
                        html += f'<li>... and {len(data) - 100} more items</li>\n'
                    html += '</ul>\n'
            else:
                html += f'<pre>{data}</pre>\n'
                
            html += '</div>\n'
        
        # Close HTML
        html += """    </div>
</body>
</html>"""
        
        # Write to file
        if output_file:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)
            
            with open(output_file, 'w') as f:
                f.write(html)
            print(f"HTML report saved to {output_file}")
        
        return html
    except Exception as e:
        print(f"Error generating HTML report: {str(e)}")
        return None

def generate_visualizations(results, output_dir):
    """Generate visualizations from analysis results"""
    try:
        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)
        
        # Track generated visualizations
        visualizations = []
        
        # Traffic volume over time (if available)
        if 'traffic_stats' in results and 'time_series' in results['traffic_stats']:
            time_data = results['traffic_stats']['time_series']
            if time_data:
                plt.figure(figsize=(12, 6))
                times = [item.get('time', i) for i, item in enumerate(time_data)]
                packets = [item.get('packets', 0) for item in time_data]
                
                plt.plot(times, packets)
                plt.title('Traffic Volume Over Time')
                plt.xlabel('Time')
                plt.ylabel('Packet Count')
                plt.grid(True)
                plt.xticks(rotation=45)
                plt.tight_layout()
                
                # Save the figure
                output_file = os.path.join(output_dir, 'traffic_volume.png')
                plt.savefig(output_file)
                plt.close()
                visualizations.append(output_file)
        
        # Protocol distribution (if available)
        if 'protocol_stats' in results and isinstance(results['protocol_stats'], dict):
            protocols = results['protocol_stats']
            if protocols:
                plt.figure(figsize=(10, 8))
                
                # Extract protocol names and counts
                labels = list(protocols.keys())
                sizes = list(protocols.values())
                
                # Sort by size
                sorted_data = sorted(zip(labels, sizes), key=lambda x: x[1], reverse=True)
                labels = [x[0] for x in sorted_data]
                sizes = [x[1] for x in sorted_data]
                
                # Limit to top 10 protocols
                if len(labels) > 10:
                    other_sum = sum(sizes[10:])
                    labels = labels[:10] + ['Other']
                    sizes = sizes[:10] + [other_sum]
                
                plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90)
                plt.axis('equal')
                plt.title('Protocol Distribution')
                plt.tight_layout()
                
                # Save the figure
                output_file = os.path.join(output_dir, 'protocol_distribution.png')
                plt.savefig(output_file)
                plt.close()
                visualizations.append(output_file)
        
        # Top talkers (if available)
        if 'top_talkers' in results and isinstance(results['top_talkers'], dict):
            talkers = results['top_talkers']
            if talkers:
                plt.figure(figsize=(12, 8))
                
                # Extract IP addresses and packet counts
                ips = list(talkers.keys())[:15]  # Limit to top 15
                counts = [talkers[ip] for ip in ips]
                
                # Sort by count
                sorted_data = sorted(zip(ips, counts), key=lambda x: x[1])
                ips = [x[0] for x in sorted_data]
                counts = [x[1] for x in sorted_data]
                
                plt.barh(ips, counts)
                plt.title('Top Talkers')
                plt.xlabel('Packet Count')
                plt.ylabel('IP Address')
                plt.grid(True, axis='x')
                plt.tight_layout()
                
                # Save the figure
                output_file = os.path.join(output_dir, 'top_talkers.png')
                plt.savefig(output_file)
                plt.close()
                visualizations.append(output_file)
        
        return visualizations
    except Exception as e:
        print(f"Error generating visualizations: {str(e)}")
        return [] 