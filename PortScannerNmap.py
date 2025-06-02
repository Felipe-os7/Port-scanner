import nmap
import sys
import ipaddress
from datetime import datetime
import json

def main():
    print("Nmap Port Scanner (Python Wrapper)")

  
    ip_input = input("Enter target IP address (e.g. 192.168.1.1): ").strip()
    try:
        ip_address = str(ipaddress.ip_address(ip_input))
    except ValueError:
        print("Invalid IP address.", file=sys.stderr)
        sys.exit(1)


    port_input = input("Enter port range (e.g. 20-80 or single port like 80): ").strip()
    if "-" not in port_input and not port_input.isdigit():
        print("Invalid port range format.", file=sys.stderr)
        sys.exit(1)

    scanner = nmap.PortScanner()

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    txt_filename = f"nmap_scan_{ip_address}_{port_input}_{timestamp}.txt"
    json_filename = f"nmap_scan_{ip_address}_{port_input}_{timestamp}.json"

    try:
        print(f"\nStarting scan on {ip_address} ports {port_input}...\n")
        scanner.scan(hosts=ip_address, ports=port_input, arguments='-sS')

        if ip_address not in scanner.all_hosts():
            print(f"No results for host {ip_address}.")
            with open(txt_filename, 'w') as txt_file:
                txt_file.write(f"No response from host {ip_address}\n")
            with open(json_filename, 'w') as json_file:
                json.dump({"host": ip_address, "ports": []}, json_file, indent=4)
            sys.exit(0)

        txt_lines = []
        json_data = {"host": ip_address, "ports": []}

        for proto in scanner[ip_address].all_protocols():
            ports = scanner[ip_address][proto].keys()
            for port in sorted(ports):
                port_info = scanner[ip_address][proto][port]
                state = port_info['state']
                name = port_info.get('name', 'unknown')
                product = port_info.get('product', '')
                version = port_info.get('version', '')

                line = f"Port {port}/{proto} is {state} - Service: {name} {product} {version}".strip()
                print(line)
                txt_lines.append(line)

                json_data["ports"].append({
                    "port": port,
                    "protocol": proto,
                    "state": state,
                    "service": name,
                    "product": product,
                    "version": version
                })
       
        with open(txt_filename, 'w') as txt_file:
            txt_file.write(f"Scan results for {ip_address} (ports {port_input})\n")
            txt_file.write(f"Started at {timestamp}\n{'-'*60}\n")
            txt_file.write('\n'.join(txt_lines))

        with open(json_filename, 'w') as json_file:
            json.dump(json_data, json_file, indent=4)

        print(f"\nScan completed. Results saved to:\n- {txt_filename}\n- {json_filename}")

    except Exception as e:
        print(f"Error during scan: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
