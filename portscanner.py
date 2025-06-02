import socket
import sys
import ipaddress
from datetime import datetime
import json

def port_name_service(port):
    try:
        return socket.getservbyport(port)
    except:
        return "unknown"

def scan_port(ip, port, output_file, results):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((ip, port))
            if result == 0:
                service = port_name_service(port)
                result_line = f"{ip} : Open port: {port}, Service: {service}"
                print(result_line)
                output_file.write(result_line + '\n')
                results.append({
                    "ip": ip,
                    "port": port,
                    "status": "open",
                    "service": service
                })
            else:
                closed_line = f"{ip} : Closed port: {port}"
                print(closed_line)
                output_file.write(closed_line + '\n')
                results.append({
                    "ip": ip,
                    "port": port,
                    "status": "closed",
                    "service": None
                })
    except socket.error as e:
        error_line = f"Socket error on port {port}: {e}"
        print(error_line, file=sys.stderr)
        output_file.write(error_line + '\n')
        results.append({
            "ip": ip,
            "port": port,
            "status": "error",
            "error": str(e)
        })

def scan_ports(ip, start_port, end_port, output_file, results):
    for port in range(start_port, end_port + 1):
        scan_port(ip, port, output_file, results)

def main():
    print("Simple Port Scanner")
    
    ip_input = input("Enter target IP address (e.g. 192.168.1.1): ").strip()
    try:
        ip_address = str(ipaddress.ip_address(ip_input))
    except ValueError:
        print("Invalid IP address.", file=sys.stderr)
        sys.exit(1)

    port_input = input("Enter port range (e.g. 20:80 or single port like 80): ").strip()
    try:
        if ":" in port_input:
            start_port, end_port = map(int, port_input.split(":"))
        else:
            start_port = end_port = int(port_input)

        if not (0 <= start_port <= 65535 and 0 <= end_port <= 65535):
            raise ValueError
        if start_port > end_port:
            print("Initial port must be less than or equal to final port", file=sys.stderr)
            sys.exit(1)
    except ValueError:
        print("Invalid port range.", file=sys.stderr)
        sys.exit(1)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename_txt = f"scan_result_{ip_address}_{start_port}-{end_port}_{timestamp}.txt"
    filename_json = f"scan_result_{ip_address}_{start_port}-{end_port}_{timestamp}.json"

    results = []

    try:
        with open(filename_txt, 'w') as output_file:
            header = f"Scan results for {ip_address}, ports {start_port} to {end_port}\nStarted at {datetime.now()}\n{'-'*60}\n"
            output_file.write(header)
            print(header.strip())
            scan_ports(ip_address, start_port, end_port, output_file, results)

        # Guardar resultados en JSON
        with open(filename_json, 'w') as json_file:
            json.dump({
                "scan_info": {
                    "ip": ip_address,
                    "start_port": start_port,
                    "end_port": end_port,
                    "timestamp": timestamp
                },
                "results": results
            }, json_file, indent=4)

        print(f"\nScan completed. Results saved to {filename_txt} and {filename_json}")
    except IOError as e:
        print(f"Failed to write to file: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()
