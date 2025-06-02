import subprocess
import ipaddress
import json
from datetime import datetime
import sys

def run_nmap_grep_scan(ip, ports):
    command = ["/usr/bin/nmap", "-p", ports, "-sV", "-Pn", "-oG", "-", ip]
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print("❌ Error ejecutando nmap:")
        print("Comando:", ' '.join(command))
        print("Código de salida:", e.returncode)
        print("STDOUT:", e.stdout)
        print("STDERR:", e.stderr)
        sys.exit(1)

def parse_grepable_output(output):
    ports = []
    for line in output.splitlines():
        if line.startswith("Host:"):
            parts = line.split("Ports: ")
            if len(parts) < 2:
                continue
            ports_part = parts[1].strip()
            for port_entry in ports_part.split(","):
                fields = port_entry.split("/")
                if len(fields) >= 3:
                    port_num = fields[0]
                    state = fields[1]
                    protocol = fields[2]
                    service = fields[4] if len(fields) > 4 else "unknown"
                    ports.append({
                        "port": port_num,
                        "state": state,
                        "protocol": protocol,
                        "service": service
                    })
    return ports

def main():
    ip_input = input("IP: ").strip()
    try:
        ip = str(ipaddress.ip_address(ip_input))
    except ValueError:
        print("Dirección IP inválida.")
        sys.exit(1)

    port_input = input("Puertos (ej. 22 o 20-80 o 80,443): ").strip()
    if not port_input:
        print("Rango de puertos inválido.")
        sys.exit(1)
    port_input = port_input.replace(":", "-")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    txt_filename = f"nmap_scan_{ip}_{timestamp}.txt"
    json_filename = f"nmap_scan_{ip}_{timestamp}.json"

    output = run_nmap_grep_scan(ip, port_input)
    ports_info = parse_grepable_output(output)

    with open(txt_filename, 'w') as f_txt:
        for port in ports_info:
            line = f"Port: {port['port']}/{port['protocol']}, State: {port['state']}, Service: {port['service']}"
            f_txt.write(line + "\n")

    with open(json_filename, 'w') as f_json:
        json.dump(ports_info, f_json, indent=4)

    print(f"Resultados TXT: {txt_filename}")
    print(f"Resultados JSON: {json_filename}")

if __name__ == '__main__':
    main()
