import subprocess
import json
from datetime import datetime
import ipaddress
import sys

def run_nmap_scan(ip, ports):
    command = ["/usr/bin/nmap", "-p", ports, "-sV", "-oX", "-", ip]
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

def xml_to_json(xml_data):
    try:
        import xmltodict
    except ImportError:
        subprocess.run([sys.executable, "-m", "pip", "install", "xmltodict"], check=True)
        import xmltodict
    parsed = xmltodict.parse(xml_data)
    clean = remove_at_keys(parsed)
    return clean

def remove_at_keys(obj):
    if isinstance(obj, dict):
        new_dict = {}
        for key, value in obj.items():
            new_key = key.lstrip("@")
            new_dict[new_key] = remove_at_keys(value)
        return new_dict
    elif isinstance(obj, list):
        return [remove_at_keys(item) for item in obj]
    else:
        return obj

def extract_ports_with_status(scan_json):
    ports_list = []
    try:
        ports = scan_json['nmaprun']['host']['ports']['port']
    except KeyError:
        return ports_list
    if isinstance(ports, dict):
        ports = [ports]
    for port in ports:
        portid = port.get('portid', '')
        state = port.get('state', {}).get('state', '')
        service = port.get('service', {}).get('name', 'unknown')
        line = f"Port: {portid}, State: {state}, Service: {service}"
        ports_list.append(line)
    return ports_list

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
    xml_output = run_nmap_scan(ip, port_input)
    scan_json = xml_to_json(xml_output)
    ports_info = extract_ports_with_status(scan_json)
    with open(txt_filename, 'w') as f_txt:
        for line in ports_info:
            f_txt.write(line + '\n')
    with open(json_filename, 'w') as f_json:
        json.dump(scan_json, f_json, indent=4)
    print(f"Resultados TXT: {txt_filename}")
    print(f"Resultados JSON: {json_filename}")

if __name__ == '__main__':
    main()
