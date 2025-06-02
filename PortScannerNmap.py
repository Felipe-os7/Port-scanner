import subprocess
import json
from datetime import datetime
import ipaddress
import sys
import xmltodict

def run_nmap_scan(ip, ports):
    command = ["nmap", "-p", ports, "-sV", "-oX", "-", ip]
    try:
        print(f"\n🔎 Ejecutando: {' '.join(command)}\n")
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print("❌ Nmap falló con el siguiente mensaje de error:\n", file=sys.stderr)
        print(e.stderr.strip() if e.stderr else "No stderr disponible", file=sys.stderr)
        print("\n🔁 Comando ejecutado:", ' '.join(command), file=sys.stderr)
        sys.exit(1)


def xml_to_json(xml_data):
    try:
        import xmltodict
    except ImportError:
        print("Instalando xmltodict...")
        subprocess.run([sys.executable, "-m", "pip", "install", "xmltodict"])
        import xmltodict

    parsed = xmltodict.parse(xml_data)
    clean = remove_at_keys(parsed)
    return json.dumps(clean, indent=4)

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

def main():
    print("🔐 Nmap Port Scanner ")

    ip_input = input("📍 IP de destino: ").strip()
    try:
        ip = str(ipaddress.ip_address(ip_input))
    except ValueError:
        print("❌ Dirección IP inválida.")
        return

    port_input = input(" Puertos (ej. 22 o 20-80 o 80,443,8080): ").strip()
    if not port_input:
        print("❌ Rango de puertos inválido.")
        return

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    txt_filename = f"nmap_scan_{ip}_{timestamp}.txt"
    json_filename = f"nmap_scan_{ip}_{timestamp}.json"

    print("🕒 Iniciando escaneo...")

    xml_output = run_nmap_scan(ip, port_input)

    with open(txt_filename, 'w') as f:
        f.write(xml_output)

    json_data = xml_to_json(xml_output)
    with open(json_filename, 'w') as f:
        f.write(json_data)

    print(f"\n✅ Escaneo completado.")
    print(f"📄 XML (original): {txt_filename}")
    print(f"🧾 JSON (limpio): {json_filename}")

if __name__ == '__main__':
    main()
