#!/usr/bin/python3

"""
CyberScout: Scanner orientativo de IPs
- Detecta OS usando TTL
- Escanea puertos comunes
- Obtiene versión de servicios (heurística)
- Indica posibles vulnerabilidades conocidas (orientativo)
"""


import re, sys, subprocess, socket, platform


if len(sys.argv) != 2:
    print("\n[!] Uso: python3 " + sys.argv[0] + " <direccion-ip>\n")
    sys.exit(1)

def get_ttl(ip):

    proc = subprocess.Popen(["/usr/bin/ping -c 1 %s" % ip_address, ""], stdout=subprocess.PIPE, shell=True)
    (out,err) = proc.communicate()

    out = out.split()
    out = out[12].decode('utf-8')

    ttl_value = re.findall(r"\d{1,3}", out)[0]

    return ttl_value

def get_os(ttl):

    ttl = int(ttl)

    if ttl >= 0 and ttl <= 64:
        return "Linux"
    elif ttl >= 65 and ttl <= 128:
        return "Windows"
    else:
        return "Not Found"

def scan_ports(ip):

    cmd = f"nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn {ip}"
    try:
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=600)
        output = proc.stdout
    except Exception as e:
        print("Error ejecutando nmap:", e)
        return []

    open_ports = []
    # Buscar líneas que contienen "port/tcp open"
    for line in output.splitlines():
        match = re.search(r"(\d+)/tcp\s+open", line)
        if match:
            open_ports.append(int(match.group(1)))

    ports_str = ",".join(str(p) for p in sorted(open_ports))

    return ports_str

def get_service_versions(ip, ports, output_file="targeted"):

    # Convertir lista de puertos a string "22,80,443"
    port_str = ",".join(str(p) for p in ports)

    cmd = f"nmap -p{port_str} -sCV {ip} -oN {output_file}"
    try:
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=600)
        output = proc.stdout
    except Exception as e:
        print("Error ejecutando nmap:", e)
        return []

    # Analizar la salida para extraer puerto, servicio y versión
    results = []
    # Buscamos líneas tipo: "22/tcp open  ssh     OpenSSH 7.2p2 Debian ..."
    for line in output.splitlines():
        line = line.strip()
        match = re.match(r"(\d+)/tcp\s+open\s+(\S+)\s*(.*)", line)
        if match:
            port = int(match.group(1))
            service = match.group(2)
            version = match.group(3).strip() if match.group(3) else ""
            results.append({"port": port, "service": service, "version": version})

    return results

if __name__ == '__main__':

    ip_address = sys.argv[1]

    ttl = get_ttl(ip_address)
    os_name = get_os(ttl)

    open_ports = scan_ports(ip_address)

    #service_versions = get_service_versions(ip_address, open_ports)
    print("\n%s (ttl -> %s): %s\n" % (ip_address, ttl, os_name))
    print("Puertos abiertos: %s" % (open_ports))
    #for s in service_versions:
        #print(f"Puerto {s['port']}/tcp: {s['service']} - {s['version']}")

