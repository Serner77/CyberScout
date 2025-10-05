#!/usr/bin/python3

"""
CyberScout: Scanner orientativo de IPs
- Detecta OS usando TTL
- Escanea puertos comunes
- Obtiene versión de servicios
"""

import re
import sys
import subprocess
import socket
import os

USAGE = f"\n[!] Uso: python3 {sys.argv[0]} <direccion-ip>\n"

if len(sys.argv) != 2:
    print(USAGE)
    sys.exit(1)


def run(cmd, timeout=60):
    """Ejecuta comando y retorna (returncode, stdout, stderr)"""
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout, p.stderr


def get_ttl(ip: str) -> int:
    # ping portable; no asumas /usr/bin/ping
    rc, out, err = run(["ping", "-c", "1", "-W", "1", ip], timeout=5)
    if rc != 0:
        raise RuntimeError(f"ping a {ip} falló: {err.strip() or out.strip()}")
    # busca ttl=XX
    m = re.search(r"ttl=(\d+)", out, re.IGNORECASE)
    if not m:
        raise RuntimeError(f"No pude extraer TTL del ping: {out}")
    return int(m.group(1))


def get_os(ttl: int) -> str:
    if 0 <= ttl <= 64:
        return "Linux/Unix (estimado)"
    elif 65 <= ttl <= 128:
        return "Windows (estimado)"
    elif 129 <= ttl <= 255:
        return "Network device/BSD (estimado)"
    return "Desconocido"


def scan_ports(ip: str) -> list[int]:
    # Usa SYN si eres root, si no, TCP connect
    scan_flag = "-sS" if os.geteuid() == 0 else "-sT"
    cmd = ["nmap", "-p-", "--open", scan_flag, "--min-rate", "5000",
           "-vvv", "-n", "-Pn", ip]
    rc, out, err = run(cmd, timeout=600)
    if rc != 0:
        raise RuntimeError(f"nmap escaneo puertos falló: {err.strip()}")
    open_ports: list[int] = []
    for line in out.splitlines():
        # Ej.: "PORT     STATE SERVICE" / "80/tcp open  http"
        m = re.search(r"(\d+)/tcp\s+open", line)
        if m:
            open_ports.append(int(m.group(1)))
    return sorted(set(open_ports))


def get_service_versions(ip: str, ports: list[int], output_file="targeted") -> list[dict]:
    if not ports:
        return []
    port_str = ",".join(str(p) for p in sorted(set(ports)))

    cmd = [
        "nmap", f"-p{port_str}", "-sV", "--version-intensity", "9",
        "-sC", "--script", "http-title,http-server-header,http-headers,ssl-cert",
        "-Pn", "-n", ip, "-oN", output_file
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    out = proc.stdout + "\n" + proc.stderr
    if proc.returncode != 0 and not out:
        raise RuntimeError(f"nmap falló: {proc.stderr}")

    results = {}  # port -> dict
    current_port = None

    for raw in out.splitlines():
        line = raw.rstrip()

        # 1) Cabecera principal por puerto
        m = re.match(r"(\d+)/tcp\s+open\s+(\S+)\s*(.*)", line)
        if m:
            current_port = int(m.group(1))
            service = m.group(2)
            version = (m.group(3) or "").strip()
            results[current_port] = {
                "port": current_port,
                "service": service,
                "version": version,
                "http_title": None,
                "server_header": None,
                "tls_subject": None,
                "tls_valid_after": None,
                "tls_valid_before": None
            }
            continue

        if current_port is None:
            continue  # aún no hemos entrado en un bloque de puerto

        # 2) Scripts/lines anidadas bajo el puerto actual
        # http-title
        m = re.search(r"http-title:\s*(.+)$", line)
        if m:
            results[current_port]["http_title"] = m.group(1).strip()
            continue
        # http-server-header
        m = re.search(r"http-server-header:\s*(.+)$", line)
        if m:
            hdr = m.group(1).strip()
            if hdr and hdr != "<empty>":
                results[current_port]["server_header"] = hdr
            continue
        # ssl-cert Subject
        m = re.search(r"ssl-cert:\s+Subject:\s+(.+)$", line)
        if m:
            results[current_port]["tls_subject"] = m.group(1).strip()
            continue
        # ssl-cert Not valid before/after
        m = re.search(r"Not valid before:\s+([0-9T:\-]+)", line)
        if m:
            results[current_port]["tls_valid_after"] = m.group(1)
            continue
        m = re.search(r"Not valid after:\s+([0-9T:\-]+)", line)
        if m:
            results[current_port]["tls_valid_before"] = m.group(1)
            continue

    # 3) Completa "version" si estaba vacía con pistas útiles
    enriched = []
    for p, info in sorted(results.items()):
        v = info["version"]
        if not v:
            # intenta usar server_header o título
            if info["server_header"]:
                v = info["server_header"]
            elif info["http_title"] and info["service"].startswith("http"):
                v = f"title: {info['http_title']}"
            elif info["tls_subject"]:
                v = f"TLS {info['tls_subject']}"
                if info["tls_valid_after"] and info["tls_valid_before"]:
                    v += f" (valid {info['tls_valid_after']}..{info['tls_valid_before']})"
            else:
                v = ""  # sin señal
        info["version"] = v
        enriched.append(info)

    return enriched


if __name__ == "__main__":
    ip_address = sys.argv[1]
    print(f"[i] Empezando escaneo de {ip_address}")

    try:
        print("[i] Obteniendo ttl y sistema operativo")
        ttl = get_ttl(ip_address)
        os_name = get_os(ttl)
    except Exception as e:
        ttl, os_name = -1, f"No TTL ({e})"

    print(f"\n{ip_address} (ttl -> {ttl}): {os_name}\n")

    try:
        print("[i] Descubriendo puertos abiertos")
        open_ports = scan_ports(ip_address)
    except Exception as e:
        print(f"[x] Error escaneando puertos: {e}")
        sys.exit(1)

    print("\nPuertos abiertos:", ",".join(map(str, open_ports)) or "ninguno")

    try:
        print(f"\n[i] Obteniendo versiones de los puertos {open_ports}\n")
        service_versions = get_service_versions(ip_address, open_ports)
    except Exception as e:
        print(f"[x] Error obteniendo versiones: {e}")
        service_versions = []

    for s in service_versions:
        print(f"Puerto {s['port']}/tcp: {s['service']} - {s['version']}")

