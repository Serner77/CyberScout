# CyberScout

Escáner orientativo de IPs para Linux. **CyberScout** realiza detección de sistema operativo por TTL, descubre puertos abiertos con Nmap y enumera versiones y metadatos de servicios de forma rápida y reproducible.

---

## Índice

- [Características](#características)
- [Arquitectura-y-Flujo](#arquitectura-y-flujo)
- [Requisitos](#requisitos)
- [Instalación](#instalación)
  - [Instalación como comando del sistema](#instalación-como-comando-del-sistema)
- [Uso](#uso)
  - [Ejemplos](#ejemplos)
  - [Salida de ejemplo](#salida-de-ejemplo)
- [Rendimiento](#rendimiento)
- [Compatibilidad](#compatibilidad)
- [Buenas prácticas y ética](#buenas-prácticas-y-ética)
- [Solución de problemas](#solución-de-problemas)
- [Contribuir](#contribuir)
- [Autor](#autor)

---

## Características

- **Detección rápida de OS (estimado)** mediante análisis del **TTL** devuelto por `ping`.
- **Descubrimiento de puertos** con Nmap sobre **todo el rango** (`-p-`) y filtrado de puertos **abiertos** (`--open`).
- **Enumeración de servicios y versiones** con perfil mixto (Opción 1):  
  `-sV --version-intensity 9 -sC --script http-title,http-server-header,http-headers,ssl-cert`.
- **Parsers dedicados** que enriquecen la versión cuando el banner no es concluyente (título HTTP, cabecera `Server`, sujeto del certificado TLS y validez).
- **Selección automática del tipo de escaneo**:
  - **SYN scan** (`-sS`) si se ejecuta como root.
  - **TCP connect** (`-sT`) en caso contrario.
- **Mensajes de progreso claros**, manejo de excepciones y salida legible para terminal.
- **Dependencias mínimas**: Python 3 y Nmap.

---

## Arquitectura y Flujo

1. **Reachability & TTL**  
   `ping -c 1 -W 1 <ip>` → extracción de `ttl=<N>` → mapeo aproximado a familia de OS:
   - `0–64`: Linux/Unix (estimado)
   - `65–128`: Windows (estimado)
   - `129–255`: Network device/BSD (estimado)

2. **Port Discovery**  
   `nmap -p- --open -sS|-sT --min-rate 5000 -vvv -n -Pn <ip>` → recopilación de puertos `tcp` en estado **open**.

3. **Service Enumeration (perfil Opción 1)**  
   `nmap -sV --version-intensity 9 -sC --script http-title,http-server-header,http-headers,ssl-cert -p<lista> -Pn -n <ip>`  
   Campos parseados:
   - Servicio y cadena de versión.
   - `http-title`, `http-server-header`, `http-headers`.
   - Certificados TLS: `Subject`, `Not valid before/after`.

4. **Enriquecimiento**  
   Si no hay versión explícita, se sustituyen pistas útiles (Server, título HTTP, sujeto TLS con ventana de validez).

---

## Requisitos

- **Sistema**: Linux  
- **Python**: 3.8 o superior  
- **Herramientas externas**:
  - `nmap` en el `PATH`
  - `ping` disponible en el sistema (ubicación no asumida)
- **Permisos**:
  - Opcionalmente **root** para SYN scan (`-sS`). Sin privilegios, se usa `-sT`.

Instalación de Nmap (Debian/Ubuntu):

    sudo apt update && sudo apt install -y nmap

---

## Instalación

Clona el repositorio y da permisos de ejecución al script:

    git clone https://github.com/<tu-usuario>/cyberscout.git
    cd cyberscout
    chmod +x cyberscout.py

> El script incluye *shebang* (`#!/usr/bin/python3`), por lo que puede ejecutarse directamente si es ejecutable.

### Instalación como comando del sistema

Invoca `cyberscout` desde cualquier ruta.

**Sistema completo (requiere sudo):**

    sudo cp /ruta/al/repo/cyberscout.py /usr/local/bin/cyberscout
    sudo chmod +x /usr/local/bin/cyberscout

---

## Uso

    python3 cyberscout.py <direccion-ip>
    # o, si lo instalaste como comando del sistema:
    cyberscout <direccion-ip>

Argumentos:

- `direccion-ip` — IP objetivo (IPv4).

### Ejemplos

Escaneo básico (sin privilegios, usará -sT):

    cyberscout 192.168.1.10

SYN scan (más sigiloso y rápido, requiere root):

    sudo cyberscout 192.168.1.10

### Salida de ejemplo

[i] Empezando escaneo de 192.168.1.10
[i] Obteniendo ttl y sistema operativo

192.168.1.10 (ttl -> 128): Windows (estimado)

[i] Descubriendo puertos abiertos

Puertos abiertos: 22,80,443

[i] Obteniendo versiones de los puertos [22, 80, 443]

  Puerto 22/tcp: ssh - OpenSSH 8.2p1 Ubuntu
  
  Puerto 80/tcp: http - Apache httpd 2.4.41
  
  Puerto 443/tcp: https - TLS CN=example.com (valid 2024-05-01..2025-05-01)

> Nmap genera además un archivo **`targeted`** con el detalle del escaneo de servicios.

---

## Rendimiento

- **Perfil Opción 1** equilibra cobertura y tiempo:
  - `-sC` añade scripts “default” útiles; se fuerzan además `http-title`, `http-server-header`, `http-headers`, `ssl-cert`.
  - `--version-intensity 9` aumenta la probabilidad de banners a costa de latencia.
- Sugerencias:
  - Considera `--script-timeout 15s` si el objetivo abre muchos puertos o hay servicios lentos.
  - Ajusta `--min-rate` si la red es sensible (p. ej., `--min-rate 1000`).

---

## Compatibilidad

- Probado en Linux con Python 3.8–3.12.
- Requiere `nmap` y `ping` accesibles en el `PATH`.
- Orientado a **IPv4** (IPv6 no contemplado en esta versión).

---

## Buenas prácticas y ética

Uso exclusivo para **auditorías autorizadas** o entornos propios con consentimiento. El uso no autorizado puede ser **ilegal**. Asegúrate de cumplir la normativa aplicable.

---

## Solución de problemas

- **“ping falló / No pude extraer TTL”** → verifica conectividad, ICMP y que `ping` esté instalado.
- **“nmap escaneo puertos falló”** → confirma `nmap` en `PATH`; baja `--min-rate` si la red es lenta/filtrada.
- **“Permisos requeridos para SYN scan”** → ejecuta con `sudo` o utiliza el *fallback* `-sT`.
- **HTTPS sin banner** → intenta sin `-Pn` o incrementa `--version-intensity`.

---

## Contribuir

1. Abre un *issue* con el cambio propuesto.  
2. Haz *fork* y crea una rama (`feature/json-output`, `fix/ttl-parse`).  
3. Incluye *tests* o casos de salida cuando aplique.  
4. Abre un *Pull Request* con descripción clara de impacto y riesgos.

---

## Autor

Desarrollado por Serner77.

---
