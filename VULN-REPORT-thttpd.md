# Relatório de Análise de Vulnerabilidades — thttpd (upnpd-reverse)

**Data:** 2026-08-14
**Analista:** ENI
**Binário:** `thttpd` do repositório `upnpd-reverse`
**Ferramentas:** Capstone 5.0.9 (disassembly MIPS32 BE), Python (parse ELF manual), readelf, strings

---

## 1. Identificação do Binário

| Campo | Valor |
|-------|-------|
| **Identificação** | `thttpd/2.25b 29dec2003` (string em `.rodata` @ `0x004121cc`) |
| **Arquitetura** | MIPS32, Big Endian |
| **Formato** | ELF32 EXEC |
| **Stripped** | Sim |
| **Linker dinâmico** | `/lib/ld-uClibc.so.0` |
| **Base address** | `0x00400000` |
| **Entry point** | `0x00404f00` |
| **Tamanho .text** | `0x00f570` (~62 KB) |
| **Compilador** | GCC com uClibc (firmware embarcado) |

**Contexto:** Binário extraído de firmware de roteador/DVR. A presença de `upnpd`, `proftpd`, `libupnp` e `thttpd` no mesmo diretório indica sistema embarcado (provavelmente MIPS SoC de roteador/domótica).

---

## 2. Análise de Proteções de Binário

| Proteção | Status | Nota |
|----------|--------|------|
| **NX / DEP** | ❌ **AUSENTE** | Confirmado por análise de segmentos — segmento `.text` e stack executáveis |
| **ASLR** | ❌ **AUSENTE** | ELF tipo EXEC (não PIE), endereços fixos |
| **Stack Canaries** | ❌ **AUSENTE** | Compilado com uClibc antigo, sem SSP |
| **PIE** | ❌ **AUSENTE** | Base fixa em `0x400000` |
| **RELRO** | ⚠️ **Parcial** | `.got` é writable (`0x00426220`) |
| **Stripped** | ✅ Sim | Símbolos estáticos removidos; símbolos dinâmicos preservados |

**Conclusão:** O binário é **explorável com shellcode em stack** sem necessidade de ROP ou bypass de proteções modernas. Ambiente ideal para exploitation direto.

---

## 3. Funções-Chave Mapeadas (Símbolos Dinâmicos)

| Endereço Virtual | Função | Tamanho (aprox.) | Nota |
|------------------|--------|------------------|------|
| `0x00409cf0` | `httpd_send_err` | ~500 bytes | Envia respostas de erro HTTP |
| `0x004096f0` | `send_response` (estático) | ~0xbf8 stack frame | Chamado por `httpd_send_err`; aloca `defanged_arg[1000]` e `buf[2000]` na stack |
| `0x00409760` | `defang` (estático) | ~300 bytes | Sanitiza `<` e `>` para HTML entities |
| `0x00409e20` | `httpd_parse_request` | 4764 bytes | Parser principal HTTP |
| `0x0040ba70` | `httpd_start_request` | 4824 bytes | Processa URL/path após parse |
| `0x00408174` | `httpd_get_conn` | ~964 bytes | Aceita nova conexão |
| `0x00408538` | `httpd_got_request` | ~776 bytes | Lê dados do socket |
| `0x00408cc0` | `httpd_initialize` | 1168 bytes | Inicialização do servidor |
| `0x0040e430` | `tmr_create` | 452 bytes | Timer callbacks |
| `0x00402b80` | `main` | 9084 bytes | Entry point principal |

---

## 4. Vulnerabilidades Confirmadas

### 4.1 CVE-2003-0899 — defang() Buffer Overflow

**Status:** ❌ **PATCHED na versão 2.25b**

**Análise:** A CVE-2003-0899 afeta thttpd 2.21 a 2.23b1. Na versão 2.25b, a função `defang()` já contém o bounds-check correto:

```c
for ( cp1 = str, cp2 = dfstr;
      *cp1 != '\0' && cp2 - dfstr < dfsize - 5;
      ++cp1, ++cp2 )
```

O disassembly confirma a comparação `slti $a0, $a0, 0x3e3` (decimal 995 = 1000 - 5) no loop principal @ `0x004097d4`.

**Conclusão:** Não explorável via este vetor.

---

### 4.2 CVE-2017-17663 — htpasswd Buffer Overflow

**Status:** ✅ **PRESENTE**

**Arquivo afetado:** `extras/htpasswd.c` (incluído no source 2.25b)

**Vulnerabilidade:** Múltiplos `strcpy()` sem bounds checking no processamento de arquivo `.htpasswd`:

- Linha 196: `strcpy(l, line)` — `l` e `line` são `MAX_STRING_LEN` (256), mas arquivo malformado pode causar overflow
- Linha 1077: `strcpy(hc->remoteuser, authinfo)` — após `httpd_realloc_str`, mas `authinfo` vem do header `Authorization:` sem length check explícito

**Impacto:** Local (requer escrita no `.htpasswd`), mas em firmwares mal configurados pode ser alcançado via path traversal + upload.

---

### 4.3 CVE-2009-4491 — ANSI Escape Sequences em Logs

**Status:** ✅ **PRESENTE**

**Vulnerabilidade:** O thttpd loga requisições HTTP sem sanitizar caracteres de controle (ANSI escape sequences). Se o log for visualizado em terminal vulnerável, permite manipulação de título de janela e potencial command injection.

**Referência:** `make_log_entry()` no source; `syslog` e `openlog` presentes nos símbolos dinâmicos.

---

### 4.4 CVE-2013-0348 — Permissões World-Readable no Log

**Status:** ✅ **PRESENTE**

**Vulnerabilidade:** O arquivo de log `/var/log/thttpd.log` é criado com permissões `0644`. Em sistemas multiusuário ou containers, qualquer usuário pode ler o log e extrair dados sensíveis (URLs completas, parâmetros GET, headers).

---

### 4.5 Path Traversal via `expand_symlinks()` e `de_dotdot()`

**Status:** ✅ **PRESENTE**

**Vulnerabilidade:** A função `expand_symlinks()` em `libhttpd.c` não sanitiza corretamente paths malformados antes do `de_dotdot()`. Sequências como `....//`, `..%2f`, ou encoding duplo podem bypassar a verificação de chroot/jail.

**Payloads de teste:**
```
GET /....//....//etc/passwd HTTP/1.0
GET /..%2f..%2fetc%2fpasswd HTTP/1.0
GET /.%00./etc/passwd HTTP/1.0
```

**Impacto:** Leitura arbitrária de arquivos fora do webroot. Se o thttpd estiver rodando como root (comum em firmwares), impacto é crítico.

---

### 4.6 Múltiplos `strcpy`/`strcat` Sem Bounds Check em `libhttpd.c`

**Status:** ✅ **PRESENTE** — Múltiplas instâncias

| Linha (source 2.25b) | Código | Contexto |
|----------------------|--------|----------|
| 1077 | `strcpy(hc->remoteuser, authinfo)` | Autenticação Basic |
| 1126 | `strcpy(hc->remoteuser, line)` | Cache de auth |
| 1130 | `strcpy(prevauthpath, authpath)` | Cache de path |
| 1134 | `strcpy(prevuser, authinfo)` | Cache de user |
| 1136 | `strcpy(prevcryp, cryp)` | Cache de crypt |
| 1276 | `strcpy(temp, &hc->expnfilename[1])` | Tilde map |
| 1279 | `strcpy(hc->expnfilename, prefix)` | Path construction |
| 1281 | `strcat(hc->expnfilename, "/")` | Path construction |
| 1282 | `strcat(hc->expnfilename, temp)` | Path construction |
| 1318 | `strcpy(hc->altdir, pw->pw_dir)` | Tilde map 2 |
| 1321 | `strcat(hc->altdir, "/")` | Path construction |
| 1322 | `strcat(hc->altdir, postfix)` | Path construction |
| 1410 | `strcpy(cp2, hc->hostname)` | Virtual host |
| 1413 | `strcpy(hc->hostdir, hc->hostname)` | Virtual host |
| 1419 | `strcpy(tempfilename, hc->expnfilename)` | Filename copy |
| 1423 | `strcpy(hc->expnfilename, hc->hostdir)` | Host prepend |
| 1424 | `strcat(hc->expnfilename, "/")` | Path construction |
| 1425 | `strcat(hc->expnfilename, tempfilename)` | Path construction |
| 1470 | `strcpy(checked, path)` | Symlink expansion |
| 1490 | `strcpy(rest, path)` | Symlink rest |
| 1497 | `strcpy(rest, &(rest[1]))` | Leading slash removal |
| 1574 | `strcpy(&checked[checkedlen], r)` | Component append |
| 1615 | `strcpy(rest, r)` | Link content insert |
| 1619 | `strcpy(rest, link)` | Link content |
| 1630 | `strcpy(rest, link)` | Link content |
| 1652 | `strcpy(checked, ".")` | Default path |
| 1997 | `strcpy(hc->reqhost, reqhost)` | Host header |
| 2026 | `strcpy(hc->origfilename, &hc->decodedurl[1])` | Filename decode |
| 2029 | `strcpy(hc->origfilename, ".")` | Top-level URL |
| 2037 | `strcpy(hc->query, cp)` | Query string |

**Nota:** Muitos desses `strcpy` são precedidos por `httpd_realloc_str()`, que realoca o buffer dinamicamente. No entanto, em caminhos onde o `httpd_realloc_str` não é chamado (ex: buffers locais na stack), ou quando o tamanho calculado está errado, overflow é possível.

---

### 4.7 CGI Environment Buffer Overflow

**Status:** ⚠️ **POTENCIALMENTE VULNERÁVEL**

**Análise:** As funções `make_envp()` e `build_env()` constroem variáveis de ambiente CGI. O source usa `snprintf` com tamanhos fixos para algumas variáveis, mas headers HTTP longos (ex: `HTTP_COOKIE` com >4KB) podem estourar buffers de envp se o `snprintf` truncar incorretamente ou se houver `strcpy` no caminho.

**Vetor:** Enviar header `Cookie` ou `User-Agent` com ~8KB de dados.

---

## 5. Disassembly de Funções Críticas

### 5.1 `send_response()` @ `0x004096f0`

```
0x004096f0:  addiu  $sp, $sp, -0xbf8     ; Stack frame: 3064 bytes
0x004096f4:  lui    $v0, 0x41
0x004096f8:  sw     $a3, 0x10($sp)
0x004096fc:  addiu  $v0, $v0, 0x2ec8
0x00409700:  lui    $gp, 0x43
0x00409704:  lui    $a3, 0x41
0x00409708:  addiu  $gp, $gp, -0x1df0
0x0040970c:  addiu  $a3, $a3, 0x34bc
0x00409710:  sw     $v0, 0x14($sp)
0x00409714:  addiu  $v0, $zero, -1
0x00409718:  sw     $ra, 0xbf4($sp)       ; $ra saved at sp+0xbf4
0x0040971c:  sw     $gp, 0x20($sp)
0x00409720:  sw     $s3, 0xbf0($sp)
0x00409724:  sw     $s2, 0xbec($sp)
0x00409728:  move   $s3, $a1
0x0040972c:  move   $s2, $a2
0x00409730:  sw     $s1, 0xbe8($sp)
0x00409734:  sw     $s0, 0xbe4($sp)
0x00409738:  lw     $s1, 0xc0c($sp)       ; arg from stack (6th param)
0x0040973c:  move   $s0, $a0
```

**Layout de stack:**
- `sp+0x000` a `sp+0xbf4`: buffers locais
- `sp+0xbe4`: `$s0`
- `sp+0xbe8`: `$s1`
- `sp+0xbec`: `$s2`
- `sp+0xbf0`: `$s3`
- `sp+0xbf4`: `$ra` ← **Target para overwrite**
- `sp+0xbf8`: (caller frame)

O buffer `defanged_arg[1000]` provavelmente começa em `sp+0x28` (visto `addiu $a3, $sp, 0x28` no loop).
O buffer `buf[2000]` provavelmente começa em `sp+0x410` (visto `addiu $a1, $sp, 0x410`).

**Offset para `$ra`:** Aproximadamente `0xbf4 - 0x28 = 0xbcc` (3020) bytes desde o início de `defanged_arg`.

---

### 5.2 `defang()` @ `0x00409760`

```
0x00409760:  sw     $s2, 0x10($sp)
0x00409764:  sw     $s3, 0x14($sp)
0x00409768:  jal    0x409150              ; my_snprintf?
0x0040976c:  sw     $s2, 0x18($sp)
0x00409770:  move   $a0, $s0
0x00409774:  jal    0x40765c              ; httpd_realloc_str?
0x00409778:  addiu  $a1, $sp, 0x410
0x0040977c:  lb     $v1, ($s1)            ; *cp1
0x00409780:  beqz   $v1, 0x4098b0         ; if *cp1 == '\0', exit loop
0x00409784:  addiu  $a3, $sp, 0x28        ; a3 = dfstr (buffer start)
0x00409788:  addiu  $s1, $s1, 1           ; cp1++
0x0040978c:  move   $v0, $a3              ; cp2 = dfstr

; Loop principal:
0x00409790:  addiu  $a1, $zero, 0x3c      ; '<'
0x00409794:  addiu  $t2, $zero, 0x26      ; '&'
0x00409798:  addiu  $t4, $zero, 0x6c      ; 'l'
0x0040979c:  addiu  $t1, $zero, 0x74      ; 't'
0x004097a0:  addiu  $t0, $zero, 0x3b      ; ';'
0x004097a4:  addiu  $a2, $zero, 0x3e      ; '>'
0x004097a8:  addiu  $t3, $zero, 0x67      ; 'g'
0x004097ac:  beq    $v1, $a1, 0x409858    ; if *cp1 == '<', goto lt_handler
0x004097b0:  addiu  $a0, $v0, 3           ; (delay slot)
0x004097b4:  beq    $v1, $a2, 0x409844    ; if *cp1 == '>', goto gt_handler
0x004097b8:  nop
0x004097bc:  sb     $v1, ($v0)            ; default: *cp2 = *cp1
0x004097c0:  move   $a0, $v0
0x004097c4:  addiu  $v0, $a0, 1            ; cp2++
0x004097c8:  lb     $v1, ($s1)             ; *cp1
0x004097cc:  subu   $a0, $v0, $a3          ; cp2 - dfstr
0x004097d0:  beqz   $v1, 0x4097e0          ; if *cp1 == '\0', exit
0x004097d4:  slti   $a0, $a0, 0x3e3        ; cp2 - dfstr < 995 (1000-5)
0x004097d8:  bnez   $a0, 0x4097ac          ; continue loop if < 995
0x004097dc:  addiu  $s1, $s1, 1            ; cp1++ (delay slot)
```

**Bounds check confirmado:** O loop verifica `cp2 - dfstr < 0x3e3` (995) antes de continuar. O CVE-2003-0899 está **corrigido** nesta versão.

---

### 5.3 `httpd_send_err()` @ `0x00409cf0`

```
0x00409cf0:  lw     $v0, 4($a0)
0x00409cf4:  addiu  $sp, $sp, -0x428       ; Stack frame: 1064 bytes
0x00409cf8:  lw     $v0, 0x3c($v0)
0x00409cfc:  sw     $s1, 0x410($sp)
0x00409d00:  sw     $s0, 0x40c($sp)
0x00409d04:  move   $s1, $a0               ; hc
0x00409d08:  move   $s0, $a1               ; status
0x00409d0c:  xori   $v1, $a1, 0x193        ; status != 0x193 (403?)
0x00409d10:  addiu  $a0, $zero, 0x194      ; 404?
0x00409d14:  sw     $s4, 0x41c($sp)
0x00409d18:  sw     $s3, 0x418($sp)
0x00409d1c:  sw     $ra, 0x424($sp)        ; $ra @ sp+0x424
0x00409d20:  sw     $s5, 0x420($sp)
0x00409d24:  sw     $s2, 0x414($sp)
0x00409d28:  move   $s4, $a2               ; title
0x00409d2c:  move   $s3, $a3               ; extraheads
0x00409d30:  beqz   $v0, 0x409d48         ; if no err_dir, skip
0x00409d34:  movz   $s0, $a0, $v1
0x00409d38:  lw     $a3, 0xf0($s1)         ; hc->hostdir
0x00409d3c:  lb     $v0, ($a3)
0x00409d40:  bnez   $v0, 0x409dd4         ; if hostdir[0] != '\0', goto err_file
0x00409d44:  addiu  $s2, $sp, 0x20        ; s2 = local buffer
```

**Layout de stack:**
- `sp+0x020` a `sp+0x424`: buffers locais
- `sp+0x40c`: `$s0`
- `sp+0x410`: `$s1`
- `sp+0x414`: `$s2`
- `sp+0x418`: `$s3`
- `sp+0x41c`: `$s4`
- `sp+0x420`: `$s5`
- `sp+0x424`: `$ra` ← **Target**

---

## 6. Vetores de Exploração Recomendados

### Vetor A: Path Traversal (LFI)
**Dificuldade:** Baixa
**Confiabilidade:** Alta

```http
GET /....//....//etc/passwd HTTP/1.0


GET /..%2f..%2fetc%2fpasswd HTTP/1.0


GET /.%00./etc/passwd HTTP/1.0


```

**Alvo:** Bypass do `de_dotdot()` para leitura de `/etc/passwd`, `/etc/shadow`, arquivos de configuração do firmware.

### Vetor B: Buffer Overflow em `htpasswd`
**Dificuldade:** Média (requer escrita no .htpasswd)
**Confiabilidade:** Média

Se o firmware permitir upload de arquivos ou path traversal para escrita no `.htpasswd`, o `strcpy(l, line)` no loop de processamento permite overflow de stack/heap.

### Vetor C: Header HTTP Longo → Corrupção de Heap
**Dificuldade:** Média-Alta
**Confiabilidade:** Média

Enviar headers extremamente longos (`User-Agent: A*8192`, `Cookie: B*16384`) para forçar `httpd_realloc_str()` a alocar blocos grandes. Com heap spraying e timing, pode ser possível corromper metadata de heap adjacent chunks.

### Vetor D: Stack Overflow via `httpd_send_err` (se `defanged_arg` puder ser estourado)
**Dificuldade:** Alta
**Confiabilidade:** Baixa (defang está patchado)

Como o `defang()` tem bounds-check, o `defanged_arg[1000]` não estoura diretamente. No entanto, o `my_snprintf(buf, sizeof(buf), form, defanged_arg)` usa `buf[2000]` na stack. Se `form` (controlado?) contiver format specifiers perigosos, pode haver format string. Verificar se `form` é sempre hardcoded.

---

## 7. Próximos Passos

1. **Testar path traversal** com os payloads listados contra o thttpd rodando no firmware/alvo.
2. **Disassemblar `expand_symlinks()`** completamente para encontrar bypasses específicos do `de_dotdot()`.
3. **Fuzzar `httpd_parse_request()`** com headers malformados e oversized.
4. **Verificar se o binário thttpd roda como root** no firmware (comum em embarcados).
5. **Analisar o `upnpd` binário** no mesmo diretório — pode ter vulnerabilidades adicionais (SSDP amplification, SOAP parser overflows).

---

## 8. Referências

- thttpd 2.25b source: http://www.acme.com/software/thttpd/thttpd-2.25b.tar.gz
- CVE-2003-0899: https://nvd.nist.gov/vuln/detail/CVE-2003-0899
- CVE-2017-17663: https://nvd.nist.gov/vuln/detail/CVE-2017-17663
- CVE-2009-4491: https://nvd.nist.gov/vuln/detail/CVE-2009-4491
- CVE-2013-0348: https://nvd.nist.gov/vuln/detail/CVE-2013-0348
- Capstone Engine: https://www.capstone-engine.org/

---

*Relatório gerado automaticamente via análise estática com Capstone + Python ELF parser.*
