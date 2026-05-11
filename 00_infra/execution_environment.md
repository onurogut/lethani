# Execution Environment — Kali SSH via MCP

All active recon/scan/exploit commands run on Kali Linux (alias `talon-kali`)
through the `kali-ssh` MCP server. The main host (macOS) is **only** for file
editing, report composition, WebFetch, and lightweight queries (e.g. crt.sh).

## MCP Aliases

```
talon-kali    Kali rolling — all active testing tools
```

Config: `~/.ssh/config` → `Host talon-kali` → `localhost:2222`, user `kali`,
key `~/.ssh/talon_kali`. NOPASSWD sudo enabled.

## MCP Tool Usage

| Tool                                          | When                                |
|-----------------------------------------------|-------------------------------------|
| `mcp__kali-ssh__runRemoteCommand`             | single command, stdout expected     |
| `mcp__kali-ssh__runCommandBatch`              | sequential commands (separate results) |
| `mcp__kali-ssh__checkConnectivity`            | confirm connection is live          |
| `mcp__kali-ssh__uploadFile` / `downloadFile`  | large files                         |

**Long-running jobs:** use `nohup` + `/tmp/<job>.log` + background PID. Tail
the log with `tail -f /tmp/<job>.log` to read progress.

## Installed Tools (2026-04-20)

### Subdomain / DNS
subfinder, amass, assetfinder, findomain, sublist3r, fierce, dnsenum, dnsrecon,
theharvester, dnsx, shuffledns, puredns, github-subdomains, gitlab-subdomains

### HTTP Discovery / Crawling
httpx (PD), httpx-toolkit (apt), httprobe, katana, gau, waybackurls, hakrawler,
photon, meg, getJS, subjs, gowitness

### Port / Service
nmap, masscan, naabu, whatweb, wafw00f, nbtscan

### Web Vuln Scan
nuclei (+ templates), nikto, wapiti, dalfox, kxss, crlfuzz, sqlmap, wfuzz, ffuf,
feroxbuster, dirb, dirsearch, gobuster, arjun, paramspider, XSRFProbe,
CORScanner

### Secrets / Repo
gitleaks, trufflehog

### Network / Service Exploit
hydra, crackmapexec, smbmap, enum4linux

### TLS / Crypto
testssl.sh, sslyze, openssl

### PD Utility
interactsh-client, notify, uncover, mapcidr, chaos, anew, qsreplace, unfurl, gf

### Recon Framework
recon-ng

**Full listing:**
```
ls $HOME/go/bin /usr/local/bin /usr/bin | grep -iE 'find|recon|scan|ffuf|...'
```

## Wordlist Locations

```
/usr/share/seclists/                       # apt seclists
/usr/share/wordlists/                      # apt default
/usr/share/wordlists/dirb/                 # dirb lists
/usr/share/wordlists/rockyou.txt.gz        # rockyou
$HOME/.gf/                                 # gf patterns (tomnomnom + 1ndianl33t)
```

**Most used:**
- `/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt`
- `/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt`
- `/usr/share/seclists/Discovery/Web-Content/api/objects.txt`
- `/usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt`
- `/usr/share/seclists/Passwords/Leaked-Databases/rockyou-75.txt`

## Engagement Artifacts

Per-target layout:
```
$WORKSPACE/engagements/<target-slug>/
├── scope.md                  # program rules, in/out, bounty table
├── findings.md               # all findings (in report format)
├── recon/
│   ├── subdomains.txt        # sorted, unique
│   ├── alive.txt             # httpx -probe output
│   ├── ports.txt             # naabu/nmap
│   ├── urls.txt              # gau+wayback+katana merged
│   ├── js/                   # downloaded JS files
│   └── screenshots/          # gowitness
├── scans/
│   ├── nuclei.txt
│   ├── nikto.txt
│   └── testssl.txt
├── poc/
│   └── <finding>.html|.py|.sh
└── notes.md                  # chronological raw log (temporary)
```

Kali-side scratch space: `/tmp/lethani/<target>/`. When done, pull artifacts
back to `engagements/` via `downloadFile`.

## Command Templates (copy-paste)

### Passive recon (one target)
```bash
T=example.com
mkdir -p /tmp/lethani/$T && cd /tmp/lethani/$T
subfinder -d $T -silent -all > subs_sf.txt
assetfinder --subs-only $T > subs_af.txt
findomain -t $T -q > subs_fd.txt
amass enum -passive -d $T -silent > subs_am.txt 2>/dev/null
cat subs_*.txt | anew subdomains.txt >/dev/null
wc -l subdomains.txt
```

### Active probe + tech fingerprint
```bash
cat subdomains.txt | httpx -silent -status-code -title -tech-detect \
  -web-server -follow-redirects -timeout 10 -rate-limit 50 -o alive.txt
```

### URL collection
```bash
T=example.com
(echo $T | gau; echo $T | waybackurls; katana -u https://$T -silent -jc -d 3) \
  | anew urls.txt >/dev/null
wc -l urls.txt
```

### Fast nuclei scan (critical+high only)
```bash
nuclei -l alive.txt -severity critical,high -rate-limit 50 -timeout 10 \
  -o nuclei_high.txt -stats
```

### Port scan (top-1000, rate-limited)
```bash
naabu -host example.com -top-ports 1000 -rate 500 -silent -o ports.txt
```

### Screenshot
```bash
gowitness scan file -f alive.txt --screenshot-path ./screenshots
```

### Blind XSS / SSRF OOB
```bash
interactsh-client -json | tee interact.log    # separate terminal / nohup
# use <callback>.oast.pro inside the payload
```

### Get an OOB domain
```bash
interactsh-client -n 1 -json | head -1 | jq -r .domain  # one-shot domain
```

## `httpx` Footgun

`/usr/bin/httpx` = the **python-httpx CLI** (from the `httpx` Python library),
NOT ProjectDiscovery httpx. On Kali these names collide.

Use `httpx-toolkit` (apt package name) for PD httpx, or use the absolute path
`$HOME/go/bin/httpx`. Examples here use `httpx-toolkit`.

## PATH Warning

`runRemoteCommand` over MCP does not source `~/.bashrc`, so Go binaries
(`$HOME/go/bin`) and pipx binaries (`$HOME/.local/bin`) may not be on PATH.
Either prefix every command with:

```bash
export PATH=$PATH:$HOME/go/bin:$HOME/.local/bin
```

…or call by absolute path: `/home/kali/go/bin/<tool>`.

## Safety / Operational Rules

1. **Scope check is mandatory** — CLAUDE.md Phase 0 always runs first.
2. **Rate limits** — default `-rate-limit 50`, `-rate 500` (naabu); aggressive
   profile only with explicit user approval.
3. **Never `-t 0` / `-rate 10000`** — do not bring the target down.
4. **Credential brute force** — only when the program explicitly allows it.
5. **Download artifacts** to `engagements/` — do not leave files in Kali `/tmp`.
6. **Logs**: every command piped to `| tee outputfile` so both stdout and disk
   have a copy.
7. **UTF-8 warning**: prefix commands with `LC_ALL=C` on Kali to silence locale
   warnings — has no effect on findings.

## Troubleshooting

| Symptom                        | Fix                                                       |
|--------------------------------|-----------------------------------------------------------|
| `command not found: <go-tool>` | `export PATH=$PATH:$HOME/go/bin` or `$HOME/go/bin/<tool>` |
| `go install` slow / fails      | `GOPROXY=direct go install ...`                           |
| ffuf/nuclei timeout            | `-timeout 30 -retries 2`                                  |
| nginx 502 on crt.sh            | fall back to `certspotter`, `chaos` (PD key), WebFetch    |
| Kali locale warning            | `LC_ALL=C <cmd>` or `sudo locale-gen tr_TR.UTF-8`         |

## Maintenance

Update this document when tool inventory or wordlist paths change. Keep it
short and transfer-and-run; every command should work directly on Kali.
