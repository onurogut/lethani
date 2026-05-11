#!/usr/bin/env bash
# setup-kali.sh — install the tool inventory lethani expects on Kali.
# Runs ON Kali (scp this file over, then bash it via SSH).
# Idempotent. Re-running it skips already-installed tools.
set -euo pipefail

say() { printf '[lethani:kali] %s\n' "$*"; }
warn() { printf '[lethani:kali] WARN: %s\n' "$*" >&2; }

export DEBIAN_FRONTEND=noninteractive
export GOPATH="${GOPATH:-$HOME/go}"
export PATH="$PATH:$GOPATH/bin:$HOME/.local/bin"

#
# 1. apt packages
#
APT_PKGS=(
  # build basics
  build-essential git curl wget jq make
  # network / port
  nmap masscan whatweb wafw00f nbtscan
  # web fuzz / scan
  ffuf feroxbuster gobuster dirb dirsearch nikto wapiti
  sqlmap wfuzz
  # crawling
  hakrawler
  # tls
  testssl.sh sslyze openssl
  # network/service exploit
  hydra crackmapexec smbmap enum4linux
  # secrets
  gitleaks trufflehog
  # subdomain / dns (apt versions)
  amass sublist3r fierce dnsenum dnsrecon theharvester
  # cosmetic
  bat ripgrep
  # python + go bootstrap
  python3 python3-pip python3-venv pipx
  golang-go
  # wordlists
  seclists
)

say "apt update"
sudo apt-get update -qq

say "apt install (${#APT_PKGS[@]} packages)"
sudo apt-get install -y -qq "${APT_PKGS[@]}" || warn "some apt packages may have failed"

#
# 2. Go tools (ProjectDiscovery + tomnomnom + assorted)
#
GO_TOOLS=(
  github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
  github.com/projectdiscovery/httpx/cmd/httpx@latest
  github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
  github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
  github.com/projectdiscovery/dnsx/cmd/dnsx@latest
  github.com/projectdiscovery/katana/cmd/katana@latest
  github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
  github.com/projectdiscovery/notify/cmd/notify@latest
  github.com/projectdiscovery/uncover/cmd/uncover@latest
  github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest
  github.com/projectdiscovery/chaos-client/cmd/chaos@latest
  github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
  github.com/d3mondev/puredns/v2@latest
  github.com/tomnomnom/assetfinder@latest
  github.com/tomnomnom/anew@latest
  github.com/tomnomnom/qsreplace@latest
  github.com/tomnomnom/unfurl@latest
  github.com/tomnomnom/waybackurls@latest
  github.com/tomnomnom/httprobe@latest
  github.com/tomnomnom/gf@latest
  github.com/tomnomnom/meg@latest
  github.com/lc/gau/v2/cmd/gau@latest
  github.com/lc/subjs@latest
  github.com/003random/getJS@latest
  github.com/hahwul/dalfox/v2@latest
  github.com/Emoe/kxss@latest
  github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest
  github.com/sensepost/gowitness@latest
  github.com/gwen001/github-subdomains@latest
  github.com/gwen001/gitlab-subdomains@latest
  github.com/findomain/findomain@latest
)

say "go install (${#GO_TOOLS[@]} tools — may take a few minutes)"
for tool in "${GO_TOOLS[@]}"; do
  name="$(basename "${tool%@*}")"
  if command -v "$name" >/dev/null 2>&1 || [[ -x "$GOPATH/bin/$name" ]]; then
    continue
  fi
  if ! GOPROXY=direct go install -v "$tool" 2>&1 | tail -1; then
    warn "go install failed: $tool"
  fi
done

#
# 3. Python tools (pipx)
#
say "pipx ensurepath"
pipx ensurepath >/dev/null 2>&1 || true

PIPX_TOOLS=(
  arjun
  paramspider
  XSRFProbe
  corscanner
)

for tool in "${PIPX_TOOLS[@]}"; do
  if pipx list 2>/dev/null | grep -q "package $tool "; then
    continue
  fi
  pipx install "$tool" 2>&1 | tail -1 || warn "pipx install failed: $tool"
done

#
# 4. nuclei templates
#
if command -v nuclei >/dev/null 2>&1 || [[ -x "$GOPATH/bin/nuclei" ]]; then
  say "nuclei -update-templates"
  "${GOPATH}/bin/nuclei" -update-templates -silent 2>&1 | tail -3 || true
fi

#
# 5. summary
#
say "summary — installed binaries:"
for bin in subfinder httpx nuclei naabu ffuf sqlmap gowitness interactsh-client arjun katana gau; do
  if command -v "$bin" >/dev/null 2>&1; then
    printf '[lethani:kali]   OK  %s\n' "$bin"
  elif [[ -x "$GOPATH/bin/$bin" ]]; then
    printf '[lethani:kali]   OK  %s (in $GOPATH/bin)\n' "$bin"
  else
    printf '[lethani:kali]   MISS %s\n' "$bin"
  fi
done

say "done. add 'export PATH=\$PATH:\$HOME/go/bin:\$HOME/.local/bin' to ~/.bashrc if not already there."
