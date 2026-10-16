#!/usr/bin/env bash
# SSH LAN — one script, menu TUI or CLI. Bash/Linux (client or OpenSSH server).
# Usage: chmod +x ssh-lan.sh && ./ssh-lan.sh
# CLI:   ./ssh-lan.sh help|status|harden|add-client|remove|client [-- options]

SSH_LAN_VERSION="$(head -n1 "$(dirname "${BASH_SOURCE[0]}")/../../VERSION" 2>/dev/null | tr -d '\r' || echo dev)"
# ไม่ใช้ set -u — bash หลายตัวพังที่ local a=1 b=$a (unbound variable)
set -eo pipefail
shopt -s nullglob
export LANG="${LANG:-en_US.UTF-8}"
export LC_ALL="${LC_ALL:-en_US.UTF-8}"

ACTION="${ACTION:-}"
LOGIN_USER="${LOGIN_USER:-${USER:-root}}"
SUBNET="${SUBNET:-}"
MY_PUB_KEY_PATH="${MY_PUB_KEY_PATH:-}"
MY_PUB_KEY="${MY_PUB_KEY:-}"
UNINSTALL_SERVER="${UNINSTALL_SERVER:-0}"
PAIR_TARGET="${PAIR_TARGET:-}"
PAIR_USER="${PAIR_USER:-}"
PAIR_ALIAS="${PAIR_ALIAS:-}"
PAIR_BOTH="${PAIR_BOTH:-0}"

# --- defaults (override with the SSH_* environment variables) ---
SSH_HOST_ALIAS="${SSH_HOST_ALIAS:-ssh-lan}"
SSH_SERVER_IP="${SSH_SERVER_IP:-}"
SSH_SERVER_HOST="${SSH_SERVER_HOST:-}"
SSH_SERVER_IP_SEARCH="${SSH_SERVER_IP_SEARCH:-}"
SSH_SERVER_USER="${SSH_SERVER_USER:-${USER:-root}}"
SSH_IDENTITY="${SSH_IDENTITY:-id_ed25519_lan}"

SSHD_DROPIN='/etc/ssh/sshd_config.d/99-ssh-lan.conf'
UFW_RULE_COMMENT='ssh-lan'

while [[ $# -gt 0 ]]; do
  case "$1" in
    help|status|harden|add-client|remove|client|pair) ACTION="$1"; shift ;;
    --target) PAIR_TARGET="$2"; shift 2 ;;
    --as) PAIR_USER="$2"; shift 2 ;;
    --alias) PAIR_ALIAS="$2"; shift 2 ;;
    --both) PAIR_BOTH=1; shift ;;
    --login-user) LOGIN_USER="$2"; shift 2 ;;
    --subnet) SUBNET="$2"; shift 2 ;;
    --pubkey-path) MY_PUB_KEY_PATH="$2"; shift 2 ;;
    --pubkey) MY_PUB_KEY="$2"; shift 2 ;;
    --uninstall-server) UNINSTALL_SERVER=1; shift ;;
    -h|--help)
      echo "Usage: $0 [help|status|harden|add-client|remove|client|pair] [--subnet CIDR] [--pubkey-path FILE] [--target USER@HOST --alias NAME --both]"
      exit 0
      ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done

# --- UI ---
_cyan() { printf '\033[36m%s\033[0m\n' "$*"; }
_green() { printf '\033[32m%s\033[0m\n' "$*"; }
_yellow() { printf '\033[33m%s\033[0m\n' "$*"; }
_red() { printf '\033[31m%s\033[0m\n' "$*"; }
_gray() { printf '\033[90m%s\033[0m\n' "$*"; }
_magenta() { printf '\033[35m%s\033[0m\n' "$*"; }

show_motion() {
  local label="${1:-...}" ms="${2:-700}"
  local spin='|/-\'
  local n i dot s
  n=$(( ms / 70 )); [[ $n -lt 6 ]] && n=6
  i=0
  while [[ $i -lt $n ]]; do
    dot=$(( (i % 3) + 1 ))
    s="${spin:$((i % 4)):1}"
    printf '\r  %s  %s %*s   ' "$s" "$label" "$dot" ''
    sleep 0.07
    i=$((i + 1))
  done
  echo
}

show_fill() {
  local label="${1:-...}" width=22 i=0
  while [[ $i -le $width ]]; do
    local bar; bar=$(printf '#%.0s' $(seq 1 "$i" 2>/dev/null || true))
    bar="${bar:0:$i}"
    printf '\r  [%*s] %s   ' "$width" "$bar" "$label"
    sleep 0.028
    i=$((i + 1))
  done
  echo
}

show_boot() {
  clear
  _cyan '  .  SSH'
  sleep 0.12
  _cyan '  .. SSH ใน'
  sleep 0.12
  _cyan '  ... SSH ในบ้าน'
  show_fill 'เตรียมเมนู'
}

show_steps() {
  local title="$1" now="$2"; shift 2
  local labels=("$@")
  clear
  echo
  _cyan "  $title"
  echo
  local i=0 n=${#labels[@]}
  while [[ $i -lt $n ]]; do
    local num=$((i + 1)) mark='  ' color=''
    if [[ $num -lt $now ]]; then mark='ok'; fi
    if [[ $num -eq $now ]]; then mark='>>'; fi
    if [[ $mark == '>>' ]]; then printf '  \033[32m%s  %s  %s\033[0m\n' "$mark" "$num" "${labels[$i]}"
    elif [[ $mark == 'ok' ]]; then printf '  \033[32m%s  %s  %s\033[0m\n' "$mark" "$num" "${labels[$i]}"
    else printf '  \033[90m%s  %s  %s\033[0m\n' "$mark" "$num" "${labels[$i]}"
    fi
    if [[ $i -lt $((n - 1)) ]]; then _gray '       |'; fi
    i=$((i + 1))
  done
  echo
}

pause() { read -r -p '  Enter...' _ || true; }

# --- core ---
need_cmd() {
  command -v "$1" >/dev/null 2>&1 || { _red "  ต้องมีคำสั่ง: $1"; exit 1; }
}

OS_KIND="$(uname -s)"   # Linux or Darwin (macOS)

# sed -i differs on macOS (BSD): it wants a suffix argument
sed_i() { if sed --version >/dev/null 2>&1; then sed -i "$@"; else sed -i '' "$@"; fi; }

# first address for a name: getent on Linux, dscacheutil on macOS
resolve_host() {
  getent hosts "$1" 2>/dev/null | awk '{print $1; exit}' && return 0
  dscacheutil -q host -a name "$1" 2>/dev/null | awk '/^ip_address:/ {print $2; exit}'
}

is_server() {
  if [[ "${SSH_LAN_SERVER:-}" == '1' ]]; then return 0; fi
  if [[ "$OS_KIND" == 'Darwin' ]]; then nc -z -w1 127.0.0.1 22 >/dev/null 2>&1; return; fi
  systemctl is-active sshd >/dev/null 2>&1 || systemctl is-active ssh >/dev/null 2>&1 || return 1
  ss -ltn 2>/dev/null | grep -q ':22 ' && return 0
  return 1
}

have_sudo() {
  [[ "$(id -u)" -eq 0 ]] && return 0
  command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null
}

assert_root() {
  if [[ "$(id -u)" -eq 0 ]]; then return 0; fi
  if command -v sudo >/dev/null 2>&1; then
    _yellow '  ต้องใช้ sudo'
    read -r -p '  รัน sudo ใหม่ไหม [Y/n] ' r
    [[ "$r" =~ ^[nN] ]] && { _red '  ยกเลิก'; exit 1; }
    exec sudo -E env ACTION="$ACTION" LOGIN_USER="$LOGIN_USER" SUBNET="$SUBNET" \
      MY_PUB_KEY_PATH="$MY_PUB_KEY_PATH" MY_PUB_KEY="$MY_PUB_KEY" \
      UNINSTALL_SERVER="$UNINSTALL_SERVER" \
      SSH_HOST_ALIAS="$SSH_HOST_ALIAS" SSH_SERVER_IP="$SSH_SERVER_IP" \
      SSH_SERVER_USER="$SSH_SERVER_USER" SSH_IDENTITY="$SSH_IDENTITY" \
      "$0" ${ACTION:+"$ACTION"}
  fi
  _red '  ต้องเป็น root หรือมี sudo'
  exit 1
}

authorized_keys_path() {
  local u="${1:-$LOGIN_USER}"
  if [[ "$u" == "$USER" ]] || [[ "$(id -u)" -eq 0 && "$u" == "$LOGIN_USER" ]]; then
    echo "${HOME}/.ssh/authorized_keys"
  else
    echo "/home/$u/.ssh/authorized_keys"
  fi
}

resolve_pubkey() {
  local line=''
  if [[ -n "$MY_PUB_KEY" ]]; then
    line=$(echo "$MY_PUB_KEY" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
  elif [[ -n "$MY_PUB_KEY_PATH" ]]; then
    [[ -f "$MY_PUB_KEY_PATH" ]] || { _red "  ไม่พบไฟล์: $MY_PUB_KEY_PATH"; exit 1; }
    line=$(grep -m1 -E '^(ssh-(ed25519|rsa|ecdsa)|ecdsa-sha2-)' "$MY_PUB_KEY_PATH" | tr -d '\r')
  else
    _red '  ไม่มี public key'; exit 1
  fi
  [[ "$line" =~ ^(ssh-(ed25519|rsa|ecdsa)|ecdsa-sha2-) ]] || { _red '  บรรทัด public key ไม่ถูก'; exit 1; }
  echo "$line"
}

show_fingerprint() {
  local pub="$1"
  local t
  t=$(mktemp)
  printf '%s\n' "$pub" >"$t"
  ssh-keygen -lf "$t" 2>/dev/null || true
  rm -f "$t"
}


add_key_line() {
  local path="$1" key="$2"
  local dir; dir=$(dirname "$path")
  mkdir -p "$dir"
  chmod 700 "$dir" 2>/dev/null || true
  if [[ -f "$path" ]] && grep -Fq "$key" "$path"; then return 1; fi
  echo "$key" >>"$path"
  chmod 600 "$path" 2>/dev/null || true
  return 0
}

get_auto_pubkey() {
  need_cmd ssh-keygen
  local dir="${HOME}/.ssh"
  mkdir -p "$dir"
  chmod 700 "$dir"
  local found='' made=0
  for f in "$dir/id_ed25519.pub" "$dir/${SSH_IDENTITY}.pub" "$dir"/*.pub; do
    [[ -f "$f" ]] || continue
    found="$f"; break
  done
  if [[ -z "$found" ]]; then
    show_motion 'กำลังสร้างกุญแจ' 600
    ssh-keygen -q -t ed25519 -f "$dir/id_ed25519" -N '' -C "${USER}@$(hostname -s 2>/dev/null || hostname)"
    found="$dir/id_ed25519.pub"
    made=1
  fi
  local line; line=$(grep -m1 -E '^ssh-' "$found" | tr -d '\r')
  if [[ $made -eq 1 ]]; then _green '  สร้างกุญแจให้แล้ว'; else _green '  ใช้กุญแจที่มีอยู่แล้ว'; fi
  _gray "  $found"
  show_fingerprint "$line"
  echo "$line"
}

read_pubkey_interactive() {
  _cyan '  ใช้กุญแจที่มีอยู่บนเครื่องนี้ ไม่ต้องวางไฟล์'
  show_fill 'หากุญแจ'
  get_auto_pubkey
}

# RFC 1918 ranges: 10.x, 172.16-31.x, 192.168.x
PRIVATE_RE='^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)'

lan_cidrs() {
  if [[ "$OS_KIND" == 'Darwin' ]]; then
    # ifconfig prints the mask in hex (0xffffff00): count its leading ones
    local ip mask m p
    while read -r ip mask; do
      [[ "$ip" =~ $PRIVATE_RE ]] || continue
      m=$((mask)); p=0
      while (( m & 0x80000000 )); do p=$((p + 1)); m=$(( (m << 1) & 0xFFFFFFFF )); done
      echo "$ip/$p"
    done < <(ifconfig 2>/dev/null | awk '/inet / {print $2, $4}')
    return 0
  fi
  ip -4 -o addr show 2>/dev/null | awk '{print $4}' | grep -E "$PRIVATE_RE" || true
}

# addresses of other machines this one has talked to recently
neighbors() {
  if [[ "$OS_KIND" == 'Darwin' ]]; then arp -an 2>/dev/null | awk -F'[()]' '{print $2}'; else ip neigh show 2>/dev/null | awk '{print $1}'; fi
}

lan_ips() {
  lan_cidrs | cut -d/ -f1
}

# network address of IP/prefix as CIDR
cidr_of() {
  local ip="$1" p="$2" a b c d n m
  IFS=. read -r a b c d <<<"$ip"
  n=$(( (a << 24) | (b << 16) | (c << 8) | d ))
  m=$(( (0xFFFFFFFF << (32 - p)) & 0xFFFFFFFF ))
  n=$(( n & m ))
  echo "$(( (n >> 24) & 255 )).$(( (n >> 16) & 255 )).$(( (n >> 8) & 255 )).$(( n & 255 ))/$p"
}

select_subnet() {
  declare -a cidrs=() notes=()
  local seen=' '
  add_choice() {
    local c="$1" n="$2"
    [[ -z "$c" ]] && return
    [[ "$seen" == *" $c "* ]] && return
    seen="$seen$c "
    cidrs+=("$c")
    notes+=("$n")
  }
  while read -r ipp; do
    [[ -n "$ipp" ]] || continue
    add_choice "$(cidr_of "${ipp%/*}" "${ipp#*/}")" "whole LAN (${ipp%/*})"
  done < <(lan_cidrs)

  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '22/tcp'; then
    ufw status numbered 2>/dev/null | grep '22/tcp' | head -1 | while read -r _; do :; done
    [[ -n "$SUBNET" ]] && add_choice "$SUBNET" 'current ufw (if set)'
  fi

  while read -r nip; do
    [[ -n "$nip" ]] || continue
    add_choice "${nip}/32" 'neighbor'
  done < <(neighbors | grep -E "$PRIVATE_RE" | sort -u)

  if [[ -r /var/log/auth.log ]]; then
    while read -r rip; do add_choice "${rip}/32" 'recent SSH'; done < <(
      grep -oE 'from [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' /var/log/auth.log 2>/dev/null | tail -20 | sed 's/from //' | sort -u
    )
  elif command -v journalctl >/dev/null 2>&1; then
    while read -r rip; do add_choice "${rip}/32" 'recent SSH'; done < <(
      journalctl -u ssh -u sshd --no-pager -n 40 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | grep -E "$PRIVATE_RE" | sort -u
    )
  fi

  _yellow '  เลือกหมายเลขของเครื่องที่จะเข้ามา'
  echo
  local i=1
  for idx in "${!cidrs[@]}"; do
    local note="${notes[$idx]}"
    case "$note" in
      whole*) note='ทั้งวงในบ้าน' ;;
      current*) note='ที่เปิดไว้อยู่ตอนนี้' ;;
      neighbor*) note='เจอในเครือข่าย' ;;
      recent*) note='เคยเข้ามาแล้ว' ;;
    esac
    printf '  \033[32m[%s]\033[0m \033[37m%s\033[0m   \033[90m%s\033[0m\n' "$i" "${cidrs[$idx]}" "$note"
    i=$((i + 1))
  done
  printf '  \033[32m[0]\033[0m \033[37mพิมพ์ IP เอง\033[0m\n\n'
  read -r -p '  หมายเลข: ' pick
  if [[ "$pick" == '0' ]]; then
    read -r -p '  IP เช่น 192.0.2.50:' manual
    if [[ "$manual" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then echo "${manual}/32"; return; fi
    if [[ "$manual" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]]; then echo "$manual"; return; fi
    _red '  รูปแบบ IP ไม่ถูก'; exit 1
  fi
  if ! [[ "$pick" =~ ^[0-9]+$ ]] || [[ "$pick" -lt 1 ]] || [[ "$pick" -gt ${#cidrs[@]} ]]; then
    _red '  เลือกหมายเลขในรายการ'; exit 1
  fi
  echo "${cidrs[$((pick - 1))]}"
}

apply_firewall_subnet() {
  local cidr="$1"
  local from="${cidr%/*}"
  [[ "$cidr" == */32 ]] && from="$from"

  if command -v ufw >/dev/null 2>&1; then
    ufw delete allow OpenSSH 2>/dev/null || true
    while ufw status numbered 2>/dev/null | grep -q '22/tcp'; do
      local num; num=$(ufw status numbered 2>/dev/null | grep '22/tcp' | head -1 | sed -n 's/^\[\([0-9]*\)\].*/\1/p')
      [[ -n "$num" ]] && ufw --force delete "$num" || break
    done
    ufw allow from "$from" to any port 22 proto tcp comment "$UFW_RULE_COMMENT" >/dev/null
    _green "  Firewall (ufw): 22 from $from"
    return
  fi

  if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
    firewall-cmd --permanent --remove-service=ssh 2>/dev/null || true
    firewall-cmd --permanent --add-rich-rule="rule family=\"ipv4\" source address=\"$from\" port port=\"22\" protocol=\"tcp\" accept" >/dev/null
    firewall-cmd --reload >/dev/null
    _green "  Firewall (firewalld): 22 from $from"
    return
  fi

  _yellow '  ไม่พบ ufw/firewalld — ตั้ง iptables เอง หรือติดตั้ง ufw'
}

write_sshd_dropin() {
  local user="$1"
  mkdir -p /etc/ssh/sshd_config.d
  cat >"$SSHD_DROPIN" <<EOF
# Managed by ssh-lan.sh — LAN hardening
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey
PermitEmptyPasswords no
MaxAuthTries 3
AllowUsers $user
EOF
  sshd -t
  systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || service ssh restart
}

cmd_status() {
  assert_root
  echo
  _cyan '--- Status ---'
  echo "Computer: $(hostname)  User: $LOGIN_USER"
  local svc='ssh'
  systemctl is-active ssh >/dev/null 2>&1 || svc='sshd'
  if systemctl is-active "$svc" >/dev/null 2>&1; then
    echo "sshd: active ($(systemctl is-enabled "$svc" 2>/dev/null || echo '?'))"
  else
    echo 'sshd: not running'
  fi
  if command -v ufw >/dev/null 2>&1; then
    echo "ufw 22: $(ufw status 2>/dev/null | grep -E '22/tcp|ssh-lan' | head -3 | tr '\n' '; ')"
  fi
  if ss -ltn 2>/dev/null | grep -q ':22 '; then echo 'Port 22 listen: yes'; else echo 'Port 22 listen: no'; fi
  local kf; kf=$(authorized_keys_path "$LOGIN_USER")
  echo "Key file: $kf"
  if [[ -f "$kf" ]]; then
    local cnt; cnt=$(grep -cE '^ssh-' "$kf" 2>/dev/null || echo 0)
    echo "Keys: $cnt"
    while read -r l; do show_fingerprint "$l"; done < <(grep -E '^ssh-' "$kf")
  fi
  echo "LAN IP: $(lan_ips | tr '\n' ', ' | sed 's/, $//')"
}

cmd_add_client() {
  assert_root
  local pub
  if [[ -n "$MY_PUB_KEY" || -n "$MY_PUB_KEY_PATH" ]]; then
    pub=$(resolve_pubkey)
  else
    pub=$(read_pubkey_interactive)
  fi
  local kf; kf=$(authorized_keys_path "$LOGIN_USER")
  if add_key_line "$kf" "$pub"; then _green '  เพิ่มกุญแจแล้ว'; else _green '  กุญแจนี้อยู่แล้ว ไม่ต้องทำซ้ำ'; fi
  chown "${LOGIN_USER}:${LOGIN_USER}" "$(dirname "$kf")" "$kf" 2>/dev/null || true
  systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true
  show_fingerprint "$pub"
}

cmd_harden() {
  assert_root
  need_cmd ssh-keygen
  systemctl is-active ssh >/dev/null 2>&1 || systemctl is-active sshd >/dev/null 2>&1 || {
    _yellow '  ติดตั้ง openssh-server ก่อน (เช่น apt install openssh-server)'
    exit 1
  }
  [[ -n "$SUBNET" ]] || { _red '  ต้องระบุ --subnet เช่น 192.0.2.0/24'; exit 1; }
  local sn="$SUBNET"
  local pub
  if [[ -n "$MY_PUB_KEY" ]]; then pub=$(resolve_pubkey)
  elif [[ -n "$MY_PUB_KEY_PATH" ]]; then pub=$(resolve_pubkey)
  elif [[ -f "${HOME}/.ssh/${SSH_IDENTITY}.pub" ]]; then pub=$(grep -m1 -E '^ssh-' "${HOME}/.ssh/${SSH_IDENTITY}.pub")
  else pub=$(read_pubkey_interactive)
  fi
  local kf; kf=$(authorized_keys_path "$LOGIN_USER")
  mkdir -p "$(dirname "$kf")"
  printf '%s\n' "$pub" >"$kf"
  chmod 600 "$kf"
  chown "${LOGIN_USER}:${LOGIN_USER}" "$(dirname "$kf")" "$kf" 2>/dev/null || true
  apply_firewall_subnet "$sn"
  if [[ -f /etc/ssh/sshd_config ]]; then
    cp -a /etc/ssh/sshd_config "/etc/ssh/sshd_config.bak-$(date +%Y%m%d-%H%M%S)"
  fi
  write_sshd_dropin "$LOGIN_USER"
  systemctl enable ssh 2>/dev/null || systemctl enable sshd 2>/dev/null || true
  echo
  _green "Harden OK. Firewall target: $sn"
  show_fingerprint "$pub"
  _gray 'Add more clients: menu [2] or ./ssh-lan.sh add-client'
}

cmd_remove() {
  assert_root
  rm -f "$SSHD_DROPIN"
  sshd -t 2>/dev/null && systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true
  if command -v ufw >/dev/null 2>&1; then
    while ufw status numbered 2>/dev/null | grep -q "$UFW_RULE_COMMENT\|22/tcp"; do
      local num; num=$(ufw status numbered 2>/dev/null | grep -E '22/tcp|ssh-lan' | head -1 | sed -n 's/^\[\([0-9]*\)\].*/\1/p')
      [[ -n "$num" ]] && ufw --force delete "$num" || break
    done
  fi
  if [[ "$UNINSTALL_SERVER" == '1' ]]; then
    if command -v apt-get >/dev/null 2>&1; then apt-get remove -y openssh-server 2>/dev/null || true
    elif command -v dnf >/dev/null 2>&1; then dnf remove -y openssh-server 2>/dev/null || true
    fi
  else
    systemctl stop ssh 2>/dev/null || systemctl stop sshd 2>/dev/null || true
    systemctl disable ssh 2>/dev/null || systemctl disable sshd 2>/dev/null || true
  fi
  _green 'Remove OK.'
}

backup_file() {
  local p="$1"
  [[ -f "$p" ]] && cp -a "$p" "${p}.bak-$(date +%Y%m%d-%H%M%S)"
}

set_editor_platform() {
  local path="$1"
  mkdir -p "$(dirname "$path")"
  if [[ ! -f "$path" ]]; then
    cat >"$path" <<EOF
{
  "remote.SSH.remotePlatform": {
    "${SSH_HOST_ALIAS}": "windows"
  }
}
EOF
    echo 'สร้างใหม่'
    return
  fi
  backup_file "$path"
  if grep -q "\"${SSH_HOST_ALIAS}\"" "$path" 2>/dev/null; then
    if grep -q "\"${SSH_HOST_ALIAS}\": \"windows\"" "$path"; then echo 'ตั้งไว้แล้ว'; return; fi
    sed_i "s/\"${SSH_HOST_ALIAS}\"[[:space:]]*:[[:space:]]*\"[^\"]*\"/\"${SSH_HOST_ALIAS}\": \"windows\"/" "$path"
    echo 'แก้แล้ว'
    return
  fi
  _yellow "  แก้ $path ด้วยมือ: remote.SSH.remotePlatform -> ${SSH_HOST_ALIAS}: windows"
  echo 'ต้องแก้ JSON เอง'
}

ssh_lan_port_open() {
  local host="$1"
  if command -v nc >/dev/null 2>&1; then
    nc -z -w2 "$host" 22 2>/dev/null
    return $?
  fi
  timeout 2 bash -c "echo >/dev/tcp/${host}/22" 2>/dev/null
}

ssh_lan_discover_server_ip() {
  local cfg="${HOME}/.ssh/config" old ip
  if [[ -n "$SSH_SERVER_IP" ]] && ssh_lan_port_open "$SSH_SERVER_IP"; then
    echo "$SSH_SERVER_IP"
    return 0
  fi
  if [[ -f "$cfg" ]]; then
    old=$(grep -A6 -E "^Host[[:space:]]+${SSH_HOST_ALIAS}" "$cfg" 2>/dev/null | awk '/HostName/{print $2; exit}')
    if [[ -n "$old" ]] && ssh_lan_port_open "$old"; then
      echo "$old"
      return 0
    fi
  fi
  for ip in $SSH_SERVER_IP_SEARCH; do
    ssh_lan_port_open "$ip" && { echo "$ip"; return 0; }
  done
  if [[ -n "$SSH_SERVER_HOST" ]] && ssh_lan_port_open "$SSH_SERVER_HOST" 2>/dev/null; then
    resolve_host "$SSH_SERVER_HOST"
    return 0
  fi
  # nothing known answered: look at the whole local network and keep the host our key opens
  local found; found=$(sweep_ssh_hosts | sort -u)
  [[ -n "$found" ]] || return 1
  if [[ $(echo "$found" | wc -l) -gt 1 ]]; then
    for ip in $found; do
      if ssh -o BatchMode=yes -o ConnectTimeout=3 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o LogLevel=ERROR -o IdentitiesOnly=yes -i "${HOME}/.ssh/${SSH_IDENTITY}" "${SSH_SERVER_USER}@${ip}" exit 2>/dev/null; then
        echo "$ip"; return 0
      fi
    done
  fi
  echo "$found" | head -n1
}

# every address in the local /24 that answers on port 22 (shortcut: /24 only, even on a wider network)
sweep_ssh_hosts() {
  local ip base i
  while read -r ip; do
    [[ -n "$ip" ]] || continue
    base="${ip%.*}"
    for i in $(seq 1 254); do
      [[ "$base.$i" == "$ip" ]] && continue
      ( ssh_lan_port_open "$base.$i" && echo "$base.$i" ) &
    done
  done < <(lan_ips)
  wait
}

ensure_client_ssh_config() {
  local cfg="${HOME}/.ssh/config"
  SSH_SERVER_IP="$(ssh_lan_discover_server_ip || true)"
  if [[ -f "$cfg" ]] && grep -qE "^Host[[:space:]]+${SSH_HOST_ALIAS}" "$cfg" 2>/dev/null; then
    set_client_ssh_config >/dev/null
    return 0
  fi
  set_client_ssh_config >/dev/null
}

# Linux OpenSSH ปฏิเสธ private key ถ้าไม่ใช่ 600 — Windows ไม่มีกฎนี้ (เลย ps1 ไม่ต้อง chmod)
fix_client_ssh_permissions() {
  local dir="${HOME}/.ssh"
  [[ -d "$dir" ]] || return 0
  chmod 700 "$dir" 2>/dev/null || true
  local f mode
  for f in "$dir"/config "$dir"/authorized_keys "$dir"/known_hosts; do
    [[ -f "$f" ]] && chmod 600 "$f" 2>/dev/null || true
  done
  shopt -s nullglob
  for f in "$dir"/id_* "$dir"/*_ed25519 "$dir"/*_rsa; do
    [[ -f "$f" ]] || continue
    [[ "$f" == *.pub ]] && continue
    mode=$(stat -c '%a' "$f" 2>/dev/null || stat -f '%Lp' "$f" 2>/dev/null || echo '')
    if [[ -n "$mode" && "$mode" != '600' && "$mode" != '400' ]]; then
      _yellow "  แก้สิทธิ์ $(basename "$f") (${mode} → 600)"
    fi
    chmod 600 "$f" 2>/dev/null || true
  done
  for f in "$dir"/*.pub; do
    [[ -f "$f" ]] && chmod 644 "$f" 2>/dev/null || true
  done
  shopt -u nullglob 2>/dev/null || true
}

ssh_lan_test_batch() {
  ssh -o BatchMode=yes -o ConnectTimeout=8 "$@" "${SSH_HOST_ALIAS}" exit 0 2>/dev/null
}

ssh_lan_test_with_key() {
  local keyfile="$1"
  ssh -o BatchMode=yes -o ConnectTimeout=8 -i "$keyfile" -o IdentitiesOnly=yes \
    "${SSH_SERVER_USER}@${SSH_SERVER_IP}" exit 0 2>/dev/null
}

ssh_lan_find_working_identity() {
  local dir="${HOME}/.ssh" f
  fix_client_ssh_permissions
  shopt -s nullglob
  local try=(
    "$dir/${SSH_IDENTITY}"
    "$dir/id_ed25519"
    "$dir/id_rsa"
  )
  for f in "${try[@]}" "$dir"/id_* "$dir"/*_ed25519 "$dir"/*_rsa; do
    [[ -f "$f" ]] || continue
    [[ "$f" == *.pub ]] && continue
    ssh_lan_test_with_key "$f" && { echo "$f"; return 0; }
  done
  return 1
}


ssh_lan_push_server_pubkey() {
  local via="$1"
  local pub="${HOME}/.ssh/${SSH_IDENTITY}.pub"
  [[ -f "$pub" ]] || return 1
  need_cmd scp
  local remote_pub='AppData/Local/Temp/ssh-lan-client.pub'
  scp -o BatchMode=yes -o ConnectTimeout=20 -i "$via" -o IdentitiesOnly=yes \
    "$pub" "${SSH_SERVER_USER}@${SSH_SERVER_IP}:${remote_pub}" 2>/dev/null || return 1
  ssh -o BatchMode=yes -o ConnectTimeout=20 -i "$via" -o IdentitiesOnly=yes \
    "${SSH_SERVER_USER}@${SSH_SERVER_IP}" \
    'powershell -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference=\"Stop\"; $kf=\"$env:ProgramData\ssh\administrators_authorized_keys\"; $p=Join-Path $env:LOCALAPPDATA \"Temp\ssh-lan-client.pub\"; if(-not(Test-Path -LiteralPath $p)){exit 2}; $l=(Get-Content -LiteralPath $p -Raw).Trim(); if($l -notmatch \"^ssh-\"){exit 3}; $dir=Split-Path $kf; if(-not(Test-Path -LiteralPath $dir)){New-Item -ItemType Directory -Force -Path $dir|Out-Null}; if((Test-Path -LiteralPath $kf) -and (Select-String -LiteralPath $kf -SimpleMatch $l -Quiet)){exit 0}; Add-Content -LiteralPath $kf -Value $l -Encoding ascii; icacls $kf /inheritance:r /grant \"Administrators:F\" /grant \"SYSTEM:F\" | Out-Null; Restart-Service sshd -Force -ErrorAction SilentlyContinue"' \
    2>/dev/null || return 1
  return 0
}

# เมนู [1] ขั้นกุญแจ: chmod, ดึงจาก เซิร์ฟเวอร์, สร้าง, ลงทะเบียนบน เซิร์ฟเวอร์ — ไม่ถาม Y/n
ensure_client_identity() {
  need_cmd ssh
  need_cmd ssh-keygen
  local dir key pub working
  dir="${HOME}/.ssh"
  key="${dir}/${SSH_IDENTITY}"
  pub="${key}.pub"
  mkdir -p "$dir"
  fix_client_ssh_permissions
  ensure_client_ssh_config

  if ssh_lan_test_batch; then
    _green "  เซิร์ฟเวอร์พร้อมใช้ (${SSH_HOST_ALIAS})"
    ssh-keygen -lf "$pub" 2>/dev/null || ssh-keygen -lf "$key" 2>/dev/null || true
    return 0
  fi

  working=$(ssh_lan_find_working_identity || true)

  if [[ ! -f "$key" || ! -f "$pub" ]]; then
    # every machine makes its own key pair: a private key is never copied from another machine
    show_motion "สร้าง ${SSH_IDENTITY}" 500
    ssh-keygen -q -t ed25519 -f "$key" -N '' -C "${USER}@$(hostname -s 2>/dev/null || hostname)-ssh-lan"
    _green "  สร้างคู่กุญแจ ${SSH_IDENTITY}"
    fix_client_ssh_permissions
  fi

  if ssh_lan_test_batch; then
    _green "  เซิร์ฟเวอร์พร้อมใช้ (${SSH_HOST_ALIAS})"
    return 0
  fi

  working=$(ssh_lan_find_working_identity || true)
  if [[ -n "$working" ]]; then
    show_motion 'ลงทะเบียนกุญแจบน เซิร์ฟเวอร์' 800
    if ssh_lan_push_server_pubkey "$working"; then
      _green '  ใส่กุญแจบน เซิร์ฟเวอร์ แล้ว (administrators_authorized_keys)'
      sleep 2
      if ssh_lan_test_batch; then
        _green "  เซิร์ฟเวอร์พร้อมใช้ (${SSH_HOST_ALIAS})"
        return 0
      fi
    fi
  fi

  if [[ -f "$pub" ]]; then
    _gray '  fingerprint บนเครื่องนี้ (ต้องตรงกับ เซิร์ฟเวอร์ ถ้ายังเข้าไม่ได้):'
    ssh-keygen -lf "$pub" 2>/dev/null || true
  fi
  _red '  ยังเข้า เซิร์ฟเวอร์ ไม่ได้ — ต้องมีกุญแจอื่นที่ เซิร์ฟเวอร์ รู้จักอยู่แล้ว หรือเปิดรหัสผ่านชั่วคราวบน เซิร์ฟเวอร์'
  return 1
}

ssh_lan_connect_test() {
  need_cmd ssh
  ensure_client_ssh_config
  fix_client_ssh_permissions
  if ssh -o BatchMode=yes -o ConnectTimeout=8 "${SSH_HOST_ALIAS}" hostname 2>/dev/null; then
    return 0
  fi
  ensure_client_identity && ssh -o BatchMode=yes -o ConnectTimeout=8 "${SSH_HOST_ALIAS}" hostname
}

set_client_ssh_config() {
  local dir cfg
  dir="${HOME}/.ssh"
  cfg="${dir}/config"
  mkdir -p "$dir"
  chmod 700 "$dir"
  if [[ -z "${SSH_SERVER_IP:-}" ]]; then
    SSH_SERVER_IP="$(ssh_lan_discover_server_ip || true)"
    [[ -n "$SSH_SERVER_IP" ]] || { _red '  ไม่พบเซิร์ฟเวอร์ที่เปิดพอร์ต 22 — ตั้ง SSH_SERVER_IP หรือ SSH_SERVER_IP_SEARCH'; return 1; }
  fi
  local block
  block=$(cat <<EOF
Host ${SSH_HOST_ALIAS} ${SSH_SERVER_IP}
  HostName ${SSH_SERVER_IP}
  User ${SSH_SERVER_USER}
  IdentityFile ~/.ssh/${SSH_IDENTITY}
  IdentitiesOnly yes
  StrictHostKeyChecking accept-new
EOF
)
  if [[ ! -f "$cfg" ]]; then
    printf '%s\n' "$block" >"$cfg"
    chmod 600 "$cfg"
    echo 'สร้างใหม่'
    return
  fi
  if grep -qE "^Host[[:space:]]+${SSH_HOST_ALIAS}([[:space:]]|$)" "$cfg"; then
    backup_file "$cfg"
    # POSIX awk, so it runs the same on Linux and macOS: new Host line, and the HostName inside this block only
    awk -v a="$SSH_HOST_ALIAS" -v ip="$SSH_SERVER_IP" '
      /^Host[ \t]/ { inb = ($2 == a); if (inb) { print "Host " a " " ip; next } }
      inb && /^[ \t]*HostName[ \t]/ { print "  HostName " ip; next }
      { print }' "$cfg" >"$cfg.tmp" && mv "$cfg.tmp" "$cfg"
    chmod 600 "$cfg"
    echo "อัปเดต IP → ${SSH_SERVER_IP}"
    return
  fi
  backup_file "$cfg"
  printf '\n%s\n' "$block" >>"$cfg"
  chmod 600 "$cfg"
  echo 'เพิ่มแล้ว'
}

# --- pairing: put this machine's key on another machine (Windows, Linux or macOS) ---
# Every machine keeps its own key pair. Only public keys travel; no private key is ever copied.

# a public key line ends up inside a command on another machine: only known-safe characters pass
valid_pub() {
  local re='^(ssh-(ed25519|rsa)|ecdsa-sha2-nistp[0-9]{3}) [A-Za-z0-9+/=]+( [A-Za-z0-9@._-]+)?$'
  [[ "$1" =~ $re ]]
}

own_key() {
  local key="${HOME}/.ssh/${SSH_IDENTITY}"
  mkdir -p "${HOME}/.ssh"; chmod 700 "${HOME}/.ssh"
  [[ -f "$key.pub" ]] || ssh-keygen -q -t ed25519 -N '' -f "$key" -C "${USER}@$(hostname -s 2>/dev/null || hostname)-ssh-lan"
  echo "$key"
}

# PowerShell's -EncodedCommand takes UTF-16LE base64, so no quoting survives the trip through cmd.exe
b64_utf16() { printf '%s' "$1" | iconv -f UTF-8 -t UTF-16LE | base64 | tr -d '\n'; }

win_push_script() {
  sed "s|__KEY__|$1|" <<'PS'
$ProgressPreference='SilentlyContinue'; $k='__KEY__'; $adm=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole('Administrators')
$f=if($adm){Join-Path $env:ProgramData 'ssh\administrators_authorized_keys'}else{Join-Path $env:USERPROFILE '.ssh\authorized_keys'}
New-Item -Force -ItemType Directory (Split-Path $f)|Out-Null
if(-not(Test-Path $f) -or -not(Select-String -LiteralPath $f -SimpleMatch -Quiet $k)){Add-Content -LiteralPath $f -Value $k -Encoding ascii}
if($adm){icacls $f /inheritance:r /grant 'Administrators:F' /grant 'SYSTEM:F'|Out-Null}
PS
}

win_fetch_script() {
  sed "s|__LEAF__|$1|" <<'PS'
$ProgressPreference='SilentlyContinue'; $k=Join-Path $env:USERPROFILE '.ssh\__LEAF__'
if(-not(Test-Path "$k.pub")){New-Item -Force -ItemType Directory (Split-Path $k)|Out-Null; Start-Process ssh-keygen -ArgumentList "-q -t ed25519 -N `"`" -f `"$k`"" -NoNewWindow -Wait}
Get-Content "$k.pub" -TotalCount 1
PS
}

# one Host block per paired machine in ~/.ssh/config, replaced when it is already there
add_host_entry() {
  local alias="$1" host="$2" user="$3" key="$4" cfg="${HOME}/.ssh/config" tmp
  touch "$cfg"; chmod 600 "$cfg"; backup_file "$cfg"
  tmp=$(mktemp)
  awk -v a="$alias" '/^Host[ \t]/ { skip = ($2 == a && NF == 2) } !skip { print }' "$cfg" >"$tmp"
  {
    cat "$tmp"
    printf '\nHost %s\n  HostName %s\n  User %s\n  IdentityFile ~/.ssh/%s\n  IdentitiesOnly yes\n  StrictHostKeyChecking accept-new\n' "$alias" "$host" "$user" "$(basename "$key")"
  } >"$cfg"
  rm -f "$tmp"; chmod 600 "$cfg"
}

pair_list_hosts() {
  echo '  กำลังสแกนหาเครื่องที่เปิดพอร์ต 22 ในวง LAN...'
  local found; found=$(sweep_ssh_hosts | sort -u)
  if [[ -z "$found" ]]; then _yellow '  ไม่พบเครื่องที่เปิดรับ SSH'; return 0; fi
  echo "$found" | sed 's/^/  พบ /'
  _gray '  จับคู่: ./ssh-lan.sh pair --target ผู้ใช้@IP [--both]'
}

# menu entry: ask for the target (empty = list what answers on port 22), then pair
pair_prompt() {
  read -r -p '  ผู้ใช้@IP ของเครื่องที่จะจับคู่ (ว่าง = สแกนหาเครื่อง): ' PAIR_TARGET
  PAIR_BOTH=0
  if [[ -n "$PAIR_TARGET" ]]; then
    read -r -p '  ให้เครื่องนั้นเข้ามาหาเครื่องนี้ด้วยไหม [y/N] ' r
    [[ "$r" =~ ^[yY] ]] && PAIR_BOTH=1
  fi
  cmd_pair
}

cmd_pair() {
  need_cmd ssh; need_cmd ssh-keygen; need_cmd ssh-keyscan
  local target="$PAIR_TARGET" user="$PAIR_USER"
  [[ -n "$target" ]] || { pair_list_hosts; return 0; }
  if [[ "$target" == *@* ]]; then user="${target%@*}"; target="${target#*@}"; fi
  [[ "$target" =~ ^[A-Za-z0-9][A-Za-z0-9.-]*$ ]] || { _red '  ชื่อหรือ IP ของเครื่องปลายทางไม่ถูกต้อง'; return 1; }
  [[ -n "$user" ]] || user="$SSH_SERVER_USER"
  [[ "$user" =~ ^[A-Za-z0-9._-]+$ ]] || { _red '  ชื่อผู้ใช้ของเครื่องปลายทางไม่ถูกต้อง'; return 1; }
  [[ -z "$PAIR_ALIAS" || "$PAIR_ALIAS" =~ ^[A-Za-z0-9._-]+$ ]] || { _red '  ชื่อเรียก (alias) ใช้ได้เฉพาะ a-z 0-9 . _ -'; return 1; }
  ssh_lan_port_open "$target" || { _red "  เครื่อง $target ไม่ตอบที่พอร์ต 22 — เปิดรับ SSH บนเครื่องนั้นก่อน"; return 1; }

  local key pub; key=$(own_key); pub=$(head -n1 "$key.pub")
  valid_pub "$pub" || { _red '  รูปแบบ public key ไม่ถูกต้อง'; return 1; }

  # the server's own banner tells Windows (OpenSSH_for_Windows) from Linux and macOS, which take the same commands
  local windows=0 remote
  if ssh-keyscan -T 3 "$target" 2>&1 | grep -qi 'for_windows'; then windows=1; fi
  if [[ $windows -eq 1 ]]; then
    echo '  เครื่องปลายทาง: Windows'
    remote="powershell -NoProfile -EncodedCommand $(b64_utf16 "$(win_push_script "$pub")")"
  else
    echo '  เครื่องปลายทาง: Linux / macOS'
    remote="umask 077; mkdir -p ~/.ssh; touch ~/.ssh/authorized_keys; grep -qxF '$pub' ~/.ssh/authorized_keys || echo '$pub' >> ~/.ssh/authorized_keys"
  fi

  echo '  ใส่รหัสผ่านของเครื่องปลายทางเมื่อถูกถาม (สคริปต์นี้ไม่เห็นรหัสผ่าน)'
  if ! ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 "$user@$target" "$remote"; then
    _red '  ใส่กุญแจที่เครื่องปลายทางไม่สำเร็จ — ตรวจชื่อผู้ใช้/รหัสผ่าน และดูว่าเครื่องนั้นยังเปิดให้ล็อกอินด้วยรหัสผ่านอยู่'
    return 1
  fi

  # prove it: the key alone must open the door now
  local common=(-o BatchMode=yes -o ConnectTimeout=8 -o IdentitiesOnly=yes -i "$key" "$user@$target") name
  if ! name=$(ssh "${common[@]}" hostname 2>/dev/null | head -n1 | tr -d '\r'); then
    _red '  ใส่กุญแจแล้ว แต่ยังเข้าด้วยกุญแจไม่ได้ — เครื่องปลายทางอาจไม่ยอมรับ public key'
    return 1
  fi
  local alias="$PAIR_ALIAS"
  [[ -n "$alias" ]] || alias=$(printf '%s' "$name" | tr 'A-Z' 'a-z' | tr -c 'a-z0-9\n-' '-' | sed 's/^-*//;s/-*$//')
  [[ -n "$alias" ]] || alias="$target"
  add_host_entry "$alias" "$target" "$user" "$key"
  _green "  [✓] จับคู่สำเร็จ: เครื่องนี้เข้า $target ได้แล้ว ลอง  ssh $alias"

  [[ "$PAIR_BOTH" == '1' ]] || return 0

  # the other way round: take the target's PUBLIC key (made there if it has none) and allow it here
  local leaf fetch theirs; leaf=$(basename "$key")
  if [[ $windows -eq 1 ]]; then
    fetch="powershell -NoProfile -EncodedCommand $(b64_utf16 "$(win_fetch_script "$leaf")")"
  else
    fetch="mkdir -p ~/.ssh; test -f ~/.ssh/$leaf.pub || ssh-keygen -q -t ed25519 -N '' -f ~/.ssh/$leaf; head -n1 ~/.ssh/$leaf.pub"
  fi
  theirs=$(ssh "${common[@]}" "$fetch" 2>/dev/null | head -n1 | tr -d '\r')
  valid_pub "$theirs" || { _red '  ดึง public key ของเครื่องปลายทางไม่สำเร็จ'; return 1; }
  if ! is_server; then
    _yellow '  [!] เครื่องนี้ยังไม่เปิดรับ SSH จึงยังให้เครื่องนั้นเข้ามาไม่ได้ (เปิด sshd / Remote Login แล้วจับคู่อีกครั้ง)'
    return 0
  fi
  add_key_line "${HOME}/.ssh/authorized_keys" "$theirs" || true
  _green "  [✓] เครื่องนั้นเข้าเครื่องนี้ได้แล้ว: ที่เครื่องนั้นพิมพ์  ssh ${USER}@$(lan_ips | head -n1)"
}

repair_client() {
  local steps=('ตั้งโปรแกรมให้รู้ว่า เซิร์ฟเวอร์ เป็น Windows' 'จัดไฟล์ SSH' 'ตรวจกุญแจ' 'ทดสอบเชื่อมต่อ')
  show_steps 'จัดการเครื่องนี้' 1 "${steps[@]}"
  show_fill 'VS Code / Cursor'
  for pair in "Code:${HOME}/.config/Code/User/settings.json" "Cursor:${HOME}/.config/Cursor/User/settings.json"; do
    local name="${pair%%:*}" path="${pair#*:}"
    [[ "$name" == 'Cursor' && ! -d "$(dirname "$path")" ]] && continue
    local r; r=$(set_editor_platform "$path")
    _green "  $name: $r"
  done
  show_steps 'จัดการเครื่องนี้' 2 "${steps[@]}"
  show_fill 'ไฟล์ SSH'
  _green "  $(set_client_ssh_config)"
  show_steps 'จัดการเครื่องนี้' 3 "${steps[@]}"
  show_fill 'กุญแจ'
  ensure_client_identity || true
  show_steps 'จัดการเครื่องนี้' 4 "${steps[@]}"
  show_fill 'เชื่อมต่อ'
  ssh_lan_connect_test 2>&1 || _yellow '  ทดสอบไม่ผ่าน — ดูข้อความด้านบน'
  echo
  _green "  เสร็จ ปิด VS Code/Cursor แล้วเปิดใหม่ แล้วเชื่อม ${SSH_HOST_ALIAS}"
  echo
}

start_enable() {
  local steps=('เลือก IP ที่เข้าได้' 'เตรียมกุญแจให้' 'เปิดใช้')
  show_steps 'เปิดใช้' 1 "${steps[@]}"
  SUBNET=$(select_subnet)
  show_motion "เลือก $SUBNET"
  show_steps 'เปิดใช้' 2 "${steps[@]}"
  MY_PUB_KEY=$(get_auto_pubkey)
  show_motion 'ตรวจกุญแจ'
  show_steps 'เปิดใช้' 3 "${steps[@]}"
  show_motion 'กำลังเปิดใช้' 900
  cmd_harden
  echo
  _green '  เสร็จแล้ว ไม่ต้องกดเมนู 2'
  _yellow '  จากเครื่องอื่น: ssh HOST_ALIAS hostname (ใช้ชื่อใน ~/.ssh/config ไม่ใช่ IP ลอยๆ)'
  echo "  ssh ${SSH_HOST_ALIAS} hostname"
  echo
}

start_disable() {
  local steps=('ดูว่าจะปิดอะไร' 'ยืนยัน' 'ปิด')
  show_steps 'ถอน' 1 "${steps[@]}"
  _yellow '  [1] ปิดรับเข้า ยังเก็บโปรแกรมไว้'
  _red '  [2] ปิดรับเข้า และถอน openssh-server'
  _gray '  [0] กลับ'
  echo
  read -r -p '  หมายเลข: ' mode
  [[ "$mode" == '0' ]] && return
  [[ "$mode" == '1' || "$mode" == '2' ]] || { _red '  เลือก 1 หรือ 2'; exit 1; }
  show_steps 'ถอน' 2 "${steps[@]}"
  _yellow '  พิมพ์ YES เพื่อยืนยัน'
  read -r -p '  ' y
  [[ "$y" == 'YES' ]] || { _gray '  ยกเลิก'; return; }
  show_steps 'ถอน' 3 "${steps[@]}"
  show_motion 'กำลังปิด' 900
  if [[ "$mode" == '2' ]]; then UNINSTALL_SERVER=1; fi
  cmd_remove
  echo
  _green '  ปิดแล้ว เครื่องนี้ไม่รับ SSH จากวง LAN'
  echo
}

show_menu() {
  clear
  local server=0 role adm
  is_server && server=1
  if [[ $server -eq 1 ]]; then role='เครื่องรับ SSH'; else role='เครื่องที่ใช้เชื่อมต่อ'; fi
  if [[ $server -eq 1 ]]; then
    if [[ "$(id -u)" -eq 0 ]] || have_sudo; then adm='มี sudo/root'; else adm='ยังไม่มี sudo'; fi
  else
    adm='ไม่ต้องใช้ sudo'
  fi
  echo
  _magenta '  +--------------------------------+'
  _cyan '  |  SSH ในบ้าน'
  _gray "  |  script ${SSH_LAN_VERSION}"
  echo "  |  $(hostname -s 2>/dev/null || hostname)  $role"
  _gray "  |  $adm"
  _magenta '  +--------------------------------+'
  echo
  _green '  [1]  จัดการให้ครบ'
  if [[ $server -eq 1 ]]; then
    _gray '       เปิดรับ, กุญแจเดียว, ปิดรหัสผ่าน'
    _yellow '  [2]  ใส่กุญแจบนเครื่องนี้อีกครั้ง (ไม่บังคับ)'
    _cyan '  [3]  ดูสถานะ'
    _red '  [4]  ถอน'
    _cyan '  [5]  จับคู่กับเครื่องอื่น'
  else
    _gray '       ตั้ง Windows, จัด SSH, ทดสอบเข้า เซิร์ฟเวอร์'
    _cyan '  [2]  ทดสอบเชื่อมต่ออีกครั้ง'
    _cyan '  [3]  จับคู่กับเครื่องอื่น'
  fi
  _gray '  [0]  ออก'
  echo
}

start_tui() {
  show_boot
  while true; do
    show_menu
    printf '  \033[36m>\033[0m '
    read -r c || exit 0
    set +e
    if is_server; then
      case "$c" in
        1) start_enable; pause ;;
        2) cmd_add_client; pause ;;
        3) cmd_status; pause ;;
        4) start_disable; pause ;;
        5) pair_prompt; pause ;;
        0) exit 0 ;;
        *) _yellow '  กดหมายเลขในเมนู'; sleep 0.6 ;;
      esac
    else
      case "$c" in
        1) repair_client; pause ;;
        2) show_fill 'ทดสอบ'; ssh_lan_connect_test 2>&1 || _yellow '  ทดสอบไม่ผ่าน — รัน [1] หรือตรวจกุญแจบน เซิร์ฟเวอร์'; pause ;;
        3) pair_prompt; pause ;;
        0) exit 0 ;;
        *) _yellow '  กดหมายเลขในเมนู'; sleep 0.6 ;;
      esac
    fi
    set -e
  done
}

case "$ACTION" in
  '') start_tui ;;
  help) show_menu ;;
  status) cmd_status ;;
  add-client) cmd_add_client ;;
  harden)
    [[ -n "$SUBNET" ]] || { _red '  ต้องระบุ --subnet เช่น 192.0.2.0/24'; exit 1; }
    cmd_harden
    ;;
  remove) cmd_remove ;;
  client) repair_client ;;
  pair) cmd_pair ;;
  *) _red "Unknown action: $ACTION"; exit 2 ;;
esac
