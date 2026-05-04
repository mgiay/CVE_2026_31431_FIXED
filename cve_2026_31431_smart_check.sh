#!/bin/bash
# Re-execute with bash neu dang chay bang sh/dash
[ -z "${BASH_VERSION:-}" ] && exec bash "$0" "$@"
set -euo pipefail
# =================================================================
# Script: cve_2026_31431_smart_check.sh
# Chuc nang: Scan, Fix & Auto-detect Hardening status
# Tuong thich: Ubuntu, Debian, CentOS
# Usage:  ./cve_2026_31431_smart_check.sh [--check|--fix|--help]
# =================================================================

readonly CONF_FILE="/etc/modprobe.d/cve-2026-31431.conf"
readonly MODULE="algif_aead"
readonly LOG_TAG="CVE-2026-31431"
readonly KERNEL_VER="$(uname -r)"

# -------------------------------------------------------------------
# 0. CLI flags & helpers
# -------------------------------------------------------------------
usage() {
    cat <<'EOF'
Usage: cve_2026_31431_smart_check.sh [FLAG]

Flags:
  --scan     Chay kiem tra tuong tac (hoi truoc khi sua neu phat hien nguy co)
  --check    Chi kiem tra trang thai, khong tuong tac (exit code phan anh ket qua)
  --fix      Tu dong hardening neu he thong nam trong vung anh huong
  --help     Hien thi tro giup nay

Khong flag:  Hien thi huong dan su dung nay.
Exit codes:  0=safe/hardened, 1=ok, 2=vulnerable, 3=error
EOF
    exit 0
}

log_msg() { logger -t "$LOG_TAG" "$1"; }

# Kiem tra stdout co phai terminal khong (de bat mau ANSI)
if [ -t 1 ]; then
    GREEN='\033[0;32m' BLUE='\033[0;34m' YELLOW='\033[0;33m' RED='\033[0;31m' NC='\033[0m'
else
    GREEN='' BLUE='' YELLOW='' RED='' NC=''
fi

# -------------------------------------------------------------------
# 1. Quyen root
# -------------------------------------------------------------------
require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        printf '%b\n' "${RED}Loi: Script nay phai duoc chay voi quyen root.${NC}" >&2
        exit 3
    fi
}

# -------------------------------------------------------------------
# 2. Parse kernel version (robust, LC_ALL=C)
# -------------------------------------------------------------------
parse_kernel() {
    local maj min
    # Chi lay phan so, bo qua suffix (-generic, .el7, ...)
    # Vi du: 5.15.0-91-generic -> 5.15.0
    local ver_numeric
    ver_numeric="$(echo "$1" | LC_ALL=C sed -n 's/^\([0-9]\+\.[0-9]\+\).*/\1/p')"
    maj="${ver_numeric%%.*}"
    min="${ver_numeric#*.}"
    min="${min%%.*}"   # Cat bo patch level neu co (5.15.0 -> 15)

    [ -z "$maj" ] && maj=0
    [ -z "$min" ] && min=0

    K_MAJOR="$maj"
    K_MINOR="$min"
}

# -------------------------------------------------------------------
# 3. Kiem tra module loaded / da hardened
# -------------------------------------------------------------------
is_module_loaded()  { lsmod 2>/dev/null | grep -qw "$MODULE"; }
is_hardened()        { [ -f "$CONF_FILE" ]; }
is_vuln_kernel()     { [ "$K_MAJOR" -gt 4 ] || { [ "$K_MAJOR" -eq 4 ] && [ "$K_MINOR" -ge 10 ]; }; }

# -------------------------------------------------------------------
# 4. Apply fix
# -------------------------------------------------------------------
apply_fix() {
    printf '%b\n' "${BLUE}--- Dang tien hanh Hardening he thong... ---${NC}"

    cat > "$CONF_FILE" <<EOF
install $MODULE /bin/false
blacklist $MODULE
EOF
    log_msg "Da tao $CONF_FILE"

    modprobe -r "$MODULE" 2>/dev/null || true

    # Chi rebuild initramfs cho kernel hien tai (nhanh hon nhieu so voi "all")
    if command -v update-initramfs >/dev/null 2>&1; then
        update-initramfs -u -k "$KERNEL_VER"
        log_msg "update-initramfs da chay cho kernel $KERNEL_VER"
    elif command -v dracut >/dev/null 2>&1; then
        dracut -f --kver "$KERNEL_VER"
        log_msg "dracut da chay cho kernel $KERNEL_VER"
    fi

    printf '%b\n' "${GREEN}Thanh cong: Da cau hinh chan module ${MODULE}.${NC}"
    printf '%b\n' "${YELLOW}Luu y: Can reboot de dam bao module khong the bi nap lai.${NC}"
}

# -------------------------------------------------------------------
# 5. In ket qua
# -------------------------------------------------------------------
print_status() {
    local vuln="$1" hardened="$2" loaded="$3"

    printf '%s\n' "-------------------------------------------------------"
    printf '%s\n' "PHAN TICH HE THONG: $KERNEL_VER"

    if [ "$vuln" = "false" ]; then
        printf '%b\n' "${GREEN}[SAFE] Kernel cu khong bi anh huong boi CVE-2026-31431.${NC}"
        return 0

    elif [ "$hardened" = "true" ]; then
        printf '%b\n' "${BLUE}[INFO] He thong thuoc dien anh huong nhung DA DUOC HARDENING.${NC}"
        printf '%s\n' "Trang thai: Module $MODULE da bi chan nap (Blacklisted)."
        if [ "$loaded" = "true" ]; then
            printf '%b\n' "${YELLOW}[!] Luu y: Module van dang trong memory, se het sau khi reboot.${NC}"
        fi
        return 0

    elif [ "$loaded" = "false" ]; then
        printf '%b\n' "${GREEN}[OK] Module nguy hiem khong hoat dong va khong duoc ho tro trong nhan.${NC}"
        return 1

    else
        printf '%b\n' "${RED}[CRITICAL] CANH BAO: Phat hien nguy co cao CVE-2026-31431!${NC}"
        return 2
    fi
}

# -------------------------------------------------------------------
# 6. Interactive prompt
# -------------------------------------------------------------------
prompt_fix() {
    if command -v whiptail >/dev/null 2>&1; then
        if whiptail --title "XU LY AN NINH" --yesno \
            $'Phat hien lo hong CVE-2026-31431 dang hoat dong.\nBan co muon thuc hien Hardening (Disable module) ngay khong?' 12 60; then
            apply_fix
        fi
    else
        printf '%s' "Ban co muon xu ly ngay (y/n)? "
        read -r choice
        if [ "$choice" = "y" ] || [ "$choice" = "Y" ]; then
            apply_fix
        fi
    fi
}

# ===================================================================
# MAIN
# ===================================================================
require_root
parse_kernel "$KERNEL_VER"

VULN_RANGE=false
is_vuln_kernel && VULN_RANGE=true

MODULE_LOADED=false
is_module_loaded && MODULE_LOADED=true

HARDENED=false
is_hardened && HARDENED=true

MODE="${1:-}"

case "$MODE" in
    --help)
        usage
        ;;
    --scan)
        print_status "$VULN_RANGE" "$HARDENED" "$MODULE_LOADED"
        exit_code=$?
        if [ "$exit_code" -eq 2 ]; then
            prompt_fix
        fi
        printf '%s\n' "-------------------------------------------------------"
        log_msg "Scan completed (kernel=$KERNEL_VER vuln=$VULN_RANGE hardened=$HARDENED loaded=$MODULE_LOADED)"
        exit "$exit_code"
        ;;
    --check)
        print_status "$VULN_RANGE" "$HARDENED" "$MODULE_LOADED"
        exit $?
        ;;
    --fix)
        print_status "$VULN_RANGE" "$HARDENED" "$MODULE_LOADED"
        exit_code=$?
        if [ "$exit_code" -eq 2 ]; then
            apply_fix
            exit 0
        fi
        exit "$exit_code"
        ;;
    *)
        usage
        ;;
esac
