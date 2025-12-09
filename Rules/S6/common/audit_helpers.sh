#!/bin/bash
# Auditd Yardımcı Fonksiyonları

# Renk kodları
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# Auditd kurallarını yükle
reload_audit_rules() {
    if command -v augenrules &>/dev/null; then
        augenrules --load
        log_info "Audit rules reloaded"
    elif command -v service &>/dev/null; then
        service auditd restart
        log_info "Auditd service restarted"
    else
        systemctl restart auditd
        log_info "Auditd service restarted"
    fi
}

# Audit kuralını ekle (duplicate önleme)
add_audit_rule() {
    local rule_file="$1"
    local rule="$2"

    if [ ! -f "$rule_file" ]; then
        touch "$rule_file"
    fi

    if grep -Fxq "$rule" "$rule_file" 2>/dev/null; then
        log_info "Rule already exists: $rule"
    else
        echo "$rule" >> "$rule_file"
        log_info "Rule added: $rule"
    fi
}

# Privileged komutları bul ve audit kuralları oluştur
find_privileged_commands() {
    local output_file="${1:-/etc/audit/rules.d/50-privileged.rules}"

    log_info "Finding privileged commands..."

    > "$output_file"
    echo "# Privileged commands audit rules" >> "$output_file"

    find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | while read -r cmd; do
        echo "-a always,exit -F path=$cmd -F perm=x -F auid>=1000 -F auid!=unset -k privileged" >> "$output_file"
    done

    log_success "Privileged commands rules created"
}
