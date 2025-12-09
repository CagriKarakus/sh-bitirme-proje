#!/bin/bash
# PAM ve Güvenlik Yapılandırma Yardımcı Fonksiyonları
# Bu dosya diğer remediation scriptleri tarafından source edilebilir

# Renk kodları
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Log fonksiyonları
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

# PAM dosyalarını yedekle
# Kullanım: backup_pam_files
backup_pam_files() {
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local backup_dir="/etc/pam.d/.backup_${timestamp}"
    
    log_info "PAM dosyaları yedekleniyor: $backup_dir"
    
    mkdir -p "$backup_dir"
    cp /etc/pam.d/common-auth "$backup_dir/" 2>/dev/null
    cp /etc/pam.d/common-password "$backup_dir/" 2>/dev/null
    cp /etc/pam.d/common-account "$backup_dir/" 2>/dev/null
    cp /etc/pam.d/common-session "$backup_dir/" 2>/dev/null
    
    echo "$backup_dir"
}

# Yapılandırma dosyasında değer ayarla (duplicate önleme)
# Kullanım: set_config_value "/etc/security/faillock.conf" "deny" "5"
set_config_value() {
    local file="$1"
    local key="$2"
    local value="$3"
    
    # Dosya yoksa oluştur
    if [ ! -f "$file" ]; then
        touch "$file"
        log_info "Oluşturuldu: $file"
    fi
    
    # Mevcut değeri kontrol et (yorum satırı olmayan)
    if grep -qi "^${key}\s*=" "$file" 2>/dev/null; then
        # Mevcut değeri güncelle
        sed -i "s/^${key}\s*=.*/${key} = ${value}/" "$file"
        log_info "Güncellendi: ${key} = ${value}"
    elif grep -qi "^#\s*${key}\s*=" "$file" 2>/dev/null; then
        # Yorum satırını aktifleştir ve değeri güncelle
        sed -i "s/^#\s*${key}\s*=.*/${key} = ${value}/" "$file"
        log_info "Aktifleştirildi: ${key} = ${value}"
    else
        # Yeni satır ekle
        echo "${key} = ${value}" >> "$file"
        log_info "Eklendi: ${key} = ${value}"
    fi
}

# Yapılandırma dosyasında bayrak ayarla (değersiz parametre)
# Kullanım: set_config_flag "/etc/security/faillock.conf" "even_deny_root"
set_config_flag() {
    local file="$1"
    local flag="$2"
    
    # Dosya yoksa oluştur
    if [ ! -f "$file" ]; then
        touch "$file"
        log_info "Oluşturuldu: $file"
    fi
    
    # Mevcut bayrak kontrol et
    if grep -qi "^${flag}\s*$" "$file" 2>/dev/null || grep -qi "^${flag}\s*=" "$file" 2>/dev/null; then
        log_info "Zaten mevcut: ${flag}"
    elif grep -qi "^#\s*${flag}" "$file" 2>/dev/null; then
        # Yorum satırını aktifleştir
        sed -i "s/^#\s*${flag}.*/${flag}/" "$file"
        log_info "Aktifleştirildi: ${flag}"
    else
        # Yeni satır ekle
        echo "${flag}" >> "$file"
        log_info "Eklendi: ${flag}"
    fi
}

# faillock.conf'un doğru yapılandırıldığını kontrol et
# Kullanım: check_faillock_configured
check_faillock_configured() {
    local deny=$(grep -Pi "^\s*deny\s*=" /etc/security/faillock.conf 2>/dev/null | grep -oP '\d+')
    local unlock_time=$(grep -Pi "^\s*unlock_time\s*=" /etc/security/faillock.conf 2>/dev/null | grep -oP '\d+')
    
    if [ -z "$deny" ] || [ -z "$unlock_time" ]; then
        log_error "faillock.conf tam yapılandırılmamış!"
        log_error "Önce 5.3.3.1.1 ve 5.3.3.1.2 kurallarını uygulayın!"
        return 1
    fi
    
    log_info "faillock.conf yapılandırması: deny=$deny, unlock_time=$unlock_time"
    return 0
}

# PAM satırında opsiyon ekle (duplicate önleme)
# Kullanım: add_pam_option "/etc/pam.d/common-password" "pam_unix.so" "yescrypt"
add_pam_option() {
    local file="$1"
    local module="$2"
    local option="$3"
    
    # Opsiyon zaten var mı kontrol et
    if grep -P "^\s*password\s+.*${module}.*\b${option}\b" "$file" &>/dev/null; then
        log_info "${option} zaten ${module} için yapılandırılmış"
        return 0
    fi
    
    # Opsiyonu ekle
    sed -i "/${module}/s/$/ ${option}/" "$file"
    log_info "${option} eklendi: ${module}"
}

# PAM satırından opsiyon kaldır
# Kullanım: remove_pam_option "/etc/pam.d/common-password" "nullok"
remove_pam_option() {
    local file="$1"
    local option="$2"
    
    if grep -q "\b${option}\b" "$file" 2>/dev/null; then
        sed -i "s/\s*${option}//g" "$file"
        log_info "${option} kaldırıldı: $file"
    else
        log_info "${option} zaten mevcut değil: $file"
    fi
}

# PAM yedeklerini geri yükle
# Kullanım: restore_pam_backup "/etc/pam.d/.backup_20231209_123456"
restore_pam_backup() {
    local backup_dir="$1"
    
    if [ -d "$backup_dir" ]; then
        log_warn "PAM yedekleri geri yükleniyor: $backup_dir"
        cp "$backup_dir"/* /etc/pam.d/
        log_success "Yedekler geri yüklendi"
    else
        log_error "Yedek dizini bulunamadı: $backup_dir"
        return 1
    fi
}

# Root kullanıcısını faillock'tan temizle
# Kullanım: clear_faillock_root
clear_faillock_root() {
    if command -v faillock &>/dev/null; then
        faillock --user root --reset 2>/dev/null
        log_info "Root faillock sayacı sıfırlandı"
    fi
}

# Tüm kullanıcılar için faillock sayacını sıfırla
# Kullanım: clear_faillock_all
clear_faillock_all() {
    if command -v faillock &>/dev/null; then
        for user in $(awk -F: '$2~/^\$.+\$/{print $1}' /etc/shadow); do
            faillock --user "$user" --reset 2>/dev/null
        done
        log_info "Tüm faillock sayaçları sıfırlandı"
    fi
}
