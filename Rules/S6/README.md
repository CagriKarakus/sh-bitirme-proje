# Section 6: Logging and Auditing

Bu bölüm CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0 standardının 6. bölümünü içerir.

## Yapı

### 6.1 System Logging
- **6.1.1** Configure systemd-journald service (4 kontrol)
- **6.1.2** Configure journald (8 kontrol)
- **6.1.3** Configure rsyslog (8 kontrol)
- **6.1.4** Configure Logfiles (1 kontrol)

### 6.2 System Auditing
- **6.2.1** Configure auditd Service (4 kontrol)
- **6.2.2** Configure Data Retention (4 kontrol)
- **6.2.3** Configure auditd Rules (21 kontrol)
- **6.2.4** Configure auditd File Access (10 kontrol)

### 6.3 Configure Integrity Checking
- **6.3.1** AIDE Installation (1 kontrol)
- **6.3.2** Filesystem Integrity Check (1 kontrol)
- **6.3.3** Cryptographic Mechanisms (1 kontrol)

## Toplam İstatistikler
- Toplam klasör: 60+
- Toplam script: 123
- Ana kategoriler: 3 (6.1, 6.2, 6.3)
- Alt kategoriler: 10

## Kullanım

Her alt klasörde iki script bulunur:
- `audit.sh`: Mevcut konfigürasyonu kontrol eder
- `remediation.sh`: Gerekli düzeltmeleri yapar

### Örnek
```bash
# Journald servisini kontrol et
cd 6.1/6.1.1/6.1.1.1
./audit.sh

# Düzeltme uygula
sudo ./remediation.sh
```

## Yardımcı Dosyalar
- `common/audit_helpers.sh`: Auditd yardımcı fonksiyonları

## Notlar
- Tüm scriptler S1-S5 bölümleriyle tutarlı formatta oluşturulmuştur
- Automated kontroller otomatik çalıştırılabilir
- Manual kontroller için dokümantasyon incelenmeli
- Bazı kontroller sistem yeniden başlatma gerektirebilir
