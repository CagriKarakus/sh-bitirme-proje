---
description: Windows hardening kuralı oluşturma rehberi - CIS Benchmark tabanlı
---

# Windows Hardening Rule Creation Workflow

Bu workflow, CIS Benchmark tabanlı Windows hardening kuralları oluşturmak için kullanılır.

## Öncelikle Oku

**ÖNEMLİ**: Kural oluşturmadan önce mutlaka aşağıdaki mimari dokümanı oku:
- `docs/WINDOWS_HARDENING_ARCHITECTURE.md`

## Kural JSON Yapısı

Her kural aşağıdaki yapıya sahip olmalıdır:

```json
{
  "rule_id": "X.X.X",
  "title": "Kural başlığı",
  "description": "Detaylı açıklama",
  "cis_level": 1,
  "category": "Kategori adı",
  "applies_to": ["Windows 11", "Windows Server 2022"],
  
  "registry_config": {
    "path": "HKLM:\\...",
    "value_name": "ValueName",
    "value_type": "REG_DWORD",
    "value_data": 1,
    "comparison": "equals"
  },
  
  "gpo_config": {
    "policy_path": "Computer Configuration\\...",
    "setting_name": "Setting Name",
    "setting_value": 1,
    "admx_category": "Category"
  },
  
  "implementation_local": {
    "powershell_command": "Tek satırlık komut",
    "powershell_script": "Çok satırlı script",
    "requires_admin": true,
    "requires_reboot": false
  },
  
  "implementation_gpo": {
    "inf_section": "[System Access]",
    "inf_key": "KeyName",
    "inf_value": "Value"
  },
  
  "audit_logic": {
    "powershell_script": "return ($value -eq $expected)",
    "expected_result": true
  },
  
  "remediation_rollback": {
    "powershell_command": "Geri alma komutu",
    "original_value": null
  },
  
  "references": ["URL1", "URL2"],
  "tags": ["tag1", "tag2"]
}
```

## Zorunlu Alanlar

- `rule_id` - CIS Benchmark referans numarası
- `title` - Kısa kural adı
- `description` - Detaylı açıklama
- `cis_level` - 1 veya 2
- `audit_logic` - Denetim script'i (ZORUNLU)

## Dizin Yapısı

Kurallar şu dizin yapısına göre kaydedilmeli:

```
platforms/windows/rules/
├── S1_Account_Policies/
│   ├── 1.1.1.json
│   ├── 1.1.2.json
├── S2_Local_Policies/
│   ├── 2.1.1.json
└── ...
```

## Dikkat Edilecekler

1. **Registry path** her zaman tam yol olmalı (HKLM:\\ ile başlamalı)
2. **Audit logic** mutlaka `$true` veya `$false` döndürmeli
3. **value_type** sadece şunlar olabilir: REG_DWORD, REG_SZ, REG_EXPAND_SZ, REG_MULTI_SZ, REG_QWORD
4. **comparison** sadece şunlar olabilir: equals, less_than_or_equal, greater_than_or_equal, not_equals, exists, not_exists
5. PowerShell scriptlerinde `-ErrorAction SilentlyContinue` kullan
6. Her remediation için rollback bilgisi ekle

## Örnek Kullanım

Kullanıcı "CIS 1.1.1 kuralını oluştur" dediğinde:
1. Bu workflow'u oku
2. `docs/WINDOWS_HARDENING_ARCHITECTURE.md` dosyasını referans al
3. JSON şemasına uygun kural oluştur
4. Uygun dizine kaydet
