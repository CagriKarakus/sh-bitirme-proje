---
name: bagimlilik_kontrol_et
description: Belirtilen bir sıkılaştırma kuralının önkoşullarını (bağımlılıklarını) listeler.

# Skill'in ne zaman tetiklenmesi gerektiğini anlatan anahtar kelimeler ve senaryolar.
# Antigravity bu ifadelere göre doğru skill'i seçer.
when_to_use:
  - "Bir kuralın bağımlılıklarını kontrol etmek istediğinde."
  - "Bir kuralı uygulamadan önce hangi kuralların gerekli olduğunu öğrenmek istediğinde."
  - "Kuralın önkoşulu var mı diye sorduğunda."
  - "['kural_adi'] kuralının bağımlılıkları nelerdir?"
  - "['kural_adi'] kuralını uygulayabilir miyim?"

# Skill'in çalışması için gereken girdiler (parametreler).
parameters:
  - name: kural_adi
    type: string
    description: "Bağımlılıkları kontrol edilecek kuralın adı (Örn: KURAL_B_GELISTIRILMIS_LOGLAMA)."
    required: true

# Skill'in nasıl kullanılacağına dair örnek komutlar ve diyaloglar.
how_to_use:
  - "Kullanıcı: 'KURAL_B_GELISTIRILMIS_LOGLAMA kuralının bağımlılıkları var mı?'"
  - "Antigravity -> Bu skill'i 'kural_adi: KURAL_B_GELISTIRILMIS_LOGLAMA' parametresi ile çalıştırır."
  - "Kullanıcı: 'Logları merkeze gönderen kuralın önkoşulu nedir?'"
  - "Antigravity -> (Doğal dil işleme ile) KURAL_C_LOGLARI_MERKEZE_GONDER kuralını bulur ve skill'i çalıştırır."

# Bu skill'in arkasındaki mantık akışı (pseudo-code)
# Bu kısım, skill'in kodunu yazarken size yol gösterir.
logic:
  - 1. `kural_adi` parametresini al.
  - 2. `rules.yaml` dosyasını oku ve veriyi yükle.
  - 3. Yüklenen veride `kural_adi` ile eşleşen kuralı bul.
  - 4. Eğer kural bulunamazsa: "'{kural_adi}' isminde bir kural bulunamadı." mesajı döndür.
  - 5. Eğer kural bulunursa, `dependencies` listesini kontrol et.
  - 6. Eğer `dependencies` listesi boşsa: "'{kural_adi}' kuralının bilinen bir bağımlılığı yoktur. Tek başına uygulanabilir." mesajı döndür.
  - 7. Eğer `dependencies` listesinde kurallar varsa: "'{kural_adi}' kuralının uygulanabilmesi için şu kuralların önceden uygulanmış olması gerekmektedir: {bağımlılık_listesi}." mesajı döndür.
---