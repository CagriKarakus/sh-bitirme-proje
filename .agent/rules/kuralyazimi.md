---
trigger: always_on
---

name: kural_yazma_rehberi
description: Yeni bir sıkılaştırma kuralı yazmak için izlenmesi gereken adımları ve en iyi pratikleri açıklar.

# Skill'in ne zaman tetiklenmesi gerektiğini anlatan anahtar kelimeler ve senaryolar.
when_to_use:
  - "Yeni bir kural nasıl yazılır?"
  - "Kural yazma adımları nelerdir?"
  - "['isletim_sistemi'] için yeni bir kural oluşturmak istiyorum."
  - "Kural yazarken nelere dikkat etmeliyim?"
  - "Kural yazma standardı nedir?"

# Skill'in çalışması için gereken girdiler (parametreler).
parameters:
  - name: isletim_sistemi, kural_yaz
    type: string
    description: "Kuralın yazılacağı işletim sisteminin adı (Örn: Linux, Windows)."
    required: true

# Skill'in nasıl kullanılacağına dair örnek komutlar ve diyaloglar.
how_to_use:
  - "Kullanıcı: 'Yeni bir kural yazmak istiyorum.'"
  - "Antigravity -> 'Harika! Hangi işletim sistemi için kural yazmak istiyorsunuz? (Örn: Linux, Windows)'"
  - "---"
  - "Kullanıcı: 'Linux için yeni kural yazma adımları nelerdir?'"
  - "Antigravity -> Bu skill'i 'isletim_sistemi: Linux' parametresi ile çalıştırır ve aşağıdaki adımları listeler."

# Bu skill'in arkasındaki mantık akışı ve kullanıcıya sunacağı rehber.
logic:
  - "Yeni bir '{isletim_sistemi}' kuralı yazmak için izlemen gereken adımlar aşağıda listelenmiştir:"
  - |
    **1. Adım: Araç (Tool) Kontrolü**
    Öncelikle, yazacağın kuralın otomasyonunu sağlayacak bir script veya araç olup olmadığını kontrol et. 
    Bunun için `{isletim_sistemi}` işletim sistemine özel `tools/` klasörünü incelemelisin.
    Mevcut bir aracı kullanmak, tutarlılığı artırır ve gereksiz kod yazımını önler.

  - |
    **2. Adım: Mevcut Kural Yapısını İncele**
    Projedeki tutarlılığı korumak için, daha önce yazılmış kuralları dikkatlice incele. Özellikle şu noktalara odaklan:
    - **İsimlendirme Standardı:** Kuralların nasıl isimlendirildiğine bak (Örn: `KURAL_MODUL_ACIKLAMA`). Senin kuralın da bu standarda uymalı.
    - **Meta-veri Alanları:** kendi kuralına da eksiksiz ekle.
    - **Manuel kurallar** Eğer yazacağın WINDOWS kuralı CIS taradından MANUEL olarak belirtildiyse onu manuel klasörüne yaz.

  - |
    **3. Adım: Kuralı Oluştur ve Açıklamasını Yaz**
    Yukarıdaki standartlara uygun şekilde kural dosyanı oluştur.
    `description` (açıklama) alanının çok önemli olduğunu unutma. Bu alanda kuralın ne yaptığını, neden önemli olduğunu ve sisteme olası etkilerini net bir dille anlatmalısın.

  - |
    **4. Adım: Test Et**
    Oluşturduğun kuralı bir test ortamında uygulayarak beklendiği gibi çalıştığından ve sisteme istenmeyen bir yan etki yapmadığından emin ol.

  - "Bu adımları izleyerek hem standartlara uygun hem de herkesin kolayca anlayabileceği sürdürülebilir kurallar yazabilirsin."
---