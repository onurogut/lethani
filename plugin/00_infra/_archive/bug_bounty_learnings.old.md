# Bug Bounty Learnings — Real Reports & Best Practices
# Compiled: 2026-04-14
# Sources: HackerOne disclosed reports, medium writeups, HackerOne docs

---

## 1. RAPOR YAZIM KURALLARI (HackerOne Quality Guidelines)

### Baslik Formati
- KOTU: "XSS in web app"
- IYI: "Stored XSS in user profile field allows script execution on profile view"
- FORMULA: [Vuln Type] + [Nerede] + [Ne Yapabilir]

### Zorunlu Bolumler
1. **Title** — Vuln tipi + asset + etkilenen parametre
2. **Summary** — 2-3 cumle, ne buldum ve neden onemli
3. **Steps to Reproduce** — Numaralanmis, URL/parametre/rol belirtilmis
4. **Impact** — Saldirgan ne yapabilir, gercek senaryo
5. **Supporting Material** — Screenshot, video, curl komutlari
6. **Mitigation** (opsiyonel) — Fix onerisi, bonus kazandirir

### Kabul Edilme Kriterleri
- Adimlar TEKRARLANABILIR olmali
- Impact SOMUT olmali (teori degil, gercek veri/kanit)
- Kod bloklari markdown ile formatli
- Scope icinde olmali (once kurallar okunmali!)
- Daha once raporlanmamis olmali

### Reddedilme Sebepleri
- Belirsiz aciklamalar, ozel detay yok
- Impact aciklamasi yok veya abartili
- Scanner ciktisi kopyala-yapistir, manual PoC yok
- Scope disi vulnerability
- Kotu formatlama (kod, request, aciklama karisik)

---

## 2. IDOR — En Cok Odenen Bug Tipi ($1K-$12.5K)

### Nasil Bulunur
1. **Trafik yakala** (Caido/Burp) — authenticated istek yap
2. **ID parametrelerini bul** — URL path, query param, JSON body, GraphQL variable
3. **ID'yi degistir** — sequential (56789 -> 56790), UUID, hash
4. **Hem READ hem WRITE test et** — GET + POST/PUT/DELETE
5. **Iki hesap kullan** — Hesap A'nin cookie'siyle Hesap B'nin ID'sini dene

### Yuksek Impact IDOR Ornekleri
| Rapor | Program | Bounty | Teknik |
|-------|---------|--------|--------|
| PayPal secondary user ekleme | PayPal | $10,500 | /businessmanage/users/api/v1/users path ID |
| GraphQL BillingDocument | Shopify | $5,000 | GraphQL query'de document ID |
| HackerOne license silme | HackerOne | $12,500 | GraphQL mutation'da user ID |
| Starbucks account takeover | Starbucks | N/A | IDOR -> ATO chain |
| Siparis bilgisi erisim | E-commerce | $1,000 | /api/orders?order_id=X sequential |

### IDOR Test Checklist
- [ ] Kullanici profil ID'si
- [ ] Siparis/order ID'si
- [ ] Dosya/document ID'si
- [ ] Mesaj/notification ID'si
- [ ] Adres/shipping ID'si
- [ ] Odeme/payment ID'si
- [ ] GraphQL node ID'leri
- [ ] UUID vs sequential — her ikisi de test edilmeli
- [ ] Horizontal (ayni seviye) + Vertical (admin fonksiyonu) IDOR

### E-Commerce Spesifik IDOR Hedefleri
- /api/orders/{id} — baskasinin siparis detaylari
- /api/users/{id}/addresses — baskasinin adresleri
- /api/invoices/{id} — baskasinin faturalari
- /api/payments/{id} — baskasinin odeme bilgileri
- /api/tickets/{id} — baskasinin destek talepleri
- /api/wishlist/{id} — baskasinin istek listesi
- /api/reviews/{id} — baskasinin yorumlarini silme/degistirme

---

## 3. SSRF — En Yuksek Bounty Potansiyeli ($3K-$25K)

### Nasil Bulunur
1. **URL kabul eden parametre bul** — webhook, import, avatar URL, PDF generator, preview
2. **Burp Collaborator / interact.sh ile dogrula** — OOB request geldi mi?
3. **Internal endpoint'lere yonlendir** — 127.0.0.1, 169.254.169.254, internal hostname
4. **Bypass teknikleri dene** — IP encoding, DNS rebinding, redirect chain

### SSRF Bypass Teknikleri
```
# IP encoding bypass
http://0x7f000001/           # hex
http://0177.0.0.1/           # octal
http://2130706433/            # decimal
http://127.1/                 # short form
http://[::1]/                 # IPv6

# DNS rebinding (en etkili bypass)
# lock.cmpxchg8b.com/rebinder.html kullan
# Public IP <-> 169.254.169.254 arasinda gecer

# Redirect chain
# Kendi sunucunda 302 redirect yap -> internal IP'ye

# URL parsing farkliliklari
http://evil.com@169.254.169.254/
http://169.254.169.254.evil.com/
http://169.254.169.254%00.evil.com/
```

### AWS Metadata Endpointleri (SSRF Basarili Olursa)
```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/[ROLE-NAME]
http://169.254.169.254/latest/user-data
http://169.254.169.254/latest/dynamic/instance-identity/document
```

### Gercek Ornek: LarkSuite SSRF ($Critical)
1. Wiki "import from docs" ozelligi Confluence ZIP kabul ediyor
2. ZIP icindeki HTML'de img src URL'leri server-side fetch ediliyor
3. Direkt 169.254.169.254 engellenmis
4. DNS rebinding ile bypass: rbndr.us uzerinden IP degistirme
5. ~10 denemede basarili, AWS EC2 credentials elde edildi
6. Critical severity, hizli fix

### Gercek Ornek: HelloSign/Dropbox SSRF ($4,913)
1. HelloSign'da webhook/callback URL ozelligi
2. URL'ye Burp Collaborator koyarak OOB istek dogrulandi
3. AWS metadata endpoint'ine yonlendirme ile private key elde edildi

---

## 4. XSS — Hala Gecerli Ama Chain Gerekiyor ($500-$20K)

### 2025'te XSS Trendleri
- Tek basina reflected XSS dusuk degerli ($500 veya N/A)
- STORED XSS hala yuksek degerli (ozellikle admin panelinde)
- XSS + CSRF chain = Account Takeover = HIGH/CRITICAL
- Cache poisoning + XSS = Stored XSS at scale = CRITICAL ($18,900 PayPal)
- Blind XSS (admin panelinde tetiklenen) = HIGH

### En Yuksek Odenen XSS Ornekleri
| Rapor | Program | Bounty | Teknik |
|-------|---------|--------|--------|
| Stored XSS on signin + cache poison | PayPal | $20,000 | Cache poisoning -> stored XSS |
| Stored XSS via cache poisoning | PayPal | $18,900 | Ayni endpoint, farkli bypass |
| XSS in Steam React client | Valve | $7,500 | React dangerouslySetInnerHTML |
| Redirect param -> XSS | Reddit | $5,000 | accounts.reddit.com redirect |
| HEY.com email stored XSS | Basecamp | $5,000 | Email parsing -> stored XSS |

### XSS Aranacak Yerler (E-Commerce)
- Arama kutusu (reflected)
- Urun yorumlari (stored)
- Profil bilgileri — isim, adres (stored)
- Destek ticket'lari (blind XSS — admin panelinde gorulur)
- URL parametreleri — redirect, callback, error message
- Email sablonlari — isim alani HTML render ediliyorsa

---

## 5. BUSINESS LOGIC — E-Commerce Icin Altin Madeni ($4K+)

### Ornekler (zooplus'ta kupon/voucher HARIC!)
- Checkout'ta fiyat manipulasyonu — total_amount parametresi degistirme
- Negatif miktar — quantity=-1 ile para iadesi tetikleme
- Currency confusion — farkli doviz ile odeme
- Discount stacking — birden fazla indirim ayni anda uygulama
- Shipping address degistirme — odeme sonrasi adres IDOR

### Gercek Ornek: Checkout Price Manipulation ($4,200)
1. Urun sepete eklendi, checkout baslatildi
2. Burp ile POST /checkout isteği yakalandi
3. total_amount parametresi $115 -> $0.50 olarak degistirildi
4. Server client-side degeri dogrulamadan kabul etti
5. $115'lik urun $0.50'ye alindi

### NOT: Zooplus'ta business logic/voucher/coupon/zoopoints OUT OF SCOPE!
- Fiyat manipulasyonu dene AMA kupon/puan istismari raporlama
- Odeme akisi ve siparis mantigi test et
- Envanter/stok manipulasyonu test et

---

## 6. GraphQL SALDIRI TEKNIKLERI

### Neden Onemli
- Modern e-commerce siteleri GraphQL kullaniyor
- Introspection aciksa tum schema gorulebilir
- Batch query ile rate limiting bypass
- IDOR GraphQL ID'lerinde cok yaygin

### Test Adimlari
1. **Introspection dene**: `{__schema{types{name,fields{name}}}}`
2. **Batch query**: tek istekte birden fazla query -> rate limit bypass
3. **Field suggestion**: hatali field yazinca oneriler gelir
4. **Mutation'larda auth check**: query'de auth var ama mutation'da yok olabilir
5. **Node ID enumeration**: global ID'leri base64 decode et, farkli tiplere eriş

---

## 7. VULNERABILITY CHAINING — Severity Yukseltme

### Kanitlanmis Chain Ornekleri
| Chain | Sonuc | Ornek |
|-------|-------|-------|
| Open Redirect + OAuth | Token theft -> ATO | CRITICAL |
| SSRF + AWS metadata | Cloud credential theft | CRITICAL |
| XSS + CSRF | Account takeover | HIGH |
| IDOR + PII | Mass data breach | CRITICAL |
| Cache poison + XSS | Stored XSS at scale | CRITICAL ($20K PayPal) |
| LFI + log poisoning | RCE | CRITICAL |
| DNS rebinding + SSRF | Internal network access | CRITICAL |
| GraphQL batch + no rate limit | Brute force | MEDIUM |

### Chain Stratejisi
1. Dusuk severity bulgu bul (info disclosure, open redirect)
2. Ikinci bir bulgu ara (XSS, SSRF, auth issue)
3. Birlikte kullanildiginda impact'in nasil arttigini goster
4. Raporda chain'i net acikla, adim adim reproduce et

---

## 8. E-COMMERCE SPESIFIK TEST LISTESI

### Odeme Akisi
- [ ] Fiyat parametresi manipulasyonu
- [ ] Currency degistirme
- [ ] Negatif miktar/tutar
- [ ] Odeme sonrasi siparis degistirme
- [ ] Race condition — ayni anda iki odeme
- [ ] Taksit/plan degistirme

### Hesap Yonetimi
- [ ] Profil IDOR (baskasinin bilgilerini gorme/degistirme)
- [ ] Adres IDOR (baskasinin adresini gorme)
- [ ] Siparis IDOR (baskasinin siparisini gorme)
- [ ] Email degistirme akisi — eski email'e bildirim gidiyor mu?
- [ ] Sifre sifirlama — token tahmin edilebilir mi?

### API
- [ ] GraphQL introspection
- [ ] REST API endpoint enumeration
- [ ] Authentication bypass (token expire kontrolu)
- [ ] Rate limiting (login, OTP, search)
- [ ] Mass assignment (ekstra field gonderme)

### Arama/Filtreleme
- [ ] SQL injection (sort, filter parametreleri)
- [ ] XSS (arama terimi yansimasi)
- [ ] SSTI (arama sonuc sayfasi template'i)
- [ ] Bilgi sizintisi (hata mesajlari, stack trace)

---

## 9. ARACLAR VE TEKNIKLER

### Zorunlu Araclar
- **Caido/Burp Suite** — trafik yakalama, replay, intruder
- **Collaborator/interact.sh** — OOB dogrulama (SSRF, blind XSS)
- **ffuf** — directory/parameter fuzzing
- **nuclei** — sablonlu zafiyet tarama
- **httpx** — toplu HTTP probe

### Etkili Workflow
1. RECON: subdomain + tech stack + endpoint kesfet
2. TRAFIK YAKALA: Caido ile authenticated browsing
3. ENDPOINT ANALIZ: her parametre icin vuln tipi belirle
4. MANUAL TEST: en yuksek impact endpoint'lerden basla
5. CHAIN: dusuk bulguları birlestir
6. RAPOR: clear title + steps + impact + PoC

---

## 10. ORTAK HATALAR VE DERSLER

### Yapma
- Scanner output'u kopyala-yapistir rapor gonderme
- Impact'i abartma — guveni kirarsın
- Scope disi hedef test etme
- Ayni vuln'u farkli parametrelerde ayri rapor etme (tek rapor, tek bounty)
- Teorik impact yazma — KANITLA

### Yap
- Iki hesap olustur (IDOR testi icin zorunlu)
- Program kurallarini OKU (her program farkli)
- HackerOne email alias kullan (program istiyorsa)
- Duplicate check yap (raporlamadan once)
- Professional ol — triage ekibiyle kavga etme
- Dusuk severity bile olsa chain potansiyeli varsa raporla (chain'i acikla)

---

## KAYNAKLAR

- HackerOne Top Reports: github.com/reddelexc/hackerone-reports
- Writeups: pentester.land/writeups/
- IDOR Guide: intigriti.com/researchers/hackademy/idor
- SSRF: github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery
- XSS: github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection
- HackerOne Quality Reports: docs.hackerone.com/en/articles/8475116-quality-reports
