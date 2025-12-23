import google.generativeai as genai
import json
from scraper import veri_getir, ders_detay_getir

# 1. AI Ayarları
API_KEY = ""#api keyinizi yazın
genai.configure(api_key=API_KEY)

def model_kur():
    # Mevcut en iyi modeli seçer
    models = [m.name for m in genai.list_models() if 'generateContent' in m.supported_generation_methods]
    secilen = next((m for m in models if "flash" in m), models[0])
    
    talimat = """
    Sen İKÜ Akıllı Akademik Danışmanısın. 
    ⚠️ ASLA ÇİĞNENMEZ KURALLAR:
    - Ders kodlarını (TBP1001 vb.) ASLA yazma. Sadece dersin tam adını yaz.
    - Kullanıcı 'ders' sorduğunda 1, 2, 3 ve 4. yarıyıl başlıkları altında dersleri listele.
    - Sadece istene cevabı ver, vizyon/misyon gibi kalabalık metinleri atla.
    """
    return genai.GenerativeModel(model_name=secilen, system_instruction=talimat)

bot = model_kur()

# 2. Config Yükleme
try:
    with open('config.json', 'r', encoding='utf-8') as f:
        config = json.load(f)
except Exception as e:
    print(f"Hata: {e}")
    config = {"bolumler": {}}

# Hafıza
hafiza = {"aktif_bolum": None, "canli_veri": ""}

print("🤖 Bot: Hazırım! Hangi bölümü konuşalım? (Çıkmak için 'exit' yazın)")

hafiza = {"aktif_bolum": None, "canli_veri": ""}

while True:
    soru = input("\nSiz: ").strip().lower()
    if soru in ["exit", "çıkış"]: break

    # DİNAMİK BÖLÜM TESPİTİ (Geliştirildi)
    yeni_bolum_anahtari = None
    for anahtar in config["bolumler"].keys():
        # Anahtardaki alt çizgileri kaldırıp kontrol et (bilgisayar_programciligi -> bilgisayar programciligi)
        temiz_anahtar = anahtar.replace("_", " ")
        
        # Soru içinde bölüm adı geçiyor mu? 
        # (Örn: "mimarlık" kelimesi "mimarlık bölümü amacı nedir" içinde var mı?)
        if temiz_anahtar in soru or anahtar in soru:
            yeni_bolum_anahtari = anahtar
            break
    
    # Eğer yeni bir bölüm tespit edildiyse verileri yükle
    if yeni_bolum_anahtari:
        if hafiza["aktif_bolum"] != yeni_bolum_anahtari:
            hafiza["aktif_bolum"] = yeni_bolum_anahtari
            print(f"🔍 {yeni_bolum_anahtari.upper()} verileri yükleniyor...")
            linkler = list(config["bolumler"][yeni_bolum_anahtari].values())
            hafiza["canli_veri"] = veri_getir(linkler)
    
    # Hala bir bölüm seçilmediyse uyar (Bu kısım senin aldığın hatayı yönetir)
    if not hafiza["aktif_bolum"]:
        print("Bot: Hangi bölüm hakkında bilgi almak istersiniz? (Örn: Mimarlık, Bilgisayar Programcılığı)")
        continue
    
    # Hafıza Kontrolü
    if not hafiza["aktif_bolum"]:
        print("Bot: Hangi bölüm hakkında bilgi almak istersiniz? (Örn: Mimarlık, Bilgisayar Programcılığı)")
        continue

    # DERS ANALİZİ VE LİNKE GİTME (Görseldeki hataları çözen kısım)
    bulunan_link = None
    # Canlı veri içindeki gizli URL etiketlerini tarar
    for satir in hafiza["canli_veri"].split('\n'):
        if soru in satir.lower() and "[URL:" in satir:
            bulunan_link = satir.split("[URL:")[1].split("]")[0]
            break

    if bulunan_link:
        print(f"🔗 {soru} içeriği derinlemesine analiz ediliyor...")
        detay_verisi = ders_detay_getir(bulunan_link)
        istek = f"DERS DETAYI: {detay_verisi}\nSORU: {soru} detaylarını açıklar mısın?"
    else:
        istek = f"BÖLÜM VERİSİ: {hafiza['canli_veri']}\nSORU: {soru}"

    try:
        response = bot.generate_content(istek)
        print(f"\nBot: {response.text.strip()}")
    except Exception as e:
        print(f"❌ Hata: {e}")