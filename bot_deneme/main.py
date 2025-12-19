import os
from dotenv import load_dotenv
from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.orm import Session
from datetime import time, date, timedelta, datetime
from sqlalchemy import desc
from sqlalchemy import Date, func, cast
from datetime import datetime
from typing import Optional
from sqlalchemy import exc as sa_exc # Hata ayıklama için
from sqlalchemy import text  # Bunu ekle
import pyodbc

# GÜVENLİK KÜTÜPHANELERİ
from pydantic import BaseModel
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import bcrypt
from jose import JWTError, jwt

# GEMINI KÜTÜPHANELERİ
from google import genai
from google.genai import types

# Kendi dosyalarımız
from database import DersProgrami, SinavTakvimi, Duyuru, Notlar, User, ServisSaatleri, get_db

# --- Çevre Ayarları ve Güvenlik ---
load_dotenv()
API_KEY = os.getenv("GEMINI_API_KEY")
SECRET_KEY = os.getenv("SECRET_KEY", "gizli-ve-guvenli-anahtar-buraya") 
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

conn_str = (
    "Driver={SQL Server};"
    "Server=DESKTOP-3M4E4P0;"
    "Database=SchoolAssistantDB;"
    "Trusted_Connection=yes;"
)
conn = pyodbc.connect(conn_str)

# ----------------------------------------------------------------------
# SİSTEM PROMPT'U
# ----------------------------------------------------------------------

SYSTEM_PROMPT = """
Sen, [Üniversite Adı] öğrencilerine hizmet veren Akıllı Bilgi Asistanısın. 
Görevin, öğrencinin sorduğu sorulara en uygun aracı kullanarak (get_ders_programi_by_gun, get_sinavlar_by_ders_ve_tarih, get_son_duyurular, get_ogrenci_notlari_ve_ortalama, add_ders_programi, add_sinav_takvimi, add_ogrenci_notu, delete_ogrenci_notu, update_sinav_takvimi, delete_ders_programi, get_servis_saatleri) doğru ve doğal dilde cevap vermektir.

Kurallar:
1. Hitap Şekli: Daima resmi, yardımsever ve öğrenciye özel bir ton kullan.
2. Öncelik: Her zaman önce aracın çıktısını analiz et, sonra cevabı doğal dile çevir.
3. Servis Sorgulama: Kullanıcı servis saati sorduğunda, get_servis_saatleri aracını kullan. Eğer güzergah grubu (route_group) belirtilmemişse, yalnızca kalkış (from_stop) ve varış (to_stop) duraklarını kullanarak aracı doğrudan çağır. Cevapta from_stop, to_stop ve depart_time bilgilerini net belirt.
4. Kişiselleştirme: Eğer kullanıcı giriş yapmışsa (prompt içinde adı ve numarası geçecektir), ona ismiyle hitap et.
5. Çözüm Yoksa: Eğer araçlar soruyu çözemiyorsa, genel bir cevap vererek aracı kullanmadığını belirt.
6. Tarih ve Saat Formatı: Cevaplarında tarihleri gün/ay/yıl (Örn: 20 Aralık 2025) formatında, saatleri ise (Örn: 14:00) formatında ver.
7. Güncelleme/Silme Gereklilikleri: Not silme (delete_ogrenci_notu) ve sınav güncelleme (update_sinav_takvimi) işlemleri için ID (not_id/sinav_id) gereklidir. Ders silme (delete_ders_programi) işlemi için ise ders adı (ders_adi) yeterlidir. Kullanıcı gerekli parametreyi vermezse, önce listeleme araçlarını kullanmasını veya eksik bilgiyi sormasını öner.
"""

# ----------------------------------------------------------------------
# GÜVENLİK VE MODELLER
# ----------------------------------------------------------------------

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token") 

def verify_password(plain_password: str, hashed_password: str) -> bool:
    password_bytes = plain_password.encode('utf-8')
    hashed_bytes = hashed_password.encode('utf-8')
    try:
        return bcrypt.checkpw(password_bytes, hashed_bytes)
    except ValueError:
        return False

def get_password_hash(password: str) -> str:
    limited_password = password.encode('utf-8')[:72]
    salt = bcrypt.gensalt()
    hashed_bytes = bcrypt.hashpw(limited_password, salt)
    return hashed_bytes.decode('utf-8') 

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Kimlik bilgileri doğrulanamadı",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise credentials_exception
    return user

# Pydantic Modelleri
class UserCreate(BaseModel):
    full_name: str; email: str; password: str; ogrenci_no: str
class UserResponse(BaseModel):
    id: int; full_name: str; email: str; ogrenci_no: str
    class Config:
        orm_mode = True
class Token(BaseModel):
    access_token: str; token_type: str
class QueryModel(BaseModel):
    prompt: str 
class DersEkleModel(BaseModel):
    ders_adi: str; gun: str; saat_baslangic: str; sinif_no: str; ogretmen_adi: str
class SinavEkleModel(BaseModel):
    ders_adi: str; sinif_duzeyi: str; tarih: str; saat: str; konu: str; ogretmen_adi: str;
class NoteCreate(BaseModel):
    title: str
    text_content: str

# FastAPI Uygulaması
app = FastAPI(title="Akıllı Okul Asistanı")
# Gemini İstemcisi
client = genai.Client(api_key=API_KEY) 

# ----------------------------------------------------------------------
# KULLANICI YÖNETİMİ UÇ NOKTALARI
# ----------------------------------------------------------------------

@app.post("/register", response_model=UserResponse, summary="Yeni kullanıcı (öğrenci) kaydı.")
def register_user(user: UserCreate, db: Session = Depends(get_db)):
    try: 
        db_user = db.query(User).filter((User.email == user.email) | (User.ogrenci_no == user.ogrenci_no)).first()
        if db_user:
            raise HTTPException(status_code=400, detail="E-posta veya Öğrenci Numarası zaten kayıtlı.")

        hashed_password = get_password_hash(user.password)
        
        new_user = User(full_name=user.full_name, email=user.email, hashed_password=hashed_password, ogrenci_no=user.ogrenci_no)
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        return new_user
    except Exception as e: 
        print("\n*** KAYIT SIRASINDA KRİTİK PYTHON/DB HATASI ***:", e)
        db.rollback() 
        raise HTTPException(status_code=500, detail=f"Kayıt işlemi iç hatası: {e}")

@app.post("/token", response_model=Token, summary="Giriş yap ve JWT token al.")
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form_data.username).first()
    
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Hatalı e-posta veya şifre", headers={"WWW-Authenticate": "Bearer"})
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": str(user.id)}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/notes")
def get_notes(current_user: User = Depends(get_current_user)):
    cursor = conn.cursor()
    cursor.execute("SELECT id, title, text_content FROM notes WHERE user_id = ?", (current_user.id,))
    rows = cursor.fetchall()
    return [{"id": r[0], "title": r[1], "content": r[2]} for r in rows]

# Not Ekleme
@app.post("/notes")
def create_note(note: NoteCreate, current_user: User = Depends(get_current_user)):
    cursor = conn.cursor()
    cursor.execute("INSERT INTO notes (user_id, title, text_content) VALUES (?, ?, ?)",
                   (current_user.id, note.title, note.text_content))
    conn.commit()
    return {"message": "Not başarıyla eklendi"}

# Not Silme
@app.delete("/notes/{note_id}")
def delete_note(note_id: int, current_user: User = Depends(get_current_user)):
    cursor = conn.cursor()
    cursor.execute("DELETE FROM notes WHERE id = ? AND user_id = ?", (note_id, current_user.id))
    conn.commit()
    return {"message": "Not silindi"}


# ----------------------------------------------------------------------
# GEMINI İÇİN TÜM ARAÇLAR (READ & CREATE & UPDATE & DELETE)
# ----------------------------------------------------------------------

# --- ARAÇ 1-4: Çekme Fonksiyonları ---
def get_ders_programi_by_gun(gun: str, owner_id: int):
    db = next(get_db())
    try:
        # 1. Günü temizle: Boşlukları sil ve İlk harfi büyük yap (pazartesi -> Pazartesi)
        temiz_gun = str(gun).strip().capitalize()
        
        # 2. DEBUG: Terminale ne aradığını yazalım (Siyah ekrandan kontrol edersin)
        print(f"--- SORGULANIYOR: Gün: '{temiz_gun}', UserID: {owner_id} ---")

        # 3. Sorguyu yap (Hem ID hem de Öğrenci No ihtimaline karşı User tablosuyla eşleşen ID'yi al)
        user = db.query(User).filter((User.id == owner_id) | (User.ogrenci_no == str(owner_id))).first()
        target_id = user.id if user else owner_id

        dersler = db.query(DersProgrami).filter(
            DersProgrami.gun == temiz_gun,
            DersProgrami.owner_id == target_id
        ).all()

        if not dersler:
            print(f"--- SONUÇ: Ders bulunamadı! ---")
            return {"status": "success", "message": f"{temiz_gun} günü için kayıtlı bir dersiniz bulunmuyor.", "data": []}

        # 4. Veriyi asistanın anlayacağı formata çevir
        sonuc = []
        for d in dersler:
            sonuc.append({
                "ders_adi": d.ders_adi,
                "saat": d.saat_baslangic.strftime("%H:%M"),
                "sinif": d.sinif_no,
                "ogretmen": d.ogretmen_adi
            })
        
        db.close()
        return {"status": "success", "data": sonuc}

    except Exception as e:
        db.close()
        print(f"--- HATA: {str(e)} ---")
        return {"status": "error", "message": str(e)}

def get_sinavlar_by_ders_ve_tarih(ders_adi: str = None, sinif_duzeyi: str = None):
    db = next(get_db()); query = db.query(SinavTakvimi)
    if ders_adi: query = query.filter(SinavTakvimi.ders_adi.ilike(f"%{ders_adi}%")) # ilike ile esnek arama
    if sinif_duzeyi: query = query.filter(SinavTakvimi.sinif_duzeyi.ilike(f"%{sinif_duzeyi}%"))
    sinavlar = query.all(); db.close()
    if not sinavlar: return {"status": "success", "data": "Belirtilen kriterlere uygun sınav bulunamadı."}
    result = []
    for sinav in sinavlar: result.append({"ders": sinav.ders_adi, "sinif": sinav.sinif_duzeyi, "tarih": sinav.tarih.strftime("%d.%m.%Y"), "saat": sinav.saat.strftime("%H:%M"), "konu": sinav.konu, "sinav_id": sinav.id})
    return {"status": "success", "data": result}

def get_son_duyurular(kategori: str = None, limit: int = 5):
    db = next(get_db()); query = db.query(Duyuru).order_by(desc(Duyuru.tarih)) 
    if kategori: query = query.filter(Duyuru.kategori.ilike(f"%{kategori}%"))
    duyurular = query.limit(limit).all(); db.close()
    if not duyurular: return {"status": "success", "data": "Belirtilen kriterlere uygun duyuru bulunamadı."}
    result = []
    for d in duyurular: result.append({"baslik": d.baslik, "tarih": d.tarih.strftime("%d.%m.%Y"), "kategori": d.kategori, "ozet": d.icerik[:100] + "..."})
    return {"status": "success", "data": result}

def get_ogrenci_notlari_ve_ortalama(owner_id: int, ogrenci_no: str, ders_adi: str = None):
    db = next(get_db())
    # Hem ogrenci_no hem owner_id ile çift güvenlik sağlıyoruz
    query = db.query(Notlar).filter(Notlar.owner_id == owner_id, Notlar.ogrenci_no == ogrenci_no)
    if ders_adi: query = query.filter(Notlar.ders_adi.ilike(f"%{ders_adi}%"))
    notlar = query.all(); db.close()
    if not notlar: return {"status": "success", "data": "Not bulunamadı."}
    # (Ortalama hesaplama mantığı aynı kalıyor...)
    return {"status": "success", "data": [n.puan for n in notlar]}
    
# --- ARAÇ 5: Ders Programına Ders Ekleme ---
def add_ders_programi(ders_adi: str, gun: str, saat_baslangic: str, sinif_no: str, ogretmen_adi: str, owner_id: int, **kwargs):
    db = next(get_db())
    try:
        # Saat formatını (12.00 -> 12:00) otomatik düzelt
        saat_temiz = str(saat_baslangic).replace(".", ":").strip()
        saat_obj = datetime.strptime(saat_temiz, "%H:%M").time()
        
        # KRİTİK DÜZELTME: Eğer asistan yanlışlıkla öğrenci no gönderdiyse
        # Veritabanında hem 'id' hem de 'ogrenci_no' üzerinden kontrol yapalım
        user = db.query(User).filter((User.id == owner_id) | (User.ogrenci_no == str(owner_id))).first()
        
        if not user:
            return {"status": "error", "message": f"Kritik Hata: Sistemde {owner_id} bilgisine sahip kullanıcı bulunamadı."}

        yeni_ders = DersProgrami(
            ders_adi=ders_adi,
            gun=gun.capitalize(),
            saat_baslangic=saat_obj,
            sinif_no=sinif_no,
            ogretmen_adi=ogretmen_adi,
            owner_id=user.id # Her zaman gerçek tablo ID'sini kullan
        )
        db.add(yeni_ders)
        db.commit()
        db.close()
        return {"status": "success", "message": f"{ders_adi} başarıyla eklendi."}
    except Exception as e:
        db.rollback()
        db.close()
        return {"status": "error", "message": f"Veritabanı hatası: {str(e)}"}

# --- ARAÇ 6: Sınav Takvimine Sınav Ekleme ---
def add_sinav_takvimi(ders_adi: str, sinif_duzeyi: str, tarih: str, saat: str, konu: str, ogretmen_adi: str, owner_id: int):
    db = next(get_db())
    try:
        tarih_obj = datetime.strptime(tarih, "%Y-%m-%d").date()
        saat_obj = datetime.strptime(saat, "%H:%M").time()
        yeni_sinav = SinavTakvimi(
            ders_adi=ders_adi, sinif_duzeyi=sinif_duzeyi, 
            tarih=tarih_obj, saat=saat_obj, konu=konu, 
            ogretmen_adi=ogretmen_adi, owner_id=owner_id # EKLENDİ
        )
        db.add(yeni_sinav); db.commit(); db.close()
        return {"status": "success", "message": "Sınav eklendi."}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# --- ARAÇ 7: Öğrenci Notu Ekleme ---
def add_ogrenci_notu(ogrenci_no: str, ders_adi: str, sinav_turu: str, puan: int, etkisi: int, owner_id: int):
    db = next(get_db())
    yeni_not = Notlar(
        ogrenci_no=ogrenci_no, ders_adi=ders_adi, sinav_turu=sinav_turu, 
        puan=puan, etkisi=etkisi, owner_id=owner_id, tarih=datetime.now().date()
    )
    db.add(yeni_not); db.commit(); db.close()
    return {"status": "success"}

# --- ARAÇ 8: Not Silme (DELETE) ---
def delete_ogrenci_notu(not_id: int):
    """
    Belirtilen ID'ye sahip öğrenci notunu veritabanından siler. 
    """
    db = next(get_db())
    try:
        notu_sil = db.query(Notlar).filter(Notlar.id == not_id).first()
        if not notu_sil:
            db.close()
            return {"status": "error", "message": f"ID {not_id} ile eşleşen bir not bulunamadı."}
        
        db.delete(notu_sil)
        db.commit()
        db.close()
        return {"status": "success", "message": f"ID {not_id} numaralı not başarıyla silindi."}
    except Exception as e:
        db.rollback()
        db.close()
        return {"status": "error", "message": f"Not silme sırasında iç hata: {e}"}
    
    # --- YENİ ARAÇ 11: Ders Programindan Ders Silme (Ders Adı ile) ---
def delete_ders_programi(ders_adi: str, owner_id: int):
    """
    Kullanıcının kendi ders programından belirli bir dersi siler.
    """
    db = next(get_db())
    try:
        # Sadece bu kullanıcıya (owner_id) ait olan ve ismi benzeyen dersi bul
        ders = db.query(DersProgrami).filter(
            DersProgrami.ders_adi.ilike(f"%{ders_adi}%"),
            DersProgrami.owner_id == owner_id
        ).first()

        if not ders:
            db.close()
            return {"status": "error", "message": f"Programınızda '{ders_adi}' isimli bir ders bulunamadı."}

        db.delete(ders)
        db.commit()
        db.close()
        return {"status": "success", "message": f"'{ders_adi}' dersi programınızdan silindi."}
    except Exception as e:
        db.rollback()
        db.close()
        return {"status": "error", "message": str(e)}

# --- ARAÇ 9: Sınav Güncelleme (UPDATE) ---
def update_sinav_takvimi(sinav_id: int, ders_adi: str = None, tarih: str = None, saat: str = None, konu: str = None):
    """
    Belirtilen ID'ye sahip sınav kaydını günceller. 
    Tarih "YYYY-MM-DD" ve saat "HH:MM" formatında olmalıdır.
    """
    db = next(get_db())
    try:
        sinav = db.query(SinavTakvimi).filter(SinavTakvimi.id == sinav_id).first()
        if not sinav:
            db.close()
            return {"status": "error", "message": f"ID {sinav_id} ile eşleşen bir sınav bulunamadı."}

        # Güncellenecek alanlar
        if ders_adi: sinav.ders_adi = ders_adi.capitalize()
        if tarih: sinav.tarih = datetime.strptime(tarih, "%Y-%m-%d").date()
        if saat: sinav.saat = datetime.strptime(saat, "%H:%M").time()
        if konu: sinav.konu = konu
        
        db.commit()
        db.refresh(sinav)
        db.close()
        return {"status": "success", "message": f"ID {sinav_id} numaralı sınav kaydı başarıyla güncellendi."}
    except ValueError:
        db.close()
        return {"status": "error", "message": "Geçersiz tarih veya saat formatı. Lütfen YYYY-MM-DD ve HH:MM formatlarını kullanın."}
    except Exception as e:
        db.rollback()
        db.close()
        return {"status": "error", "message": f"Sınav güncelleme sırasında iç hata: {e}"}

# --- ARAÇ 10: Servis Saatleri Çekme (READ - Servis) ---
def get_servis_saatleri(route_group: str = None, from_stop: str = None, to_stop: str = None):
    """
    Belirtilen durak ve güzergah gruplarına göre servis saatlerini veritabanından çeker.
    """
    db = next(get_db())
    query = db.query(ServisSaatleri)

    if route_group:
        query = query.filter(ServisSaatleri.route_group.ilike(f"%{route_group}%"))
    if from_stop:
        query = query.filter(ServisSaatleri.from_stop.ilike(f"%{from_stop}%"))
    if to_stop:
        query = query.filter(ServisSaatleri.to_stop.ilike(f"%{to_stop}%"))

    # Servis saatlerini saati küçükten büyüğe doğru sıralar
    saatler = query.order_by(ServisSaatleri.depart_time).all()
    db.close()

    if not saatler:
        return {"status": "success", "data": "Belirtilen kriterlere uygun servis saati bulunamadı."}
    
    result = []
    for servis in saatler:
        result.append({
            "route_group": servis.route_group,
            "from_stop": servis.from_stop,
            "to_stop": servis.to_stop,
            "depart_time": servis.depart_time.strftime("%H:%M")
        })
    
    # Cevabın daha anlaşılır olması için güzergah grubuna göre gruplayalım
    grouped_result = {}
    for item in result:
        group = item['route_group']
        if group not in grouped_result:
            grouped_result[group] = []
        grouped_result[group].append(f"Kalkış: {item['from_stop']} -> Varış: {item['to_stop']} @ {item['depart_time']}")

    return {"status": "success", "data": grouped_result}


# ----------------------------------------------------------------------
# ANA API UÇ NOKTASI (VERİTABANI ODAKLI)
# ----------------------------------------------------------------------

@app.post("/ask", summary="Akıllı asistan ile doğal dilde sorgulama yapın.")
def ask_assistant(query: QueryModel, current_user: User = Depends(get_current_user)):
    try: 
        prompt = query.prompt 
        context_mesaji = f"Merhaba {current_user.full_name}, senin öğrenci numaran {current_user.ogrenci_no}. Sorun: {prompt}"
        
        # 1. Gemini'ye Soru ve TÜM Araçları Gönder
        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=context_mesaji, 
            config=types.GenerateContentConfig(
                system_instruction=SYSTEM_PROMPT, 
                tools=[
                    get_ders_programi_by_gun, 
                    get_sinavlar_by_ders_ve_tarih, 
                    get_son_duyurular, 
                    get_ogrenci_notlari_ve_ortalama, 
                    add_ders_programi, 
                    add_sinav_takvimi, 
                    add_ogrenci_notu,
                    delete_ogrenci_notu, 
                    update_sinav_takvimi,
                    get_servis_saatleri 
                ]
            )
        )
        
        # 2. Araç Çağrısı Var mı Kontrol Et ve İşle
        if response.function_calls:
            tool_call = response.function_calls[0]
            func_name = tool_call.name; func_args = dict(tool_call.args)

            # Kişisel verilere erişen fonksiyonların listesi
            kisisel_fonksiyonlar = [
                "get_ders_programi_by_gun", "get_sinavlar_by_ders_ve_tarih", 
                "add_ders_programi", "add_sinav_takvimi", 
                "delete_ders_programi", "update_sinav_takvimi",
                "get_ogrenci_notlari_ve_ortalama", "add_ogrenci_notu"
            ]
            
            # Eğer çağrılan araç listedeyse, otomatik olarak owner_id ekle
            if func_name in kisisel_fonksiyonlar:
                func_args['owner_id'] = int(current_user.id) # Sayı olduğundan emin oluyoruz
                print(f"--- DEBUG: {func_name} aracı ID:{current_user.id} için çağrılıyor ---")
            # -----------------------------------------
            
            # Hangi fonksiyonu çağıracağını belirle
            
            if func_name == "get_ders_programi_by_gun": tool_output = get_ders_programi_by_gun(**func_args)
            elif func_name == "get_sinavlar_by_ders_ve_tarih": tool_output = get_sinavlar_by_ders_ve_tarih(**func_args)
            elif func_name == "get_son_duyurular": tool_output = get_son_duyurular(**func_args)
            elif func_name == "get_ogrenci_notlari_ve_ortalama":
                func_args['ogrenci_no'] = current_user.ogrenci_no; tool_output = get_ogrenci_notlari_ve_ortalama(**func_args)
            elif func_name == "add_ders_programi": tool_output = add_ders_programi(**func_args)
            elif func_name == "add_sinav_takvimi": tool_output = add_sinav_takvimi(**func_args)
            elif func_name == "add_ogrenci_notu": 
                func_args['ogrenci_no'] = current_user.ogrenci_no; tool_output = add_ogrenci_notu(**func_args)
            
            # YENİ ARAÇ ÇAĞRILARI
            elif func_name == "delete_ogrenci_notu": tool_output = delete_ogrenci_notu(**func_args) 
            elif func_name == "update_sinav_takvimi": tool_output = update_sinav_takvimi(**func_args)
            elif func_name == "get_servis_saatleri": tool_output = get_servis_saatleri(**func_args)
            elif func_name == "delete_ders_programi": tool_output = delete_ders_programi(**func_args) # GÜNCELLENDİ
            
            else: tool_output = {"status": "error", "message": f"Tanımlanmayan araç çağrısı: {func_name}"}
            # 3. Çekilen Veriyi Tekrar Gemini'ye Gönder
            second_response = client.models.generate_content(
                model='gemini-2.5-flash',
                contents=[context_mesaji, types.Content(parts=[types.Part.from_function_response(name=func_name, response=tool_output)])],
                config=types.GenerateContentConfig(system_instruction=SYSTEM_PROMPT)
            )
            return {"answer": second_response.text, "tool_used": func_name}

        # 4. Araç Çağrısı Yoksa
        return {"answer": response.text, "tool_used": "none"}

    except Exception as e: 
        print("\n*** ASİSTAN SORGUSUNDA KRİTİK PYTHON HATASI (main.py) ***:", e)
        raise HTTPException(status_code=500, detail=f"Asistan sorgulama işlemi iç hatası: {e}. Detaylar sunucu loglarında.")
            
# ----------------------------------------------------------------------
# TEST VERİSİ EKLEME FONKSİYONU
# ----------------------------------------------------------------------

@app.post("/test-veri-ekle", tags=["Geliştirme"])
def add_test_data(db: Session = Depends(get_db)):
    try:
        # Önce tüm tabloları temizleyelim
        db.execute(text("DELETE FROM notlar"))
        db.execute(text("DELETE FROM sinavlar"))
        db.execute(text("DELETE FROM ders_programi"))
        db.execute(text("DELETE FROM duyurular"))
        db.execute(text("DELETE FROM shuttle_trips"))
        db.execute(text("DELETE FROM users"))

        # 1. Test Kullanıcısını Oluştur (Bu kullanıcı ID: 1 olacak)
        hashed_pw = get_password_hash("123456")
        test_user = User(full_name="Test Öğrenci", email="test@iku.edu.tr", hashed_password=hashed_pw, ogrenci_no="2025001")
        db.add(test_user)
        db.commit()
        db.refresh(test_user) # ID'yi (1) almak için yeniliyoruz

        # 2. Dersleri Bu Kullanıcıya (owner_id=test_user.id) Ata
        db.add(DersProgrami(ders_adi="Matematik", gun="Pazartesi", saat_baslangic=time(9, 0), sinif_no="B-101", ogretmen_adi="Ayşe Yılmaz", owner_id=test_user.id))
        db.add(DersProgrami(ders_adi="Fizik", gun="Pazartesi", saat_baslangic=time(10, 0), sinif_no="C-205", ogretmen_adi="Mehmet Demir", owner_id=test_user.id))
        
        # 3. Notları Bu Kullanıcıya Ata
        db.add(Notlar(ogrenci_no="2025001", ders_adi="Matematik", sinav_turu="Vize", puan=75, etkisi=40, tarih=date(2025, 11, 15), owner_id=test_user.id))

        # 4. Genel Veriler (Duyuru ve Servislerde owner_id gerekmez)
        db.add(Duyuru(baslik="Kış Şenliği", icerik="Ertelenmiştir.", tarih=date(2025, 12, 12), kategori="Genel"))
        db.add(ServisSaatleri(route_group='ATAKOY', from_stop='Ataköy', to_stop='İncirli', depart_time=time(8, 30)))

        db.commit()
        return {"message": "Test verileri owner_id: 1 olan kullanıcı için başarıyla eklendi."}
    except Exception as e:
        db.rollback()
        return {"status": "error", "message": str(e)}
    
    # DOSYANIN EN SONU:
if __name__ == "__main__":
    import uvicorn
    import webbrowser
    from threading import Timer

    def open_browser():
        # Docs yerine doğrudan Streamlit arayüzünü (8501 portu) açmasını sağlayalım
        webbrowser.open("http://localhost:8501")

    print("Backend (FastAPI) başlatılıyor...")
    # Eğer sadece backend'i başlatacaksan 8000/docs kalabilir. 
    # Ama Streamlit'i ayrıca çalıştıracaksan bu Timer'a gerek kalmayabilir.
    # Yine de durmasında bir sakınca yok.
    uvicorn.run(app, host="127.0.0.1", port=8000)