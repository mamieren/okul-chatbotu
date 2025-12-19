from sqlalchemy import create_engine, Column, Integer, String, Date, Time, Boolean, ForeignKey
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

# Kendi bağlantı bilgilerine göre düzenle
SERVER_NAME = "DESKTOP-3M4E4P0" 
DATABASE_NAME = "SchoolAssistantDB" 

SQLALCHEMY_DATABASE_URL = (
    f"mssql+pyodbc://{SERVER_NAME}/{DATABASE_NAME}?driver=ODBC+Driver+17+for+SQL+Server"
)

engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# ----------------------------------------------------------------------
# TABLO MODELLERİ (YENİLENMİŞ)
# ----------------------------------------------------------------------

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    full_name = Column(String(100)) 
    email = Column(String(100), unique=True, index=True) 
    hashed_password = Column(String) 
    ogrenci_no = Column(String(50), unique=True, index=True) 
    is_active = Column(Boolean, default=True) 

class DersProgrami(Base):
    __tablename__ = "ders_programi"
    id = Column(Integer, primary_key=True, index=True) 
    # YENİ: Bu ders kime ait?
    owner_id = Column(Integer, index=True) 
    ders_adi = Column(String(100), index=True) 
    gun = Column(String(20)) 
    saat_baslangic = Column(Time) 
    sinif_no = Column(String(10))
    ogretmen_adi = Column(String(100))

class SinavTakvimi(Base):
    __tablename__ = "sinavlar"
    id = Column(Integer, primary_key=True, index=True)
    # YENİ: Bu sınav kime ait?
    owner_id = Column(Integer, index=True)
    ders_adi = Column(String(100), index=True)
    sinif_duzeyi = Column(String(10)) 
    tarih = Column(Date) 
    saat = Column(Time) 
    konu = Column(String(255))
    ogretmen_adi = Column(String(100))

class Notlar(Base):
    __tablename__ = "notlar"
    id = Column(Integer, primary_key=True, index=True)
    # YENİ: Bu not kime ait?
    owner_id = Column(Integer, index=True)
    ogrenci_no = Column(String(50), index=True) 
    ders_adi = Column(String(100), index=True)
    sinav_turu = Column(String(50)) 
    puan = Column(Integer) 
    etkisi = Column(Integer) 
    tarih = Column(Date) 

class Duyuru(Base):
    __tablename__ = "duyurular"
    id = Column(Integer, primary_key=True, index=True)
    baslik = Column(String(255), index=True)
    icerik = Column(String) 
    tarih = Column(Date)
    kategori = Column(String(50)) 
    yayinlayan = Column(String(100))

class ServisSaatleri(Base):
    __tablename__ = "shuttle_trips" # Ortak tablo, owner_id gerekmez
    id = Column(Integer, primary_key=True, index=True)
    route_group = Column(String(50), index=True) 
    from_stop = Column(String(80))
    to_stop = Column(String(80)) 
    depart_time = Column(Time) 

# Tabloları oluştur
Base.metadata.create_all(bind=engine)

# Veritabanı oturumu sağlayan yardımcı fonksiyon
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()