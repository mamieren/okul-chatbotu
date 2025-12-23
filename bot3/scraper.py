import requests
from bs4 import BeautifulSoup

def veri_getir(link_listesi):
    birlesik_veri = ""
    for url in link_listesi:
        try:
            res = requests.get(url, timeout=10)
            res.encoding = 'utf-8'
            soup = BeautifulSoup(res.text, 'html.parser')
            # Tablo verilerini ve içindeki linkleri temizle
            for row in soup.find_all('tr'):
                cells = row.find_all(['td', 'th'])
                satir = []
                for cell in cells:
                    link = cell.find('a')
                    if link and link.get('href'):
                        href = link.get('href')
                        if not href.startswith('http'):
                            href = "https://akademikpaket.iku.edu.tr/TR/" + href
                        satir.append(f"{cell.get_text(strip=True)} [URL:{href}]")
                    else:
                        satir.append(cell.get_text(strip=True))
                birlesik_veri += " | ".join(satir) + "\n"
        except: continue
    return birlesik_veri

def ders_detay_getir(url):
    try:
        res = requests.get(url, timeout=10)
        res.encoding = 'utf-8'
        soup = BeautifulSoup(res.text, 'html.parser')
        return soup.get_text(separator=' ', strip=True)
    except:
        return "İçerik çekilemedi."