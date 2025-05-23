from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import numpy as np

# ====================================================================
# MULAI KODE EKSTRAKSI FITUR ANDA (dari feature.py yang Anda berikan)
# ====================================================================
import ipaddress
import re
import urllib.request
from bs4 import BeautifulSoup
import socket
import requests
# Pastikan 'googlesearch-python' terinstal, dan ingat ini bisa lambat/diblokir Google
# from googlesearch import search 
import whois
from datetime import date, datetime
import time
from dateutil.parser import parse as date_parse
from urllib.parse import urlparse

# Mematikan peringatan SSL (hanya untuk pengembangan, tidak disarankan untuk produksi)
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

class FeatureExtraction:
    features = []
    def __init__(self,url):
        self.features = []
        self.url = url
        self.domain = ""
        self.whois_response = None
        self.urlparse = None
        self.response = None
        self.soup = None

        try:
            # Menggunakan timeout untuk request agar tidak menggantung terlalu lama
            # Menambahkan verify=False untuk mengabaikan sertifikat SSL (Hanya untuk debugging jika perlu, hapus di produksi)
            self.response = requests.get(url, timeout=5, verify=False) 
            self.soup = BeautifulSoup(self.response.text, 'html.parser')
        except requests.exceptions.RequestException as e:
            print(f"Error fetching URL {url}: {e}")
            # Lanjutkan meskipun gagal fetch, fitur terkait response/soup akan jadi -1
        except Exception as e:
            print(f"General error with BeautifulSoup: {e}")

        try:
            self.urlparse = urlparse(url)
            self.domain = self.urlparse.netloc
        except Exception as e:
            print(f"Error parsing URL {url}: {e}")

        # WHOIS bisa sangat lambat atau gagal, jadi penting untuk menanganinya
        if self.domain:
            try:
                self.whois_response = whois.whois(self.domain)
            except Exception as e:
                print(f"Error with WHOIS for domain {self.domain}: {e}")

        # Panggil semua fungsi fitur Anda secara berurutan
        # PASTIKAN URUTAN INI SAMA PERSIS DENGAN URUTAN FITUR SAAT ANDA MELATIH MODEL ANDA!
        self.features.append(self.UsingIp())
        self.features.append(self.longUrl())
        self.features.append(self.shortUrl())
        self.features.append(self.symbol())
        self.features.append(self.redirecting())
        self.features.append(self.prefixSuffix())
        self.features.append(self.SubDomains())
        self.features.append(self.Hppts())
        self.features.append(self.DomainRegLen())
        self.features.append(self.Favicon())
        self.features.append(self.NonStdPort())
        self.features.append(self.HTTPSDomainURL())
        self.features.append(self.RequestURL())
        self.features.append(self.AnchorURL())
        self.features.append(self.LinksInScriptTags())
        self.features.append(self.ServerFormHandler())
        self.features.append(self.InfoEmail())
        self.features.append(self.AbnormalURL())
        self.features.append(self.WebsiteForwarding())
        self.features.append(self.StatusBarCust())
        self.features.append(self.DisableRightClick())
        self.features.append(self.UsingPopupWindow())
        self.features.append(self.IframeRedirection())
        self.features.append(self.AgeofDomain())
        self.features.append(self.DNSRecording())
        self.features.append(self.WebsiteTraffic())
        self.features.append(self.PageRank())
        self.features.append(self.GoogleIndex())
        self.features.append(self.LinksPointingToPage())
        self.features.append(self.StatsReport())

    def UsingIp(self):
        try:
            if self.urlparse and self.urlparse.hostname:
                ipaddress.ip_address(self.urlparse.hostname)
                return -1
            return 1
        except:
            return 1

    def longUrl(self):
        if len(self.url) < 54:
            return 1
        if len(self.url) >= 54 and len(self.url) <= 75:
            return 0
        return -1

    def shortUrl(self):
        match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                          'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                          'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                          'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                          'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                          'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                          'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net', self.url)
        if match:
            return -1
        return 1

    def symbol(self):
        if re.findall("@",self.url):
            return -1
        return 1

    def redirecting(self):
        if self.urlparse and self.urlparse.path and '//' in self.urlparse.path:
            return -1
        return 1

    def prefixSuffix(self):
        try:
            if self.domain:
                match = re.findall('\-', self.domain)
                if match:
                    return -1
            return 1
        except:
            return -1

    def SubDomains(self):
        if not self.urlparse or not self.urlparse.netloc:
            return -1

        dot_count = len([x for x in self.urlparse.netloc if x == '.'])
        if dot_count == 1:
            return 1
        elif dot_count == 2:
            return 0
        return -1

    def Hppts(self):
        try:
            if self.urlparse and 'https' in self.urlparse.scheme:
                return 1
            return -1
        except:
            return -1
            
    def DomainRegLen(self):
        try:
            if not self.whois_response or not self.whois_response.creation_date or not self.whois_response.expiration_date:
                return -1

            creation_date = self.whois_response.creation_date
            expiration_date = self.whois_response.expiration_date

            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]
            
            if not isinstance(creation_date, datetime):
                creation_date = date_parse(str(creation_date))
            if not isinstance(expiration_date, datetime):
                expiration_date = date_parse(str(expiration_date))

            # Hitung selisih tahun, bukan bulan, untuk usia registrasi.
            # Domain yang didaftarkan kurang dari 1 tahun cenderung mencurigakan.
            age_in_days = (expiration_date - creation_date).days
            if age_in_days >= 365: # Jika durasi pendaftaran 1 tahun atau lebih
                return 1
            return -1
        except Exception as e:
            # print(f"Error in DomainRegLen: {e}") # Debugging
            return -1

    def Favicon(self):
        try:
            if not self.soup: return -1
            for link_tag in self.soup.find_all('link', rel=re.compile("icon", re.I), href=True):
                parsed_link_href = urlparse(link_tag['href'])
                if parsed_link_href.netloc == self.domain or not parsed_link_href.netloc:
                    return 1
            return -1
        except:
            return -1

    def NonStdPort(self):
        if self.urlparse and self.urlparse.port and self.urlparse.port not in [80, 443]:
            return -1
        return 1

    def HTTPSDomainURL(self):
        try:
            if self.domain and 'https' in self.domain:
                return -1
            return 1
        except:
            return -1
            
    def RequestURL(self):
        try:
            if not self.soup: return -1
            i, success = 0, 0
            for tag in self.soup.find_all(['img', 'audio', 'embed', 'iframe'], src=True):
                src_url = urlparse(tag['src'])
                if src_url.netloc == self.domain or not src_url.netloc:
                    success += 1
                i += 1

            if i == 0: return 0
            percentage = success / float(i) * 100
            if percentage < 22.0:
                return 1
            elif((percentage >= 22.0) and (percentage < 61.0)):
                return 0
            else:
                return -1
        except Exception as e:
            return -1
            
    def AnchorURL(self):
        try:
            if not self.soup: return -1
            i, unsafe = 0, 0
            for a in self.soup.find_all('a', href=True):
                href_attr = a['href'].lower()
                if "#" in href_attr or "javascript" in href_attr or "mailto" in href_attr or (urlparse(href_attr).netloc and urlparse(href_attr).netloc != self.domain):
                    unsafe += 1
                i += 1

            if i == 0: return 0
            percentage = unsafe / float(i) * 100
            if percentage < 31.0:
                return 1
            elif ((percentage >= 31.0) and (percentage < 67.0)):
                return 0
            else:
                return -1
        except Exception as e:
            return -1

    def LinksInScriptTags(self):
        try:
            if not self.soup: return -1
            i, success = 0, 0

            for link_tag in self.soup.find_all('link', href=True):
                parsed_href = urlparse(link_tag['href'])
                if parsed_href.netloc == self.domain or not parsed_href.netloc:
                    success += 1
                i += 1

            for script_tag in self.soup.find_all('script', src=True):
                parsed_src = urlparse(script_tag['src'])
                if parsed_src.netloc == self.domain or not parsed_src.netloc:
                    success += 1
                i += 1

            if i == 0: return 0
            percentage = success / float(i) * 100
            if percentage < 17.0:
                return 1
            elif((percentage >= 17.0) and (percentage < 81.0)):
                return 0
            else:
                return -1
        except Exception as e:
            return -1

    def ServerFormHandler(self):
        try:
            if not self.soup: return -1
            forms = self.soup.find_all('form', action=True)
            if len(forms) == 0:
                return 1
            else :
                for form in forms:
                    action_attr = form['action']
                    if action_attr == "" or action_attr == "about:blank":
                        return -1
                    elif urlparse(action_attr).netloc and urlparse(action_attr).netloc != self.domain:
                        return 0
                return 1
        except Exception as e:
            return -1

    def InfoEmail(self):
        try:
            if not self.soup: return -1
            if re.findall(r"[mail\(|mailto:?]", self.soup.text, re.IGNORECASE):
                return -1
            else:
                return 1
        except:
            return -1

    def AbnormalURL(self):
        try:
            if self.whois_response:
                return 1
            else:
                return -1
        except:
            return -1

    def WebsiteForwarding(self):
        try:
            if self.response is None:
                return -1
            history_length = len(self.response.history)
            if history_length <= 1:
                return 1
            elif history_length <= 4:
                return 0
            else:
                return -1
        except:
            return -1

    def StatusBarCust(self):
        try:
            if not self.response: return -1
            if re.findall("<script>.+onmouseover.+</script>", self.response.text, re.IGNORECASE):
                return -1
            else:
                return 1
        except:
            return -1

    def DisableRightClick(self):
        try:
            if not self.response: return -1
            if re.findall(r"event.button ?== ?2|oncontextmenu", self.response.text, re.IGNORECASE):
                return -1
            else:
                return 1
        except:
            return -1

    def UsingPopupWindow(self):
        try:
            if not self.response: return -1
            if re.findall(r"alert\(|window\.open\(", self.response.text, re.IGNORECASE):
                return -1
            else:
                return 1
        except:
            return -1

    def IframeRedirection(self):
        try:
            if not self.response: return -1
            if re.findall(r"<iframe|<frameborder>", self.response.text, re.IGNORECASE):
                return -1
            else:
                return 1
        except:
            return -1

    def AgeofDomain(self):
        try:
            if not self.whois_response or not self.whois_response.creation_date:
                return -1

            creation_date = self.whois_response.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            if not isinstance(creation_date, datetime):
                creation_date = date_parse(str(creation_date))

            today = date.today()
            age = (today.year - creation_date.year) * 12 + (today.month - creation_date.month)
            if age >= 6:
                return 1
            return -1
        except Exception as e:
            return -1

    def DNSRecording(self):
        try:
            if not self.whois_response or not self.whois_response.creation_date:
                return -1 # DNS Record tidak ditemukan (berdasarkan WHOIS)

            # Jika ada creation_date, diasumsikan DNS record ada
            return 1
        except Exception as e:
            return -1
            
    def WebsiteTraffic(self):
        try:
            # PERHATIAN: Alexa Ranking API sudah tidak tersedia secara publik.
            # Baris di bawah ini kemungkinan besar akan menyebabkan error.
            # Anda perlu mengganti ini atau menghapusnya jika tidak bisa berfungsi.
            # Untuk skripsi, disarankan mencari alternatif yang berfungsi atau menyatakan keterbatasan.
            # Sebagai placeholder, saya akan mengembalikan -1 (mencurigakan)
            # Jika Anda memiliki sumber lain, implementasikan di sini.
            
            # response_alexa = urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + self.url, timeout=5).read()
            # rank = BeautifulSoup(response_alexa, "xml").find("REACH")['RANK']
            # if (int(rank) < 100000):
            #     return 1
            # return 0
            return -1 # Default -1 karena Alexa tidak lagi berfungsi
        except :
            return -1

    def PageRank(self):
        try:
            # checkpagerank.net mungkin memiliki batasan atau perubahan API.
            # Bagian ini juga berpotensi menyebabkan error atau selalu mengembalikan -1.
            # Sebagai placeholder, saya akan mengembalikan -1 (mencurigakan)
            # Jika Anda memiliki sumber lain, implementasikan di sini.
            
            # prank_checker_response = requests.post("https://www.checkpagerank.net/index.php", {"name": self.domain}, timeout=5)
            # global_rank_match = re.findall(r"Global Rank: ([0-9]+)", prank_checker_response.text)
            # if global_rank_match:
            #     global_rank = int(global_rank_match[0])
            #     if global_rank > 0 and global_rank < 100000:
            #         return 1
            # return -1
            return -1 # Default -1
        except Exception as e:
            return -1
            
    def GoogleIndex(self):
        try:
            # PERHATIAN: Menggunakan googlesearch.search secara real-time bisa sangat lambat,
            # dan Google dapat memblokir permintaan otomatis. Ini bisa menjadi bottleneck.
            # Sebagai placeholder, saya akan mengembalikan -1 (mencurigakan)
            # Jika Anda memiliki akses ke Google Search API, gunakan itu.
            
            # from googlesearch import search # Pastikan diimpor jika digunakan
            # site_in_google = False
            # for url_in_search in search(self.url, num_results=1, stop=1, pause=2):
            #     if self.url in url_in_search or self.domain in url_in_search:
            #         site_in_google = True
            #         break
            # if site_in_google:
            #     return 1
            # else:
            #     return -1
            return -1 # Default -1
        except Exception as e:
            return -1

    def LinksPointingToPage(self):
        try:
            if not self.response: return -1
            number_of_links = len(re.findall(r"<a href=", self.response.text))
            if number_of_links == 0:
                return 1
            elif number_of_links <= 2:
                return 0
            else:
                return -1
        except:
            return -1

    def StatsReport(self):
        try:
            url_match = re.search(
                'at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly', self.url)
            
            ip_address = None
            if self.domain:
                try:
                    ip_address = socket.gethostbyname(self.domain)
                except socket.gaierror:
                    pass 

            ip_match = None
            if ip_address:
                ip_match = re.search('146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158|181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.219|46\.242\.145\.98|'
                                      '107\.151\.148\.44|107\.151\.148\.107|64\.70\.19\.203|199\.184\.144\.27|107\.151\.148\.108|107\.151\.148\.109|119\.28\.52\.61|54\.83\.43\.69|52\.69\.166\.231|216\.58\.192\.225|'
                                      '118\.184\.25\.86|67\.208\.74\.71|23\.253\.126\.58|104\.239\.157\.210|175\.126\.123\.219|141\.8\.224\.221|10\.10\.10\.10|43\.229\.108\.32|103\.232\.215\.140|69\.172\.201\.153|'
                                      '216\.218\.185\.162|54\.225\.104\.146|103\.243\.24\.98|199\.59\.243\.120|31\.170\.160\.61|213\.19\.128\.77|62\.113\.226\.131|208\.100\.26\.234|195\.16\.127\.102|195\.16\.127\.157|'
                                      '34\.196\.13\.28|103\.224\.212\.222|172\.217\.4\.225|54\.72\.9\.51|192\.64\.147\.141|198\.200\.56\.183|23\.253\.164\.103|52\.48\.191\.26|52\.214\.197\.72|87\.98\.255\.18|209\.99\.17\.27|'
                                      '216\.38\.62\.18|104\.130\.124\.96|47\.89\.58\.141|78\.46\.211\.158|54\.86\.225\.156|54\.82\.156\.19|37\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42', ip_address)
            
            if url_match:
                return -1
            elif ip_match:
                return -1
            return 1
        except Exception as e:
            return 1

    def getFeaturesList(self):
        return self.features

# ====================================================================
# AKHIR KODE EKSTRAKSI FITUR ANDA
# ====================================================================


app = Flask(__name__)
CORS(app) 

# Muat model yang sudah Anda latih
try:
    model = joblib.load('random_forest_model.joblib')
    print("Model Random Forest berhasil dimuat.")
    # Jika Anda menggunakan scaler, muat di sini:
    # scaler = joblib.load('scaler.joblib')
    # print("Scaler berhasil dimuat.")
except Exception as e:
    print(f"ERROR: Gagal memuat model atau scaler. Pastikan file ada dan benar: {e}")
    model = None
    # scaler = None

# --- Fungsi untuk menghasilkan alasan phishing berdasarkan nilai fitur ---
def generate_phishing_reasons(features, url):
    reasons = []
    
    # Mapping fitur ke deskripsi yang lebih mudah dimengerti
    feature_names = [
        "UsingIp", "longUrl", "shortUrl", "symbol", "redirecting",
        "prefixSuffix", "SubDomains", "Hppts", "DomainRegLen", "Favicon",
        "NonStdPort", "HTTPSDomainURL", "RequestURL", "AnchorURL",
        "LinksInScriptTags", "ServerFormHandler", "InfoEmail", "AbnormalURL",
        "WebsiteForwarding", "StatusBarCust", "DisableRightClick", "UsingPopupWindow",
        "IframeRedirection", "AgeofDomain", "DNSRecording", "WebsiteTraffic",
        "PageRank", "GoogleIndex", "LinksPointingToPage", "StatsReport"
    ]
    
    # Pastikan jumlah fitur sesuai dengan yang diharapkan
    if len(features) != len(feature_names):
        print(f"Warning: Jumlah fitur ({len(features)}) tidak cocok dengan jumlah nama fitur ({len(feature_names)}).")
        return ["Deteksi ambigu karena jumlah fitur tidak cocok."]

    for i, feature_value in enumerate(features):
        feature_name = feature_names[i]
        
        # Aturan sederhana untuk menentukan alasan berdasarkan nilai fitur (-1 = mencurigakan, 0 = hati-hati)
        if feature_value == -1:
            if feature_name == "UsingIp":
                reasons.append("URL menggunakan alamat IP alih-alih nama domain.")
            elif feature_name == "longUrl":
                reasons.append(f"URL terlalu panjang ({len(url)} karakter), mencurigakan.")
            elif feature_name == "shortUrl":
                reasons.append("URL dipersingkat menggunakan layanan URL shortener.")
            elif feature_name == "symbol":
                reasons.append("URL mengandung simbol '@' yang sering digunakan untuk menyamarkan domain asli.")
            elif feature_name == "redirecting":
                reasons.append("Terdapat pengalihan ganda pada URL (misalnya '//' di path).")
            elif feature_name == "prefixSuffix":
                reasons.append("Domain mengandung tanda hubung yang mencurigakan (misalnya 'paypal-login.com').")
            elif feature_name == "SubDomains":
                reasons.append("URL memiliki terlalu banyak subdomain (misalnya 'sub.sub.domain.com').")
            elif feature_name == "Hppts":
                reasons.append("URL tidak menggunakan protokol HTTPS.")
            elif feature_name == "DomainRegLen":
                reasons.append("Durasi registrasi domain kurang dari 1 tahun.")
            elif feature_name == "Favicon":
                reasons.append("Favicon tidak berasal dari domain utama.")
            elif feature_name == "NonStdPort":
                reasons.append(f"URL menggunakan port non-standar ({urlparse(url).port}).")
            elif feature_name == "HTTPSDomainURL":
                reasons.append("Kata 'https' muncul dalam nama domain, bukan hanya di protokol.")
            elif feature_name == "RequestURL":
                reasons.append("Konten eksternal (gambar/iframe) dimuat dari domain yang berbeda secara signifikan.")
            elif feature_name == "AnchorURL":
                reasons.append("Banyak tautan anchor (<a>) mengarah ke domain yang berbeda atau menggunakan Javascript/mailto.")
            elif feature_name == "LinksInScriptTags":
                reasons.append("Banyak tautan atau script eksternal dimuat dari domain yang berbeda secara signifikan.")
            elif feature_name == "ServerFormHandler":
                reasons.append("Formulir web memproses data ke domain yang berbeda atau menggunakan 'about:blank'.")
            elif feature_name == "InfoEmail":
                reasons.append("Terdapat fungsi 'mailto' atau 'mail()' dalam HTML.")
            elif feature_name == "AbnormalURL":
                reasons.append("Informasi WHOIS domain tidak dapat diakses atau tidak normal.")
            elif feature_name == "WebsiteForwarding":
                reasons.append("Terdapat lebih dari 4 pengalihan (redirect) halaman.")
            elif feature_name == "StatusBarCust":
                reasons.append("Skrip mencoba mengubah tampilan status bar browser.")
            elif feature_name == "DisableRightClick":
                reasons.append("Tombol klik kanan dinonaktifkan di halaman ini.")
            elif feature_name == "UsingPopupWindow":
                reasons.append("Situs menggunakan jendela pop-up yang mencurigakan.")
            elif feature_name == "IframeRedirection":
                reasons.append("Situs menggunakan iframe yang bisa menyembunyikan konten berbahaya.")
            elif feature_name == "AgeofDomain":
                reasons.append("Usia domain kurang dari 6 bulan, sering digunakan untuk situs phishing baru.")
            elif feature_name == "DNSRecording":
                reasons.append("Tidak ada catatan DNS yang ditemukan untuk domain ini.")
            elif feature_name == "WebsiteTraffic":
                reasons.append("Tidak ada informasi lalu lintas situs (misalnya Alexa Rank) yang tersedia atau sangat rendah.")
            elif feature_name == "PageRank":
                reasons.append("PageRank situs sangat rendah atau tidak ada.")
            elif feature_name == "GoogleIndex":
                reasons.append("URL tidak terdaftar di indeks Google (mungkin situs baru/tersembunyi).")
            elif feature_name == "LinksPointingToPage":
                reasons.append("Jumlah tautan masuk ke halaman ini sangat rendah.")
            elif feature_name == "StatsReport":
                reasons.append("URL atau IP terkait dengan host/IP yang dikenal mencurigakan.")
        elif feature_value == 0:
            if feature_name == "longUrl":
                reasons.append(f"Panjang URL sedang ({len(url)} karakter), perlu diperhatikan.")
            elif feature_name == "SubDomains":
                reasons.append("URL memiliki beberapa subdomain (misalnya 'www.sub.domain.com').")
            elif feature_name == "RequestURL":
                reasons.append("Beberapa konten eksternal dimuat dari domain yang berbeda.")
            elif feature_name == "AnchorURL":
                reasons.append("Beberapa tautan anchor mengarah ke domain yang berbeda.")
            elif feature_name == "LinksInScriptTags":
                reasons.append("Beberapa tautan atau script eksternal dimuat dari domain yang berbeda.")
            elif feature_name == "WebsiteForwarding":
                reasons.append("Terdapat 2-4 pengalihan (redirect) halaman.")

    return list(set(reasons)) # Hapus duplikasi alasan

@app.route('/predict', methods=['POST'])
def predict():
    if not model:
        return jsonify({"status": "error", "message": "Model tidak dimuat di server."}), 500

    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({"status": "error", "message": "Permintaan tidak valid. 'url' tidak ditemukan."}), 400

    input_url = data['url']
    
    try:
        extractor = FeatureExtraction(input_url)
        raw_features = extractor.getFeaturesList() # Dapatkan list fitur mentah
        
        # Ubah ke numpy array 2D untuk input model
        features = np.array([raw_features]) 
        
        # Jika Anda menggunakan scaler, terapkan di sini:
        # features_scaled = scaler.transform(features)
        # prediction = model.predict(features_scaled)[0]
        # probability = model.predict_proba(features_scaled)[0].tolist()

        prediction = model.predict(features)[0]
        probability = model.predict_proba(features)[0].tolist()

        result_label = "Unknown"
        prob_legitimate = 0.5
        prob_phishing = 0.5
        
        # Pastikan kelas-kelas model diketahui
        model_classes = model.classes_.tolist()
        if 1 in model_classes:
            prob_legitimate = probability[model_classes.index(1)]
        if -1 in model_classes:
            prob_phishing = probability[model_classes.index(-1)]

        reasons = []
        if prediction == 1:
            result_label = "Legitimate"
            # Tidak ada alasan jika legitimate
        elif prediction == -1:
            result_label = "Phishing"
            # Panggil fungsi untuk menghasilkan alasan HANYA JIKA phishing
            reasons = generate_phishing_reasons(raw_features, input_url)
        else:
            result_label = "Unknown" # Jika prediksi bukan 1 atau -1
            reasons.append("Prediksi tidak jelas.")


        return jsonify({
            "status": "success",
            "url": input_url,
            "prediction": result_label,
            "probability_phishing": prob_phishing,
            "probability_legitimate": prob_legitimate,
            "reasons": reasons # Sekarang alasan dikirim!
        })
    except Exception as e:
        print(f"Error saat prediksi URL '{input_url}': {e}")
        return jsonify({"status": "error", "message": f"Terjadi kesalahan saat memproses URL: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)