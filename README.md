# Deanshing 2.0: Deteksi Phishing Real-time

!Deanshing 2.0 adalah sebuah aplikasi pendeteksi URL phishing real-time yang terintegrasi sebagai ekstensi browser Google Chrome, didukung oleh backend Flask berbasis Python. Aplikasi ini dirancang untuk membantu pengguna mengidentifikasi URL yang mencurigakan, melindungi mereka dari potensi serangan phishing.

## Fitur Utama

* **Deteksi URL Real-time:** Memungkinkan pengguna untuk memeriksa keamanan suatu URL secara cepat.
* **Backend Flask:** Menggunakan model machine learning yang di-host di server Flask untuk menganalisis URL dan memprediksi apakah itu phishing atau legitimate.
* **Ekstensi Google Chrome:**
    * **Popup Interaktif:** Antarmuka popup yang intuitif di mana pengguna dapat memasukkan URL secara manual, melihat hasil prediksi (Phishing/Legitimate), probabilitas, dan **alasan spesifik** mengapa URL tersebut terdeteksi sebagai phishing.
    * **Menu Konteks (Klik Kanan):** Pengguna dapat mengklik kanan pada teks terseleksi atau tautan (`link`) di halaman web untuk langsung memeriksa URL terkait. Hasil prediksi ditampilkan melalui notifikasi Chrome.
    * **Notifikasi Chrome:** Memberikan peringatan cepat atau konfirmasi keamanan URL. Untuk notifikasi dari klik kanan, **tidak ada alasan** yang ditampilkan, hanya status dan probabilitas.
* **Validasi URL Cerdas:** Memiliki fungsi validasi URL untuk memastikan hanya format URL yang valid yang diproses.

## Prasyarat

Sebelum menjalankan aplikasi ini, pastikan Anda memiliki hal-hal berikut terinstal:

* **Python 3.x**
* **pip** (Pengelola paket Python)
* **Google Chrome** (untuk menjalankan ekstensi)
* **Akses internet** (untuk koneksi ke beberapa API eksternal jika model menggunakan fitur eksternal seperti WHOIS, DNS, dll.)

## Instalasi dan Setup

Aplikasi ini terdiri dari dua bagian utama: Backend Flask dan Ekstensi Chrome.

### 1. Setup Backend Flask

1.  **Clone Repositori (jika ada):**
    ```bash
    git clone <URL_REPOSITORI_ANDA>
    cd <NAMA_FOLDER_BACKEND_ANDA> # Contoh: cd backend
    ```
    *Jika Anda hanya memiliki file, letakkan `app.py` dan file model (jika ada) dalam satu folder.*

2.  **Buat Virtual Environment (Opsional, tapi sangat disarankan):**
    ```bash
    python -m venv venv
    source venv/bin/activate  # Di Windows gunakan `venv\Scripts\activate`
    ```

3.  **Instal Dependensi Python:**
    Buat file `requirements.txt` di folder backend dengan daftar dependensi berikut:
    ```
    Flask
    scikit-learn
    pandas
    numpy
    urlextract
    tldextract
    python-whois # atau 'whois' tergantung implementasi di app.py
    dnspython # atau 'dnspython' tergantung implementasi di app.py
    # Tambahkan dependensi lain yang mungkin digunakan oleh model Anda (contoh: tensorflow, keras, xgboost, lightgbm dll.)
    ```
    Kemudian instal:
    ```bash
    pip install -r requirements.txt
    ```

4.  **Jalankan Server Flask:**
    Pastikan Anda berada di direktori backend tempat `app.py` berada.
    ```bash
    python app.py
    ```
    Server akan berjalan di `http://127.0.0.1:5000/`. Pastikan ini berjalan sebelum menggunakan ekstensi.

### 2. Setup Ekstensi Google Chrome

1.  **Dapatkan File Ekstensi:**
    Pastikan Anda memiliki semua file ekstensi (yaitu `manifest.json`, `background.js`, `popup.html`, `popup.js`, `popup.css`, dan folder `icons` beserta isinya) dalam satu folder.

2.  **Muat Ekstensi di Chrome:**
    * Buka Google Chrome.
    * Ketik `chrome://extensions` di bilah alamat dan tekan Enter.
    * Aktifkan **"Developer mode"** di pojok kanan atas layar.
    * Klik tombol **"Load unpacked"**.
    * Pilih folder tempat Anda menyimpan semua file ekstensi (misalnya, folder `extension`).

3.  Ekstensi "Deanshing 2.0" sekarang akan muncul di daftar ekstensi Anda dan ikonnya akan terlihat di bilah alat Chrome Anda.

## Penggunaan

1.  **Pastikan Backend Berjalan:** Sebelum menggunakan ekstensi, pastikan server Flask (`app.py`) sedang berjalan di `http://127.0.0.1:5000/`.

2.  **Menggunakan Popup Ekstensi:**
    * Klik ikon ekstensi Deanshing 2.0 di bilah alat Chrome Anda.
    * URL tab aktif saat ini akan otomatis terisi di kolom input.
    * Anda juga bisa memasukkan URL lain secara manual.
    * Klik tombol **"Check URL"**.
    * Hasil prediksi (Phishing/Legitimate), probabilitas, dan, jika terdeteksi phishing, **daftar alasan** akan ditampilkan di dalam popup.

3.  **Menggunakan Menu Konteks (Klik Kanan):**
    * Pada halaman web mana pun, blokir (seleksi) sebagian teks yang merupakan URL, atau klik kanan langsung pada suatu tautan (`link`).
    * Pilih opsi **"Periksa URL ini"** dari menu konteks.
    * Sebuah notifikasi Chrome akan muncul dengan hasil prediksi dan probabilitas. **Notifikasi ini tidak akan menampilkan alasan**.
