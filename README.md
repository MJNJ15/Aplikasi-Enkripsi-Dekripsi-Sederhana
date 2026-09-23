# 🔐 Aplikasi Enkripsi & Dekripsi Sederhana

> Belajar kriptografi klasik + modern secara visual. Enkripsi, dekripsi, lihat langkah proses per algoritma — langsung di browser via Streamlit.

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python" />
  <img src="https://img.shields.io/badge/Streamlit-1.62-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white" alt="Streamlit" />
  <img src="https://img.shields.io/badge/Crypto-pycryptodome-2E8B57?style=for-the-badge" alt="pycryptodome" />
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge" alt="License" />
</p>

<p align="center">
  <a href="#-cara-menjalankan-di-pc-lokal">🚀 Cara Jalan</a> •
  <a href="#-fitur">Fitur</a> •
  <a href="#-struktur-proyek">Struktur</a> •
  <a href="#-cara-pakai">Cara Pakai</a> •
  <a href="#-troubleshooting">Troubleshooting</a>
</p>

---

## ✨ Tentang Program

Aplikasi desktop-web sederhana untuk **enkripsi & dekripsi teks** dengan 5 mode:

| # | Mode | Jenis | Input | Output |
|---|------|-------|-------|--------|
| 1 | **Caesar Cipher** | Klasik | Plaintext / Ciphertext + shift 0-25 | Teks biasa |
| 2 | **Vigenère Cipher** | Klasik | Teks + kunci huruf A-Z | Teks biasa |
| 3 | **DES / DEA** | Modern (Blok 64-bit, CBC) | Teks + password | Base64 `salt+iv+ciphertext` |
| 4 | **Rijndael / AES-256** | Modern (Blok 128-bit, CBC) | Teks + password | Base64 `salt+iv+ciphertext` |
| 5 | **Super Enkripsi** | Gabungan 4 di atas | 4 kunci sekaligus | Base64 akhir |

Setiap proses tampilkan **langkah-langkah detail**: bytes, padding PKCS#7, pembagian blok, salt/IV, hex preview, sampai hasil akhir. Cocok untuk tugas Kriptografi & demo kelas.

### 🔁 Alur Super Enkripsi

```
Enkripsi :  Caesar (shift) → Vigenère (kunci) → DES (password) → Rijndael (password) → Base64
Dekripsi :  Rijndael → DES → Vigenère → Caesar  (otomatis dibalik)
```

> Semua algoritma modern pakai **PBKDF2-HMAC-SHA256** (100.000 iterasi) + **CBC** + **PKCS#7**. Salt & IV acak tiap enkripsi, jadi ciphertext beda walau plaintext sama.

---

## 🧩 Fitur

- 🔤 **Klasik transparan** — lihat pergeseran huruf & tabel Vigenère per karakter
- 🔒 **Modern real** — DES & AES-256 CBC dengan `pycryptodome`, bukan simulasi
- 🧬 **Super Cipher** — gabungan klasik + modern dalam 1 klik
- 📖 **Step-by-step expander** — tabel blok & hex preview, bukan cuma hasil akhir
- 🎛️ **5 Tab Streamlit** — UI pisah, tidak campur aduk
- ⚡ **Validasi input** — cegah teks kosong, kunci salah, Base64 invalid

---

## 📂 Struktur Proyek

```
Aplikasi-Enkripsi-Dekripsi-Sederhana/
├── app.py              # UI utama Streamlit (5 tabs)
├── caesar.py           # Logika Caesar Cipher
├── vigenere.py         # Logika Vigenère Cipher
├── des.py              # DES/CBC + PBKDF2 + Base64
├── rijndael.py         # AES-256/CBC + PBKDF2 + Base64
├── super_cipher.py     # Orkestrasi Super Enkripsi (4 lapis)
├── utils.py            # PKCS7, PBKDF2, preview, helper tabel
├── requirements.txt    # Dependensi
└── README.md
```

---

## 🛠️ Tech Stack

| Komponen | Teknologi |
|----------|-----------|
| UI | [Streamlit](https://streamlit.io) 1.62 |
| Kripto modern | [pycryptodome](https://www.pycryptodome.org) 3.23 (`Crypto.Cipher.DES/AES`) |
| KDF | `hashlib.pbkdf2_hmac` SHA256 |
| Bahasa | Python 3.10+ (tested 3.13 & 3.14) |

---

## ✅ Prasyarat

- **Git** terinstall (`git --version`)
- **Python 3.10+** (`python --version` / `python3 --version`)
- **pip** (`pip --version`)
- Browser modern (Chrome/Edge/Firefox)

---

## 🚀 Cara Menjalankan di PC Lokal

> Wajib **clone dulu**, jangan download ZIP manual biar mudah update.

### 1️⃣ Clone Repository

```bash
git clone https://github.com/MJNJ15/Aplikasi-Enkripsi-Dekripsi-Sederhana.git
```

### 2️⃣ Masuk Folder

```bash
cd Aplikasi-Enkripsi-Dekripsi-Sederhana
```

### 3️⃣ Buat Virtual Environment (Disarankan)

**Windows (PowerShell):**
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

**macOS / Linux:**
```bash
python3 -m venv venv
source venv/bin/activate
```

> Jika di Windows muncul error `execution policy`, jalankan: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`

### 4️⃣ Install Dependensi

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

Isi `requirements.txt`:
```
streamlit==1.62.0
pycryptodome==3.23.0
```

> Manual tanpa `requirements.txt`:
> ```bash
> pip install streamlit pycryptodome
> ```

### 5️⃣ Jalankan Aplikasi

```bash
streamlit run app.py
```

Berhasil → terminal tampil:
```
Local URL: http://localhost:8501
Network URL: http://192.168.x.x:8501
```
Buka `http://localhost:8501` di browser. Stop app: `Ctrl + C`.

### 6️⃣ Update ke Versi Terbaru (opsional)

```bash
git pull origin main
pip install -r requirements.txt --upgrade
```

---

## 🎮 Cara Pakai

| Tab | Langkah |
|-----|---------|
| **Caesar** | Pilih Enkripsi/Dekripsi → isi teks → set shift 0-25 → **Proses Caesar** → cek expander langkah |
| **Vigenère** | Pilih mode → isi teks → kunci huruf (contoh `KUNCI`) → **Proses Vigenère** |
| **DES / Rijndael** | Pilih mode → isi plaintext / ciphertext Base64 → isi password → **Proses DES/Rijndael** → copy Base64 untuk dekripsi |
| **Super Enkripsi** | Pilih mode → isi teks → isi 4 kunci (Caesar + Vigenère + password DES + password AES) → **Proses Super** |

**Tips:**
- Ciphertext modern & super selalu **Base64** — copy utuh, jangan kepotong.
- Password salah → error `Padding tidak valid` — wajar, bukan bug.
- Salt & IV acak → enkripsi 2x dengan password sama hasil beda (aman).

---

## ❓ Troubleshooting

<details>
<summary><b>1. `ModuleNotFoundError: No module named 'Crypto'`</b></summary>

```bash
pip uninstall crypto pycrypto -y
pip install pycryptodome --force-reinstall
```
Pastikan cuma `pycryptodome` yang terpasang, bukan `crypto`/`pycrypto` lama.

</details>

<details>
<summary><b>2. `streamlit: command not found`</b></summary>

Venv belum aktif atau pip salah. Coba:
```bash
python -m streamlit run app.py
# atau
pip install streamlit
```

</details>

<details>
<summary><b>3. Port 8501 sudah dipakai</b></summary>

```bash
streamlit run app.py --server.port 8502
```

</details>

<details>
<summary><b>4. Error PowerShell `Activate.ps1 cannot be loaded`</b></summary>

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\venv\Scripts\Activate.ps1
```

</details>

<details>
<summary><b>5. `ValueError: Input bukan Base64 valid` saat dekripsi</b></summary>

Pastikan paste ciphertext Base64 lengkap (tidak ada spasi/newline kepotong). Ciphertext harus dari hasil enkripsi app ini.

</details>

---

## 📸 Preview

> Jalankan `streamlit run app.py` → 5 tabs di atas, tiap tab ada expander **"Langkah-langkah proses"** + 2 kolom **Before → Result**.

```
[Aplikasi Enkripsi dan Dekripsi]
[ Caesar | Vigenère | DES | Rijndael | Super Enkripsi ]
   └─> Langkah-langkah proses (expandable)
   └─> [Plaintext sebelum]  [Hasil akhir]
```

---

## ⚠️ Catatan Keamanan

Proyek untuk **edukasi**, bukan produksi. DES sudah usang (pakai untuk demo saja). Untuk data sensitif real, pakai AES-GCM + manajemen kunci proper, jangan Super Cipher ini.

---

## 🤝 Kontribusi

1. Fork repo
2. Buat branch `fitur-nama`
3. Commit & push
4. Buka Pull Request

---

## 📄 Lisensi

MIT — bebas pakai, modif, share. Cantumkan credit.

<p align="center">
  Dibuat untuk mata kuliah Kriptografi 🔐 — Happy encrypting!
</p>
