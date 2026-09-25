import base64
import os
from Crypto.Cipher import DES
from utils import (
    derive_key, pkcs7_pad, pkcs7_unpad, bytes_preview,
    split_into_blocks, make_code_step, make_table_step, preview
)

ALGORITHM_NAME = "DES (DEA)"
BLOCK_SIZE = 8  # 64 bit
KEY_SIZE = 8    # 64 bit (56 bit efektif + 8 bit paritas)

def des_process(text: str, password: str, mode: str):
    if not password:
        raise ValueError("Password tidak boleh kosong.")
    
    steps = []
    nomor = 0
    
    def jelaskan(pesan):
        nonlocal nomor
        nomor += 1
        steps.append(f"**Langkah {nomor}.** {pesan}")
        
    def judul(pesan):
        steps.append(f"### {pesan}")

    # ======================== ENKRIPSI ========================
    if mode == "encrypt":
        judul("Tahap 1: Preparasi Plaintext")
        
        plaintext_bytes = text.encode("utf-8")
        jelaskan("Plaintext dikonversi menjadi representasi biner (*byte array*) menggunakan encoding UTF-8.")
        steps.append(make_code_step("Representasi Heksadesimal Plaintext", bytes_preview(plaintext_bytes, 128)))
        
        padded_bytes, pad_len = pkcs7_pad(plaintext_bytes, BLOCK_SIZE)
        jelaskan(f"Diterapkan skema *padding* **PKCS#7** dengan penambahan **{pad_len} byte** agar panjang plaintext memenuhi kelipatan *block size* DES (64 bit / 8 byte).")
        steps.append(make_code_step("Plaintext Setelah Padding", bytes_preview(padded_bytes, 128)))
        
        blocks = split_into_blocks(padded_bytes, BLOCK_SIZE)
        block_rows = [{"Blok ke": i+1, "Ukuran": f"{len(b)} byte", "Hex": b.hex()} for i, b in enumerate(blocks)]
        jelaskan(f"Plaintext yang telah di-*padding* dipartisi menjadi **{len(blocks)} blok data**, di mana masing-masing blok berukuran 64 bit untuk diproses secara iteratif.")
        steps.append(make_table_step("Partisi Blok Plaintext", block_rows))

        judul("Tahap 2: Pembangkitan Kunci dan Parameter Inisialisasi")
        
        salt = os.urandom(8)
        iv = os.urandom(BLOCK_SIZE)
        key = derive_key(password, salt, KEY_SIZE)
        
        jelaskan(f"Dihasilkan nilai *cryptographic salt* acak: `{salt.hex()}`. *Salt* digunakan untuk mencegah serangan *rainbow table* dan memastikan *key derivation* yang unik.")
        jelaskan(f"Dihasilkan *Initialization Vector* (IV) acak: `{iv.hex()}`. IV digunakan pada mode *Cipher Block Chaining* (CBC) untuk mengacak blok plaintext pertama dan mencegah pola ciphertext yang berulang.")
        jelaskan(f"Password dan *salt* diproses melalui fungsi *Key Derivation* (PBKDF2-HMAC-SHA256) untuk menghasilkan *symmetric key* DES sepanjang 64 bit: `{key.hex()}`.")
        steps.append(make_code_step("Symmetric Key DES", key.hex()))

        judul("Tahap 3: Eksekusi Algoritma DES (Mode CBC)")
        
        jelaskan("**Sub-tahap 3.1 — *Initial Permutation* (IP):** 64 bit blok plaintext mengalami permutasi awal berdasarkan tabel standar DES. Tahap ini merupakan standar struktur algoritma sebelum masuk ke jaringan *Feistel*.")
        jelaskan("**Sub-tahap 3.2 — *Feistel Network* (16 Ronde):** Blok 64 bit dibagi menjadi dua sub-blok (Kiri dan Kanan). Dilakukan 16 iterasi fungsi *Feistel*, di mana sub-blok kanan diproses melalui fungsi kompresi (Ekspansi, *XOR* dengan *subkey*, substitusi melalui *S-box*, dan *P-box permutation*), kemudian di-*XOR* dengan sub-blok kiri. Sub-blok kiri dan kanan kemudian ditukar (*swap*).")
        jelaskan("**Sub-tahap 3.3 — *Inverse Initial Permutation* (IP⁻¹):** Output dari ronde ke-16 mengalami permutasi balik (kebalikan dari IP) untuk menghasilkan *ciphertext* 64 bit akhir.")
        
        cipher = DES.new(key, DES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(padded_bytes)
        steps.append(make_code_step("Ciphertext Hasil Enkripsi", bytes_preview(ciphertext, 128)))

        judul("Tahap 4: Pengemasan Payload")
        
        payload = salt + iv + ciphertext
        output = base64.b64encode(payload).decode("ascii")
        
        jelaskan(f"Komponen *salt* (8 byte), *IV* ({BLOCK_SIZE} byte), dan *ciphertext* ({len(ciphertext)} byte) dikonsolidasi menjadi satu *payload* biner, kemudian di-*encode* menggunakan **Base64** untuk memastikan integritas dan kompatibilitas transmisi data berbasis teks.")
        steps.append(make_code_step("Output Base64 Akhir", preview(output, 300)))
        jelaskan("Proses enkripsi selesai. *Ciphertext* siap untuk ditransmisikan.")
        
        return output, steps
    
    # ======================== DEKRIPSI ========================
    judul("Tahap 1: Ekstraksi Payload")
    
    cleaned = text.strip()
    if not cleaned:
        raise ValueError("Ciphertext kosong.")
    
    try:
        payload = base64.b64decode(cleaned)
    except Exception:
        raise ValueError("Input bukan Base64 valid.")
    
    jelaskan("*Payload* Base64 didekodekan kembali menjadi representasi *byte array*.")
    
    min_len = 8 + BLOCK_SIZE + BLOCK_SIZE
    if len(payload) < min_len:
        raise ValueError("Payload terlalu pendek.")
    
    salt = payload[:8]
    iv = payload[8:8+BLOCK_SIZE]
    ciphertext = payload[8+BLOCK_SIZE:]
    
    jelaskan(f"*Cryptographic salt* diekstrak: `{salt.hex()}`.")
    jelaskan(f"*Initialization Vector* (IV) diekstrak: `{iv.hex()}`.")
    jelaskan(f"*Ciphertext* ({len(ciphertext)} byte) diekstrak.")
    steps.append(make_code_step("Ciphertext Hasil Ekstraksi", bytes_preview(ciphertext, 128)))

    judul("Tahap 2: Rekonstruksi Symmetric Key")
    
    key = derive_key(password, salt, KEY_SIZE)
    jelaskan("*Symmetric key* direkonstruksi menggunakan password dan *salt* yang diekstrak melalui fungsi *Key Derivation* (PBKDF2). Kesalahan password akan menghasilkan *key* yang berbeda secara signifikan (memenuhi prinsip *avalanche effect*).")

    judul("Tahap 3: Dekripsi Algoritma DES (Mode CBC)")
    
    jelaskan("Proses dekripsi dilakukan menggunakan algoritma DES yang identik dengan enkripsi, namun dengan urutan *subkey* yang dibalik (dari ronde ke-16 menuju ronde ke-1) sesuai dengan properti inversi pada jaringan *Feistel*.")
    
    cipher = DES.new(key, DES.MODE_CBC, iv)
    try:
        padded_plaintext = cipher.decrypt(ciphertext)
    except Exception as e:
        raise ValueError(f"Dekripsi gagal: {e}")
    
    steps.append(make_code_step("Data Terdekripsi (Masih Terdapat Padding)", bytes_preview(padded_plaintext, 128)))

    judul("Tahap 4: Rekonstruksi Plaintext")
    
    try:
        plaintext_bytes, pad_len = pkcs7_unpad(padded_plaintext, BLOCK_SIZE)
    except ValueError as e:
        raise ValueError(f"Gagal mendekripsi (validasi padding gagal, kemungkinan password salah): {e}")
    
    jelaskan(f"Setelah blok *ciphertext* berhasil didekripsi, skema *padding* PKCS#7 divalidasi dan dihapus. Sebanyak **{pad_len} byte padding** dihilangkan.")
    
    output = plaintext_bytes.decode("utf-8")
    jelaskan("Plaintext berhasil direkonstruksi secara utuh dari representasi *byte array* kembali ke string UTF-8.")
    steps.append(make_code_step("Plaintext Hasil Rekonstruksi", preview(output, 1000)))
    
    return output, steps