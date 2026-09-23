import base64
import os
from Crypto.Cipher import AES

from utils import (
    derive_key, pkcs7_pad, pkcs7_unpad, bytes_preview, 
    split_into_blocks, make_code_step, make_table_step, preview
)

ALGORITHM_NAME = "Rijndael (AES-256)"
BLOCK_SIZE = 16  # 128 bit (Standar AES)
KEY_SIZE = 32    # 256 bit


def rijndael_process(text: str, password: str, mode: str):
    if not password:
        raise ValueError("Password tidak boleh kosong.")

    steps = []

    if mode == "encrypt":
        steps.append(f"Operasi enkripsi {ALGORITHM_NAME} mode CBC.")
        
        plaintext_bytes = text.encode("utf-8")
        steps.append(f"1. Plaintext diubah ke bytes UTF-8 ({len(plaintext_bytes)} byte).")
        steps.append(make_code_step("Plaintext bytes (hex)", bytes_preview(plaintext_bytes, 128)))

        # Padding
        padded_bytes, pad_len = pkcs7_pad(plaintext_bytes, BLOCK_SIZE)
        steps.append(f"2. PKCS7 Padding ditambahkan. Block size = {BLOCK_SIZE} byte.")
        steps.append(f"   Jumlah byte padding yang ditambahkan: {pad_len} (nilai hex: {hex(pad_len)}).")
        steps.append(make_code_step("Data setelah padding (hex)", bytes_preview(padded_bytes, 128)))

        # Blok
        blocks = split_into_blocks(padded_bytes, BLOCK_SIZE)
        block_rows = [{"Blok ke": i+1, "Ukuran": f"{len(b)} byte", "Hex": b.hex()} for i, b in enumerate(blocks)]
        steps.append(make_table_step("Pembagian blok plaintext (setelah padding)", block_rows))

        # Key & IV
        salt = os.urandom(16)
        iv = os.urandom(BLOCK_SIZE)
        key = derive_key(password, salt, KEY_SIZE)
        
        steps.append(f"3. Salt acak 16 byte dibuat: {salt.hex()}.")
        steps.append(f"4. IV (Initialization Vector) acak {BLOCK_SIZE} byte dibuat: {iv.hex()}.")
        steps.append(f"5. Kunci {KEY_SIZE} byte (256-bit) diturunkan dari password (PBKDF2).")
        steps.append(make_code_step("Kunci Rijndael/AES (hex)", bytes_preview(key, 32)))

        # Encrypt
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(padded_bytes)
        
        steps.append("6. Enkripsi CBC selesai.")
        steps.append(make_code_step("Ciphertext bytes (hex)", bytes_preview(ciphertext, 128)))

        # Payload
        payload = salt + iv + ciphertext
        output = base64.b64encode(payload).decode("ascii")
        
        steps.append(f"7. Payload gabungan: Salt(16) + IV({BLOCK_SIZE}) + Ciphertext({len(ciphertext)}).")
        steps.append("8. Payload di-encode ke Base64.")
        steps.append(make_code_step("Output Base64 akhir", preview(output, 300)))

        return output, steps

    # ===================== DEKRIPSI =====================
    steps.append(f"Operasi dekripsi {ALGORITHM_NAME} mode CBC.")
    
    cleaned = text.strip()
    if not cleaned:
        raise ValueError("Ciphertext kosong.")

    try:
        payload = base64.b64decode(cleaned)
    except Exception:
        raise ValueError("Input bukan Base64 valid.")

    steps.append("1. Input Base64 di-decode menjadi bytes.")
    
    min_len = 16 + BLOCK_SIZE + BLOCK_SIZE
    if len(payload) < min_len:
        raise ValueError("Payload terlalu pendek.")

    salt = payload[:16]
    iv = payload[16:16+BLOCK_SIZE]
    ciphertext = payload[16+BLOCK_SIZE:]

    steps.append(f"2. Salt (16 byte): {salt.hex()}")
    steps.append(f"3. IV ({BLOCK_SIZE} byte): {iv.hex()}")
    steps.append(f"4. Ciphertext ({len(ciphertext)} byte) diekstrak.")
    steps.append(make_code_step("Ciphertext bytes (hex)", bytes_preview(ciphertext, 128)))

    key = derive_key(password, salt, KEY_SIZE)
    steps.append("5. Kunci diturunkan ulang dari password dan salt.")

    cipher = AES.new(key, AES.MODE_CBC, iv)
    try:
        padded_plaintext = cipher.decrypt(ciphertext)
    except Exception as e:
        raise ValueError(f"Dekripsi gagal: {e}")

    steps.append("6. Dekripsi CBC selesai.")
    steps.append(make_code_step("Data terdekripsi (masih ada padding)", bytes_preview(padded_plaintext, 128)))

    try:
        plaintext_bytes, pad_len = pkcs7_unpad(padded_plaintext, BLOCK_SIZE)
    except ValueError as e:
        raise ValueError(f"Gagal membuka padding (password mungkin salah): {e}")

    steps.append(f"7. PKCS7 Unpadding: {pad_len} byte terakhir dibuang.")
    
    output = plaintext_bytes.decode("utf-8")
    steps.append("8. Bytes diubah kembali ke string UTF-8.")
    steps.append(make_code_step("Plaintext akhir", preview(output, 1000)))

    return output, steps