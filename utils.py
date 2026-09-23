import hashlib

PBKDF2_ITERATIONS = 100_000
MAX_DETAIL_ROWS = 1000
MAX_HEX_BYTES = 64


def preview(value, max_len=120):
    s = str(value)
    if len(s) <= max_len:
        return s
    return f"{s[:max_len]}... (total {len(s)} karakter)"


def derive_key(password: str, salt: bytes, key_length: int) -> bytes:
    """
    Menurunkan kunci dari password menggunakan PBKDF2-HMAC-SHA256 bawaan Python.
    key_length: 8 untuk DES, 32 untuk Rijndael (AES-256).
    """
    return hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        PBKDF2_ITERATIONS,
        dklen=key_length
    )


def pkcs7_pad(data: bytes, block_size: int):
    """
    Melakukan PKCS7 padding secara manual agar bisa ditampilkan detailnya.
    """
    pad_len = block_size - (len(data) % block_size)
    padded_data = data + bytes([pad_len] * pad_len)
    return padded_data, pad_len


def pkcs7_unpad(data: bytes, block_size: int):
    """
    Membuka PKCS7 padding.
    """
    if not data:
        raise ValueError("Data kosong.")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Padding tidak valid.")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Padding tidak valid.")
    return data[:-pad_len], pad_len


def bytes_preview(data: bytes, max_bytes=MAX_HEX_BYTES):
    if not data:
        return "(kosong)"
    if len(data) <= max_bytes:
        return data.hex()
    return data[:max_bytes].hex() + f"... (total {len(data)} byte)"


def split_into_blocks(data: bytes, block_size: int):
    """Memecah bytes menjadi blok-blok sesuai block_size."""
    return [data[i:i + block_size] for i in range(0, len(data), block_size)]


def limit_rows(rows, limit=MAX_DETAIL_ROWS):
    return rows[:limit]


def make_table_step(title, data):
    return {"type": "table", "title": title, "data": data}


def make_code_step(title, content, language="text"):
    return {"type": "code", "title": title, "content": content, "language": language}