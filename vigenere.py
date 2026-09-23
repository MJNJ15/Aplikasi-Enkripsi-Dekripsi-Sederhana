from utils import (
    MAX_DETAIL_ROWS,
    limit_rows,
    make_table_step,
    preview,
)


def vigenere_cipher(text: str, key: str, mode: str):
    """
    Vigenère Cipher klasik dengan langkah detail per karakter.

    Parameter:
    - text: plaintext atau ciphertext
    - key: kunci huruf A-Z
    - mode: "encrypt" atau "decrypt"

    Return:
    - hasil enkripsi/dekripsi
    - daftar langkah proses
    """
    key_clean = "".join(
        ch.upper() for ch in key if ch.isascii() and ch.isalpha()
    )

    if not key_clean:
        raise ValueError("Kunci Vigenère harus mengandung minimal satu huruf A-Z.")

    steps = []
    rows = []

    op_label = "enkripsi" if mode == "encrypt" else "dekripsi"

    steps.append(
        f"Operasi {op_label} Vigenère Cipher dengan kunci bersih: '{key_clean}'."
    )
    steps.append(
        "Nilai kunci: A=0, B=1, C=2, ..., Z=25."
    )

    if mode == "encrypt":
        steps.append(
            "Rumus enkripsi: huruf baru = (posisi huruf lama + nilai kunci) mod 26."
        )
    else:
        steps.append(
            "Rumus dekripsi: huruf baru = (posisi huruf lama - nilai kunci) mod 26."
        )

    steps.append(
        "Karakter non-huruf tidak diubah dan tidak mengonsumsi huruf kunci."
    )

    result = []
    examples = []
    key_stream_preview = []
    key_index = 0

    for idx, ch in enumerate(text, start=1):
        if ch.isascii() and ch.isalpha():
            key_char = key_clean[key_index % len(key_clean)]
            key_value = ord(key_char) - ord("A")

            base = ord("A") if ch.isupper() else ord("a")
            old_pos = ord(ch) - base

            if mode == "encrypt":
                shift = key_value
                new_pos = (old_pos + shift) % 26
                example_arrow = f"'{ch}' + '{key_char}'"
            else:
                shift = (-key_value) % 26
                new_pos = (old_pos - key_value) % 26
                example_arrow = f"'{ch}' - '{key_char}'"

            new_ch = chr(new_pos + base)
            result.append(new_ch)

            rows.append({
                "No": idx,
                "Karakter input": ch,
                "Kategori": "Huruf ASCII",
                "Urutan huruf yang diproses": key_index + 1,
                "Huruf kunci": key_char,
                "Index kunci": (key_index % len(key_clean)) + 1,
                "Nilai kunci (A=0)": key_value,
                "Shift efektif": shift,
                "Posisi awal": old_pos,
                "Posisi akhir": new_pos,
                "Hasil": new_ch,
                "Keterangan": "Diproses dengan kunci"
            })

            if len(key_stream_preview) < 20:
                key_stream_preview.append(key_char)

            if len(examples) < 8:
                examples.append(f"{example_arrow} -> '{new_ch}'")

            key_index += 1
        else:
            result.append(ch)

            if ch.isascii():
                kategori = "Non-huruf ASCII"
            else:
                kategori = "Non-ASCII"

            if ch.isspace():
                jenis = "Spasi"
            else:
                jenis = "Simbol/angka/lainnya"

            rows.append({
                "No": idx,
                "Karakter input": ch,
                "Kategori": kategori,
                "Jenis": jenis,
                "Urutan huruf yang diproses": "-",
                "Huruf kunci": "-",
                "Index kunci": "-",
                "Nilai kunci (A=0)": "-",
                "Shift efektif": "-",
                "Posisi awal": "-",
                "Posisi akhir": "-",
                "Hasil": ch,
                "Keterangan": "Tidak mengonsumsi kunci"
            })

    steps.append(
        "Contoh aliran kunci: "
        + ("".join(key_stream_preview) if key_stream_preview else "-")
    )

    if examples:
        steps.append("Contoh transformasi: " + ", ".join(examples))

    result_str = "".join(result)

    steps.append(
        f"Jumlah huruf yang diproses={key_index}, panjang input={len(text)} karakter."
    )

    if len(rows) > MAX_DETAIL_ROWS:
        steps.append(
            f"Catatan: tabel detail hanya menampilkan {MAX_DETAIL_ROWS} baris pertama "
            f"dari total {len(rows)} karakter agar aplikasi tidak lambat."
        )

    steps.append(
        make_table_step(
            "Detail perubahan karakter per karakter",
            limit_rows(rows)
        )
    )

    steps.append(f"Hasil akhir Vigenère: {preview(result_str, 160)}")

    return result_str, steps