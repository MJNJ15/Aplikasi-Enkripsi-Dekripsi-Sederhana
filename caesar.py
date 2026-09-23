from utils import (
    MAX_DETAIL_ROWS,
    limit_rows,
    make_table_step,
    preview,
)


def caesar_cipher(text: str, shift: int, mode: str):
    """
    Caesar Cipher klasik dengan langkah detail per karakter.

    Parameter:
    - text: plaintext atau ciphertext
    - shift: kunci pergeseran 0-25
    - mode: "encrypt" atau "decrypt"

    Return:
    - hasil enkripsi/dekripsi
    - daftar langkah proses
    """
    steps = []
    rows = []

    shift = int(shift) % 26

    if mode == "encrypt":
        effective_shift = shift
        op_label = "enkripsi"
    else:
        effective_shift = (-shift) % 26
        op_label = "dekripsi"

    steps.append(
        f"Operasi {op_label} Caesar Cipher: shift asli={shift}, shift efektif={effective_shift}."
    )
    steps.append(
        "Rumus umum: huruf baru = (posisi huruf lama + shift efektif) mod 26."
    )
    steps.append(
        "Aturan: huruf ASCII A-Z/a-z digeser; karakter lain tidak diubah."
    )

    result = []
    examples = []

    for idx, ch in enumerate(text, start=1):
        if ch.isascii() and ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            base_label = "Huruf kapital (A-Z)" if ch.isupper() else "Huruf kecil (a-z)"

            old_pos = ord(ch) - base
            new_pos = (old_pos + effective_shift) % 26
            new_ch = chr(new_pos + base)

            result.append(new_ch)

            rows.append({
                "No": idx,
                "Karakter input": ch,
                "Kategori": "Huruf ASCII",
                "Jenis": base_label,
                "Posisi awal": old_pos,
                "Shift efektif": effective_shift,
                "Posisi akhir": new_pos,
                "Hasil": new_ch,
                "Keterangan": "Digeser"
            })

            if len(examples) < 8:
                examples.append(f"'{ch}' -> '{new_ch}'")
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
                "Posisi awal": "-",
                "Shift efektif": "-",
                "Posisi akhir": "-",
                "Hasil": ch,
                "Keterangan": "Tidak diubah"
            })

            if len(examples) < 8 and not ch.isspace():
                examples.append(f"'{ch}' tetap")

    if examples:
        steps.append("Contoh transformasi: " + ", ".join(examples))

    result_str = "".join(result)

    steps.append(
        f"Panjang input={len(text)} karakter, panjang output={len(result_str)} karakter."
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

    steps.append(f"Hasil akhir Caesar: {preview(result_str, 160)}")

    return result_str, steps