from caesar import caesar_cipher
from vigenere import vigenere_cipher
from des import des_process
from rijndael import rijndael_process
from utils import preview, make_code_step

def _prefix_detail_steps(sub_steps, prefix):
    prefixed = []
    for item in sub_steps:
        if isinstance(item, dict):
            new_item = item.copy()
            title = new_item.get("title", "Detail")
            new_item["title"] = f"{prefix} - {title}"
            prefixed.append(new_item)
        else:
            prefixed.append(item)
    return prefixed

def super_encrypt(text, shift, vigenere_key, des_password, rijndael_password):
    steps = []
    steps.append("Super enkripsi dimulai: Caesar -> Vigenère -> DES (DEA) -> Rijndael (AES).")

    # Tahap 1: Caesar
    stage, sub_steps = caesar_cipher(text, shift, "encrypt")
    steps.append("Tahap 1/4: Caesar Cipher")
    steps.extend(_prefix_detail_steps(sub_steps, "Tahap 1 Caesar"))
    steps.append(make_code_step("Tahap 1 - Hasil", preview(stage, 1000)))

    # Tahap 2: Vigenère
    stage, sub_steps = vigenere_cipher(stage, vigenere_key, "encrypt")
    steps.append("Tahap 2/4: Vigenère Cipher")
    steps.extend(_prefix_detail_steps(sub_steps, "Tahap 2 Vigenère"))
    steps.append(make_code_step("Tahap 2 - Hasil", preview(stage, 1000)))

    # Tahap 3: DES
    stage, sub_steps = des_process(stage, des_password, "encrypt")
    steps.append("Tahap 3/4: DES (DEA)")
    steps.extend(_prefix_detail_steps(sub_steps, "Tahap 3 DES"))
    steps.append(make_code_step("Tahap 3 - Output Base64", preview(stage, 300)))

    # Tahap 4: Rijndael
    stage, sub_steps = rijndael_process(stage, rijndael_password, "encrypt")
    steps.append("Tahap 4/4: Rijndael (AES)")
    steps.extend(_prefix_detail_steps(sub_steps, "Tahap 4 Rijndael"))
    steps.append(make_code_step("Tahap 4 - Output Akhir Base64", preview(stage, 300)))

    return stage, steps

def super_decrypt(text, shift, vigenere_key, des_password, rijndael_password):
    steps = []
    steps.append("Super dekripsi dimulai: Rijndael (AES) -> DES (DEA) -> Vigenère -> Caesar.")

    # Tahap 1: Rijndael
    stage, sub_steps = rijndael_process(text, rijndael_password, "decrypt")
    steps.append("Tahap 1/4: Rijndael (AES)")
    steps.extend(_prefix_detail_steps(sub_steps, "Tahap 1 Rijndael"))
    steps.append(make_code_step("Tahap 1 - Hasil Dekripsi", preview(stage, 300)))

    # Tahap 2: DES
    stage, sub_steps = des_process(stage, des_password, "decrypt")
    steps.append("Tahap 2/4: DES (DEA)")
    steps.extend(_prefix_detail_steps(sub_steps, "Tahap 2 DES"))
    steps.append(make_code_step("Tahap 2 - Hasil Dekripsi", preview(stage, 1000)))

    # Tahap 3: Vigenère
    stage, sub_steps = vigenere_cipher(stage, vigenere_key, "decrypt")
    steps.append("Tahap 3/4: Vigenère Cipher")
    steps.extend(_prefix_detail_steps(sub_steps, "Tahap 3 Vigenère"))
    steps.append(make_code_step("Tahap 3 - Hasil Dekripsi", preview(stage, 1000)))

    # Tahap 4: Caesar
    stage, sub_steps = caesar_cipher(stage, shift, "decrypt")
    steps.append("Tahap 4/4: Caesar Cipher")
    steps.extend(_prefix_detail_steps(sub_steps, "Tahap 4 Caesar"))
    steps.append(make_code_step("Tahap 4 - Plaintext Akhir", preview(stage, 1000)))

    return stage, steps

def super_process(text, shift, vigenere_key, des_password, rijndael_password, mode):
    if mode == "encrypt":
        return super_encrypt(text, shift, vigenere_key, des_password, rijndael_password)
    if mode == "decrypt":
        return super_decrypt(text, shift, vigenere_key, des_password, rijndael_password)
    raise ValueError("Mode tidak dikenal.")