import streamlit as st
from caesar import caesar_cipher
from vigenere import vigenere_cipher
from des import des_process
from rijndael import rijndael_process
from super_cipher import super_process

def render_step_item(index, step):
    """
    Menampilkan satu item langkah.
    Step bisa berupa teks biasa, tabel, atau kode.
    Heading (###) tidak diberi nomor.
    """
    if isinstance(step, dict):
        step_type = step.get("type", "text")
        title = step.get("title", "Detail")
        
        if step_type == "table":
            with st.expander(f"{index}. {title}", expanded=False):
                data = step.get("data", [])
                if data:
                    st.dataframe(
                        data,
                        use_container_width=True,
                        height=350
                    )
                else:
                    st.write("Tidak ada data.")
        elif step_type == "code":
            with st.expander(f"{index}. {title}", expanded=False):
                st.code(
                    step.get("content", ""),
                    language=step.get("language", "text")
                )
        else:
            content = step.get('content', '')
            # Cek apakah heading
            if content.startswith('###'):
                st.markdown(content)
            else:
                st.markdown(f"**{index}.** {content}")
    else:
        # String biasa
        if step.startswith('###'):
            st.markdown(step)
        else:
            st.markdown(f"**{index}.** {step}")

def show_result(steps, before_text, result_text, before_label, result_label):
    """
    Menampilkan langkah proses, input sebelum operasi, dan hasil akhir.
    """
    st.success("Proses selesai.")
    with st.expander("Langkah-langkah proses", expanded=True):
        if not steps:
            st.text("Tidak ada langkah.")
        else:
            # Hitung nomor hanya untuk langkah non-heading
            nomor = 0
            for step in steps:
                # Cek apakah step adalah heading
                if isinstance(step, str):
                    is_heading = step.startswith('###')
                elif isinstance(step, dict):
                    is_heading = step.get('content', '').startswith('###')
                else:
                    is_heading = False
                
                if not is_heading:
                    nomor += 1
                    render_step_item(nomor, step)
                else:
                    render_step_item(None, step)
    
    col1, col2 = st.columns(2)
    with col1:
        st.caption(before_label)
        st.code(before_text if before_text else "(kosong)", language="text")
    with col2:
        st.caption(result_label)
        st.code(result_text if result_text else "(kosong)", language="text")

def render_caesar_tab():
    st.subheader("Caesar Cipher (Klasik)")
    st.caption("Klasik: pergeseran huruf alfabet.")
    
    operation = st.radio(
        "Operasi",
        ["Enkripsi", "Dekripsi"],
        horizontal=True,
        key="caesar_operation"
    )
    
    input_label = "Plaintext" if operation == "Enkripsi" else "Ciphertext"
    text = st.text_area(
        input_label,
        key="caesar_text",
        height=120,
        placeholder="Contoh: Selamat Pagi",
    )
    
    shift = st.number_input(
        "Kunci shift (0-25)",
        min_value=0,
        max_value=25,
        value=3,
        step=1,
        key="caesar_shift",
    )
    
    if st.button("Proses Caesar", key="caesar_button"):
        if not text:
            st.error("Teks input masih kosong.")
        else:
            try:
                mode = "encrypt" if operation == "Enkripsi" else "decrypt"
                result, steps = caesar_cipher(text, int(shift), mode)
                show_result(
                    steps,
                    text,
                    result,
                    f"{input_label} sebelum operasi",
                    "Hasil akhir Caesar",
                )
            except Exception as e:
                st.error(str(e))

def render_vigenere_tab():
    st.subheader("Vigenère Cipher (Klasik)")
    st.caption("Klasik: substitusi alfabet dengan kunci berulang.")
    
    operation = st.radio(
        "Operasi",
        ["Enkripsi", "Dekripsi"],
        horizontal=True,
        key="vigenere_operation"
    )
    
    input_label = "Plaintext" if operation == "Enkripsi" else "Ciphertext"
    text = st.text_area(
        input_label,
        key="vigenere_text",
        height=120,
        placeholder="Contoh: Selamat Pagi",
    )
    
    key = st.text_input(
        "Kunci Vigenère (huruf A-Z)",
        key="vigenere_key",
        placeholder="Contoh: KUNCI",
    )
    
    if st.button("Proses Vigenère", key="vigenere_button"):
        if not text:
            st.error("Teks input masih kosong.")
        elif not key.strip():
            st.error("Kunci Vigenère masih kosong.")
        else:
            try:
                mode = "encrypt" if operation == "Enkripsi" else "decrypt"
                result, steps = vigenere_cipher(text, key, mode)
                show_result(
                    steps,
                    text,
                    result,
                    f"{input_label} sebelum operasi",
                    "Hasil akhir Vigenère",
                )
            except Exception as e:
                st.error(str(e))

def render_modern_tab(title, caption, key_prefix, process_func, button_label):
    st.subheader(title)
    st.caption(caption)
    
    operation = st.radio(
        "Operasi", ["Enkripsi", "Dekripsi"], horizontal=True, key=f"{key_prefix}_operation"
    )
    
    input_label = "Plaintext" if operation == "Enkripsi" else "Ciphertext (Base64)"
    text = st.text_area(input_label, key=f"{key_prefix}_text", height=120)
    password = st.text_input("Password", type="password", key=f"{key_prefix}_password")
    
    if st.button(button_label, key=f"{key_prefix}_button"):
        if not text:
            st.error("Teks input masih kosong.")
        elif not password:
            st.error("Password masih kosong.")
        else:
            try:
                mode = "encrypt" if operation == "Enkripsi" else "decrypt"
                result, steps = process_func(text, password, mode)
                show_result(steps, text, result, f"{input_label} sebelum operasi", f"Hasil akhir {title}")
            except Exception as e:
                st.error(str(e))

def render_super_tab():
    st.subheader("Super Enkripsi Gabungan")
    st.info("Urutan Enkripsi: Caesar -> Vigenère -> DES (DEA) -> Rijndael (AES). Urutan dekripsi dibalik otomatis.")
    
    operation = st.radio("Operasi", ["Enkripsi", "Dekripsi"], horizontal=True, key="super_operation")
    
    input_label = "Plaintext" if operation == "Enkripsi" else "Ciphertext akhir (Base64)"
    text = st.text_area(input_label, key="super_text", height=120)
    
    col1, col2 = st.columns(2)
    with col1:
        shift = st.number_input("Kunci Caesar (0-25)", 0, 25, 3, key="super_shift")
        vigenere_key = st.text_input("Kunci Vigenère", key="super_vigenere_key")
    with col2:
        des_password = st.text_input("Password DES (DEA)", type="password", key="super_des_password")
        rijndael_password = st.text_input("Password Rijndael (AES)", type="password", key="super_rijndael_password")
    
    if st.button("Proses Super", key="super_button"):
        errors = []
        if not text: errors.append("teks kosong")
        if not vigenere_key.strip(): errors.append("kunci Vigenère kosong")
        if not des_password: errors.append("password DES kosong")
        if not rijndael_password: errors.append("password Rijndael kosong")
        
        if errors:
            st.error("Input belum lengkap: " + ", ".join(errors) + ".")
        else:
            try:
                mode = "encrypt" if operation == "Enkripsi" else "decrypt"
                result, steps = super_process(text, int(shift), vigenere_key, des_password, rijndael_password, mode)
                show_result(steps, text, result, f"{input_label} sebelum operasi", "Hasil akhir Super Enkripsi")
            except Exception as e:
                st.error(str(e))

def main():
    st.set_page_config(page_title="Demo Kriptografi", page_icon="", layout="wide")
    st.title("Aplikasi Enkripsi dan Dekripsi")
    st.write("Implementasi 2 algoritma klasik, 2 algoritma modern (Blok Cipher), dan 1 super enkripsi.")
    
    tab_caesar, tab_vigenere, tab_des, tab_rijndael, tab_super = st.tabs(
        ["Caesar Cipher", "Vigenère Cipher", "DES (DEA)", "Rijndael (AES)", "Super Enkripsi"]
    )
    
    with tab_caesar:
        render_caesar_tab()
    with tab_vigenere:
        render_vigenere_tab()
    with tab_des:
        render_modern_tab(
            title="DES / DEA (Modern)",
            caption="Data Encryption Standard (Blok Cipher 64-bit).",
            key_prefix="des",
            process_func=des_process,
            button_label="Proses DES"
        )
    with tab_rijndael:
        render_modern_tab(
            title="Rijndael / AES-256 (Modern)",
            caption="Algoritma Rijndael (Blok Cipher 128-bit, Kunci 256-bit).",
            key_prefix="rijndael",
            process_func=rijndael_process,
            button_label="Proses Rijndael"
        )
    with tab_super:
        render_super_tab()

if __name__ == "__main__":
    main()