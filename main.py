# SecureFile Locker
# AES-256 GCM Encryption-Decryption Tool
# GUI Application using Tkinter

from tkinter import *
from tkinter import filedialog, messagebox
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
import os

# ========================================
# CREATE SHA256 HASH OF FILE
# ========================================

def generate_hash(path):

    sha = SHA256.new()

    with open(path, "rb") as f:

        while True:

            chunk = f.read(4096)

            if not chunk:
                break

            sha.update(chunk)

    return sha.hexdigest()


# ===================================
# SELECT FILE FOR ENCRYPTION
# ===================================

def browse_encrypt():

    selected = filedialog.askopenfilename()

    enc_path_var.set(selected)


# =====================================
# SELECT FILE FOR DECRYPTION
# =====================================

def browse_decrypt():

    selected = filedialog.askopenfilename()
    dec_path_var.set(selected)


# ================================
# ENCRYPTION PROCESS
# ================================

def start_encryption():
    source_file = enc_path_var.get()
    secret_pass = enc_pass_var.get()

    if source_file == "" or secret_pass == "":
        messagebox.showerror(
            "Missing Data",
            "Please choose a file and enter password"
        )
        return

    try:
        before_hash = generate_hash(source_file)
        random_salt = get_random_bytes(16)
        secret_key = PBKDF2(
            secret_pass,
            random_salt,
            dkLen=32
        )
        saved_pass_hash = SHA256.new(
            secret_pass.encode()
        ).digest()

        with open(source_file, "rb") as f:
            original_data = f.read()
        aes_cipher = AES.new(
            secret_key,
            AES.MODE_GCM
        )
        encrypted_data, auth_tag = aes_cipher.encrypt_and_digest(
            original_data
        )

        final_file = source_file + ".enc"
        with open(final_file, "wb") as f:

            f.write(saved_pass_hash)
            f.write(random_salt)
            f.write(aes_cipher.nonce)
            f.write(auth_tag)
            f.write(encrypted_data)

        after_hash = generate_hash(final_file)
        messagebox.showinfo(
            "Encryption Completed",
            f"Encrypted File:\n{final_file}\n\n"
            f"Original File Hash:\n{before_hash}\n\n"
            f"Encrypted File Hash:\n{after_hash}"
        )

    except Exception as err:
        messagebox.showerror(
            "Encryption Error",
            str(err)
        )


# ======================================
# DECRYPTION PROCESS
# ======================================

def start_decryption():

    encrypted_path = dec_path_var.get()
    secret_pass = dec_pass_var.get()

    if encrypted_path == "" or secret_pass == "":
        messagebox.showerror(
            "Missing Data",
            "Please choose encrypted file and enter password"
        )
        return

    try:
        with open(encrypted_path, "rb") as f:
            stored_hash = f.read(32)
            salt_value = f.read(16)
            nonce_value = f.read(16)
            tag_value = f.read(16)
            encrypted_content = f.read()
        entered_hash = SHA256.new(
            secret_pass.encode()
        ).digest()

        if entered_hash != stored_hash:
            messagebox.showerror(
                "Access Denied",
                "Incorrect Password"
            )
            return
        generated_key = PBKDF2(
            secret_pass,
            salt_value,
            dkLen=32
        )

        aes_cipher = AES.new(
            generated_key,
            AES.MODE_GCM,
            nonce=nonce_value
        )

        decrypted_content = aes_cipher.decrypt_and_verify(
            encrypted_content,
            tag_value
        )

        restored_file = encrypted_path.replace(".enc", "")
        with open(restored_file, "wb") as f:
            f.write(decrypted_content)
        final_hash = generate_hash(restored_file)
        messagebox.showinfo(
            "Decryption Successful",
            f"Recovered File:\n{restored_file}\n\n"
            f"Recovered File Hash:\n{final_hash}"
        )
    except:
        messagebox.showerror(
            "Decryption Failed",
            "Wrong Password or File Modified"
        )


# ================================
# MAIN APPLICATION WINDOW
# ================================

app = Tk()

app.title("SecureFile Locker")
app.geometry("1000x500")
app.config(bg="#f0f0f0")
app.resizable(False, False)

enc_path_var = StringVar()
dec_path_var = StringVar()
enc_pass_var = StringVar()
dec_pass_var = StringVar()

# =============================
# ENCRYPT SECTION
# =============================

left_box = Frame(
    app,
    bg="white",
    bd=2,
    relief=RIDGE
)

left_box.place(
    x=40,
    y=60,
    width=420,
    height=350
)

Label(
    left_box,
    text="FILE ENCRYPTION",
    font=("Arial", 24, "bold"),
    fg="#00acc1",
    bg="white"
).place(x=40, y=20)

Button(
    left_box,
    text="Select File",
    font=("Arial", 14, "bold"),
    bg="#00acc1",
    fg="white",
    command=browse_encrypt
).place(x=130, y=100, width=160, height=50)

Entry(
    left_box,
    textvariable=enc_pass_var,
    font=("Arial", 14),
    show="*"
).place(x=40, y=220, width=340, height=40)

Button(
    left_box,
    text="Encrypt Now",
    font=("Arial", 16, "bold"),
    bg="#00acc1",
    fg="white",
    command=start_encryption
).place(x=40, y=280, width=340, height=50)


# ==========================
# DECRYPT SECTION
# ==========================

right_box = Frame(
    app,
    bg="white",
    bd=2,
    relief=RIDGE
)

right_box.place(
    x=540,
    y=60,
    width=420,
    height=350
)

Label(
    right_box,
    text="FILE DECRYPTION",
    font=("Arial", 24, "bold"),
    fg="#7cb342",
    bg="white"
).place(x=40, y=20)

Button(
    right_box,
    text="Select File",
    font=("Arial", 14, "bold"),
    bg="#7cb342",
    fg="white",
    command=browse_decrypt
).place(x=130, y=100, width=160, height=50)

Entry(
    right_box,
    textvariable=dec_pass_var,
    font=("Arial", 14),
    show="*"
).place(x=40, y=220, width=340, height=40)

Button(
    right_box,
    text="Decrypt Now",
    font=("Arial", 16, "bold"),
    bg="#7cb342",
    fg="white",
    command=start_decryption
).place(x=40, y=280, width=340, height=50)


# =================================
# START APPLICATION
# =================================

app.mainloop() 

#====== END ;D =======
