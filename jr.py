import tkinter as tk
from tkinter import ttk
from tkinter.messagebox import showinfo
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import base64
import os
import pyperclip

# إعداد مفتاح RSA
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()


# خوارزمية قيصر
def caesar_cipher(text, shift, decrypt=False):
    if decrypt:
        shift = -shift
    result = []
    for char in text:
        if char.isalpha():
            shift_base = 65 if char.isupper() else 97
            result.append(chr((ord(char) - shift_base + shift) % 26 + shift_base))
        else:
            result.append(char)
    return ''.join(result)


# خوارزمية أعمدة السياج (Rail Fence)
def rail_fence_cipher(text, key, decrypt=False):
    if decrypt:
        return rail_fence_decrypt(text, key)
    rail = [['\n' for i in range(len(text))] for j in range(key)]
    dir_down = False
    row, col = 0, 0

    for i in range(len(text)):
        if (row == 0) or (row == key - 1):
            dir_down = not dir_down
        rail[row][col] = text[i]
        col += 1
        row += 1 if dir_down else -1

    result = []
    for i in range(key):
        for j in range(len(text)):
            if rail[i][j] != '\n':
                result.append(rail[i][j])
    return ''.join(result)


def rail_fence_decrypt(text, key):
    rail = [['\n' for i in range(len(text))] for j in range(key)]
    dir_down = None
    row, col = 0, 0

    for i in range(len(text)):
        if row == 0:
            dir_down = True
        if row == key - 1:
            dir_down = False
        rail[row][col] = '*'
        col += 1
        row += 1 if dir_down else -1

    index = 0
    for i in range(key):
        for j in range(len(text)):
            if rail[i][j] == '*' and index < len(text):
                rail[i][j] = text[index]
                index += 1

    result = []
    row, col = 0, 0
    for i in range(len(text)):
        if row == 0:
            dir_down = True
        if row == key - 1:
            dir_down = False
        if rail[row][col] != '*':
            result.append(rail[row][col])
            col += 1
        row += 1 if dir_down else -1
    return ''.join(result)


# خوارزمية AES
def aes_encrypt(text, key):
    key = key.ljust(32)[:32].encode()  # تأكد من أن المفتاح طوله 32 بايت
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_text = encryptor.update(text.encode()) + encryptor.finalize()
    return base64.urlsafe_b64encode(iv + encrypted_text).decode()


def aes_decrypt(encrypted_text, key):
    key = key.ljust(32)[:32].encode()
    encrypted_text = base64.urlsafe_b64decode(encrypted_text)
    iv = encrypted_text[:16]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_text = decryptor.update(encrypted_text[16:]) + decryptor.finalize()
    return decrypted_text.decode()


# خوارزمية RSA
def rsa_encrypt(text):
    ciphertext = public_key.encrypt(
        text.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.urlsafe_b64encode(ciphertext).decode()


def rsa_decrypt(encrypted_text):
    encrypted_text = base64.urlsafe_b64decode(encrypted_text)
    plaintext = private_key.decrypt(
        encrypted_text,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode()


# خوارزمية Base64
def base64_encode(text):
    return base64.b64encode(text.encode()).decode()


def base64_decode(encoded_text):
    return base64.b64decode(encoded_text).decode()


# دالة تشفير النص بناءً على الخوارزمية المختارة
def encrypt_message():
    algorithm = selected_algorithm.get()
    text = message_input.get("1.0", tk.END).strip()
    password = password_input.get().strip()

    if not text:
        showinfo("!خطأ", "الرجاء إدخال الرسالة.")
        return

    if algorithm == "Caesar":

        if not password:
            showinfo("!خطأ", "الرجاء إدخال كلمة المرور.")
            return
        shift = 3
        encrypted_message = caesar_cipher(text, shift)
    elif algorithm == "Rail Fence":
        if not password:
            showinfo("!خطأ", "الرجاء ادخال كلمة المرور.")
            return
        key = 3
        encrypted_message = rail_fence_cipher(text, key)
    elif algorithm == "AES":
        if not password:
            showinfo("!خطأ", "الرجاء ادخال كلمة المرور.")
            return
        encrypted_message = aes_encrypt(text, password)
    elif algorithm == "RSA":
        if not password:
            showinfo("!خطأ", "الرجاء ادخال كلمة المرور.")
            return
        encrypted_message = rsa_encrypt(text)
    elif algorithm == "Base64":
        if not password:
            showinfo("!خطأ", "الرجاء ادخال كلمة المرور.")
            return
        encrypted_message = base64_encode(text)

    result_output.delete("1.0", tk.END)
    result_output.insert(tk.END, encrypted_message)


# دالة فك تشفير النص بناءً على الخوارزمية المختارة
def decrypt_message():
    algorithm = selected_algorithm.get()
    text = message_input.get("1.0", tk.END).strip()
    password = password_input.get().strip()

    if not text:
        showinfo("!خطأ", "الرجاء إدخال رسالة للتشفير")
        return

    try:
        if algorithm == "Caesar":
            shift = 3
            decrypted_message = caesar_cipher(text, shift, decrypt=True)
        elif algorithm == "Rail Fence":
            key = 3
            decrypted_message = rail_fence_cipher(text, key, decrypt=True)
        elif algorithm == "AES":
            if not password:
                showinfo("!خطأ", "الرجاء إدخال كلمة المرور لفك التشفير .")
                return
            decrypted_message = aes_decrypt(text, password)
        elif algorithm == "RSA":
            decrypted_message = rsa_decrypt(text)
        elif algorithm == "Base64":
            decrypted_message = base64_decode(text)
    except Exception as e:
        showinfo("!خطأ", f"فشل فك تشفير الرسالة: {e}")
        return

    result_output.delete("1.0", tk.END)
    result_output.insert(tk.END, decrypted_message)


# نسخ النص إلى الحافظة
def copy_to_clipboard():
    text = result_output.get("1.0", tk.END).strip()
    if text:
        pyperclip.copy(text)
        showinfo("Copied", "تم نسخ النص إلى الحافظة!")


# إعداد الواجهة الرسومية
root = tk.Tk()
root.title(" تطبيق تشفير الرسائل")
root.geometry("1000x770")
root.configure(bg="#000000")
root.iconbitmap('C:\\Users\\HP-PC\\Desktop\\صور\\file-security.ico')

ttk.Label(root, background="#000000",foreground='yellow', text=" تطبيق تشفير الرسائل ", font=("Helvetica", 30)).pack(pady=30)
# إدخال النص
ttk.Label(root, background="#000000",foreground='#ffffff', text=": ادخل النص ", font=("Helvetica", 16)).pack(pady=20)
message_input = tk.Text(root, height=5, bg="#000000", font=("Helvetica", 12),foreground="white", bd=2, relief="groove", highlightbackground="#ffffff", highlightthickness=2)
message_input.pack(pady=5, padx=20)

# إدخال كلمة المرور
ttk.Label(root, background="#000000", text=": ادخل كلمة المرور",foreground='#ffffff', font=("Helvetica", 14)).pack(pady=10)
password_input = tk.Entry(root, bg="#000000", font=("Arial", 14), fg="#ffffff", bd=4, show='*')
password_input.pack(pady=5, padx=20)

# إعداد الخيارات للخوارزميات
selected_algorithm = tk.StringVar(value="Caesar")

frame = tk.LabelFrame(root, text="اختر نظام للتشفير", width=950, height=50, bg="#000000",fg="#ffffff", font=(10))
frame.pack(pady=10, padx=20, side="top")

caesar_rb = tk.Radiobutton(frame, text="Caesar Cipher", variable=selected_algorithm, value="Caesar", bg="#000000",fg="yellow", font=(6))
caesar_rb.pack( side=tk.RIGHT, padx=10)

rail_fence_rb = tk.Radiobutton(frame, text="Rail Fence Cipher", variable=selected_algorithm, value="Rail Fence", bg="#000000",fg="yellow", font=(6))
rail_fence_rb.pack( side=tk.RIGHT, padx=10)

aes_rb = tk.Radiobutton(frame, text="AES", variable=selected_algorithm, value="AES", bg="#000000",fg="yellow", font=(6))
aes_rb.pack(side=tk.RIGHT,  padx=10)

rsa_rb = tk.Radiobutton(frame, text="RSA", variable=selected_algorithm, value="RSA", bg="#000000",fg="yellow", font=(6))
rsa_rb.pack(side=tk.RIGHT, padx=10)

base64_rb = tk.Radiobutton(frame, text="Base64", variable=selected_algorithm, value="Base64", bg="#000000",fg="yellow", font=(6))
base64_rb.pack(side=tk.LEFT, padx=10)

# زر التشفير
encrypt_button = tk.Button(root, text="تشفير", fg="black", width=10, command=encrypt_message)
encrypt_button.pack(pady=10)

# زر فك التشفير
decrypt_button = tk.Button(root, text="فك التشفير", fg="black", width=10, command=decrypt_message)
decrypt_button.pack(pady=10)

# حقل عرض النص المشفر أو المفكوك
ttk.Label(root, background="#000000", foreground='#ffffff', text=" : النص المشفر ", font=("Helvetica", 16)).pack(pady=10)
result_output = tk.Text(root, height=5, bg="#000000", font=("Helvetica", 12),foreground="white", bd=2, relief="groove", highlightbackground="#ffffff", highlightthickness=2)
result_output.pack(pady=5, padx=20)

# زر نسخ النص إلى الحافظة
copy_button = tk.Button(root, text="نسخ النص المشفر", fg="black", width=20, command=copy_to_clipboard)
copy_button.pack(pady=10)

root.mainloop()

