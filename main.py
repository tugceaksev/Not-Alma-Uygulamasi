import tkinter as tk
from tkinter import messagebox
from PIL import Image, ImageTk
from cryptography.fernet import Fernet
import os

yazı = "white"
arkaplan = "#f4a460"
buton = "#f5f5dc"


# Şifreleme anahtarını oluştur veya yükle
def generate_key():
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)


def load_key():
    return open("secret.key", "rb").read()


def encrypt_message(message):
    key = load_key()
    fernet = Fernet(key)
    encrypted = fernet.encrypt(message.encode())
    return encrypted


def decrypt_message(encrypted_message):
    key = load_key()
    fernet = Fernet(key)
    decrypted = fernet.decrypt(encrypted_message).decode()
    return decrypted


def on_text_click(event):
    if text_box.get("1.0", tk.END).strip() == "Metin Girin":
        text_box.delete("1.0", tk.END)  # Placeholder'ı temizle
        text_box.config(fg=yazı)  # Metin rengini geri döndür


def on_text_focus_out(event):
    if not text_box.get("1.0", tk.END).strip():
        text_box.insert("1.0", "Metin Girin")  # Placeholder'ı geri yükle
        text_box.config(fg='grey')  # Placeholder rengi


def save_data():
    text_content = text_box.get("1.0", tk.END).strip()
    password = password_entry.get().strip()

    if text_content == "Metin Girin":
        messagebox.showwarning("Uyarı", "Metin kutusu boş. Lütfen metin girin.")
        return

    if not password:
        messagebox.showwarning("Uyarı", "Şifre girilmedi.")
        return

    try:
        encrypted_text = encrypt_message(text_content)
        encrypted_password = encrypt_message(password)

        with open("data.txt", "ab") as file:
            file.write(encrypted_text + b"\n")
            file.write(encrypted_password + b"\n\n")

        messagebox.showinfo("Başarılı", "Veriler başarıyla kaydedildi.")
    except Exception as e:
        messagebox.showerror("Hata", f"Veri kaydedilirken bir hata oluştu: {e}")


def load_data():
    def check_password():
        entered_password = password_check_entry.get().strip()

        if not entered_password:
            messagebox.showwarning("Uyarı", "Lütfen bir şifre girin.")
            return

        try:
            if not os.path.exists("data.txt"):
                messagebox.showerror("Hata", "Veri dosyası bulunamadı.")
                return

            with open("data.txt", "rb") as file:
                encrypted_data = file.read().strip()
                notes = encrypted_data.split(b"\n\n")

            all_notes = ""
            for note in notes:
                if note:
                    encrypted_text, encrypted_password = note.split(b"\n")
                    decrypted_password = decrypt_message(encrypted_password)
                    if decrypted_password == entered_password:
                        decrypted_text = decrypt_message(encrypted_text)
                        all_notes += f"Metin:\n{decrypted_text}\nŞifre:\n{decrypted_password}\n\n"

            if all_notes:
                messagebox.showinfo("Notlarım", all_notes)
            else:
                messagebox.showerror("Hata", "Girilen şifreyle eşleşen not bulunamadı.")
        except Exception as e:
            messagebox.showerror("Hata", f"Veri okunurken bir hata oluştu: {e}")

    password_check_window = tk.Toplevel(window)
    password_check_window.title("Şifre Kontrolü")
    password_check_window.geometry("300x150")
    password_check_window.config(bg=arkaplan)

    password_check_label = tk.Label(password_check_window, text="Şifrenizi Girin:", bg=arkaplan, fg=yazı,
                                    font=("Times New Roman", 15))
    password_check_label.pack(pady=10)

    password_check_entry = tk.Entry(password_check_window, show='*', width=25, bg=buton, fg="black",
                                    font=("Times New Roman", 12))
    password_check_entry.pack(pady=5)

    password_check_button = tk.Button(password_check_window, text="Göster", command=check_password, bg=buton,
                                      fg="black", font=("Times New Roman", 12))
    password_check_button.pack(pady=10)


def toggle_password_visibility():
    if password_entry.cget('show') == '*':
        password_entry.config(show='')  # Şifreyi göster
        toggle_button.config(text="Gizle")
    else:
        password_entry.config(show='*')  # Şifreyi gizle
        toggle_button.config(text="Göster")


# Ana pencereyi oluştur
window = tk.Tk()
window.title("Gizli Not Defteri")
window.geometry("450x750")  # Pencerenin başlangıç boyutlarını belirle
window.config(bg=arkaplan)

# Şifreleme anahtarını oluştur (bir kez çalıştırmanız gerekebilir)
if not os.path.exists("secret.key"):
    generate_key()

# Resmi yükle ve göster
try:
    image = Image.open("foto.png")  # Dosya adını ve yolunu kontrol edin
    image = image.resize((250, 200), Image.Resampling.LANCZOS)  # Resmi yeniden boyutlandırma
    img = ImageTk.PhotoImage(image)
    label_img = tk.Label(window, image=img, bd=5, bg=arkaplan)
    label_img.pack(pady=10, padx=10)

except FileNotFoundError:
    messagebox.showerror("Hata",
                         "Resim dosyası bulunamadı. Lütfen dosyanın mevcut olduğundan ve adının doğru yazıldığından emin olun.")
except Exception as e:
    messagebox.showerror("Hata", f"Beklenmeyen bir hata oluştu: {e}")

title_label = tk.Label(window, text="Notunuzu Giriniz", font=("Times New Roman", 20, "bold"))
title_label.pack(pady=10)
title_label.config(fg=yazı, bg=arkaplan)

text_label = tk.Label(window, text="Metin Girin:", font=("Times New Roman", 15, "bold"))
text_label.pack(pady=5)
text_label.config(bg=arkaplan, fg=yazı)

text_box = tk.Text(window, height=10, width=30, fg=yazı, bg=arkaplan, bd=10, font=("Times New Roman", 18))
text_box.insert("1.0", "Metin Girin")
text_box.bind('<FocusIn>', on_text_click)
text_box.bind('<FocusOut>', on_text_focus_out)
text_box.pack(pady=10, padx=10)

# Şifre girme kutusu ve butonu için çerçeve
password_frame = tk.Frame(window)
password_frame.pack(pady=10)
password_frame.config(bg=arkaplan)

# Şifre girme kutusu
password_label = tk.Label(password_frame, text="Şifre Girin:")
password_label.pack(side=tk.LEFT)
password_label.config(bg=buton, fg="black", font=("Times New Roman", 15))

password_entry = tk.Entry(password_frame, show='*', width=20)  # Şifre karakterlerini '*' ile gizler
password_entry.pack(side=tk.LEFT)
password_entry.config(bg=arkaplan, fg=yazı)

# Şifre görünürlük butonu
toggle_button = tk.Button(password_frame, text="Göster", command=toggle_password_visibility)
toggle_button.pack(side=tk.LEFT, padx=5)  # Butona biraz sağ boşluk ekleyin
toggle_button.config(fg="black", bg=buton)

# Kaydetme butonu
save_button = tk.Button(window, text="Kaydet", command=save_data, bg=buton)
save_button.pack(pady=10)

show_button = tk.Button(window, text="Notlarım", command=load_data, bg=buton)
show_button.pack(padx=10)

window.mainloop()
