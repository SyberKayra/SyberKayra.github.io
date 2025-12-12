import customtkinter as ctk
from tkinter import filedialog, messagebox
from PIL import Image
import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# --- AYARLAR ---
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("green")

class ShadowBitApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Pencere Ayarları
        self.title("ShadowBit - Secure Steganography")
        self.geometry("700x550")
        self.resizable(False, False)

        # Başlık
        self.header = ctk.CTkLabel(self, text="ShadowBit v1.1", font=("Roboto Medium", 24))
        self.header.pack(pady=20)

        # Tab Sistemi
        self.tabview = ctk.CTkTabview(self, width=650, height=450)
        self.tabview.pack(padx=20, pady=10)

        self.tab_hide = self.tabview.add("Veri Gizle (Encrypt)")
        self.tab_reveal = self.tabview.add("Veri Çöz (Decrypt)")

        self.setup_hide_tab()
        self.setup_reveal_tab()

    # --- PLACEHOLDER (Yazı Alanı) MANTIĞI ---
    def on_entry_click(self, event):
        """Kullanıcı kutuya tıkladığında placeholder'ı sil"""
        if self.placeholder_active:
            self.entry_msg.delete("0.0", "end")
            self.entry_msg.configure(text_color=("black", "white")) # Yazı rengini normale döndür
            self.placeholder_active = False

    def on_focus_out(self, event):
        """Kullanıcı kutudan çıktığında boşsa placeholder'ı geri getir"""
        if not self.entry_msg.get("0.0", "end-1c").strip():
            self.entry_msg.configure(text_color="gray")
            self.entry_msg.insert("0.0", "Gizlenecek mesajı buraya yazın...")
            self.placeholder_active = True

    # --- ŞİFRELEME MOTORU ---
    def generate_key(self, password):
        salt = b'shadowbit_salt' 
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key

    def encrypt_message(self, message, password):
        key = self.generate_key(password)
        f = Fernet(key)
        return f.encrypt(message.encode()).decode()

    def decrypt_message(self, encrypted_message, password):
        try:
            key = self.generate_key(password)
            f = Fernet(key)
            return f.decrypt(encrypted_message.encode()).decode()
        except:
            return None

    # --- SEKME 1: GİZLEME ARAYÜZÜ ---
    def setup_hide_tab(self):
        self.btn_select_img = ctk.CTkButton(self.tab_hide, text="Fotoğraf Seç (JPG/PNG)", command=self.select_image_hide)
        self.btn_select_img.pack(pady=10)
        
        self.lbl_file_path = ctk.CTkLabel(self.tab_hide, text="Dosya seçilmedi", text_color="gray")
        self.lbl_file_path.pack()

        # Mesaj Girişi (Placeholder Ayarlı)
        self.entry_msg = ctk.CTkTextbox(self.tab_hide, height=100, width=500, text_color="gray")
        self.entry_msg.pack(pady=10)
        self.entry_msg.insert("0.0", "Gizlenecek mesajı buraya yazın...")
        
        # Olayları Bağla (Bind)
        self.placeholder_active = True
        self.entry_msg.bind("<FocusIn>", self.on_entry_click)
        self.entry_msg.bind("<FocusOut>", self.on_focus_out)

        self.entry_pass_hide = ctk.CTkEntry(self.tab_hide, placeholder_text="Şifre Belirle (Önemli!)", width=300, show="*")
        self.entry_pass_hide.pack(pady=10)

        self.btn_hide = ctk.CTkButton(self.tab_hide, text="🔒 ŞİFRELE VE GİZLE", fg_color="#c0392b", hover_color="#e74c3c", command=self.hide_process)
        self.btn_hide.pack(pady=20)
        
        self.selected_image_path = None

    # --- SEKME 2: ÇÖZME ARAYÜZÜ ---
    def setup_reveal_tab(self):
        self.btn_select_decrypt = ctk.CTkButton(self.tab_reveal, text="Şifreli Fotoğrafı Seç", command=self.select_image_reveal)
        self.btn_select_decrypt.pack(pady=10)

        self.lbl_reveal_path = ctk.CTkLabel(self.tab_reveal, text="Dosya seçilmedi", text_color="gray")
        self.lbl_reveal_path.pack()

        self.entry_pass_reveal = ctk.CTkEntry(self.tab_reveal, placeholder_text="Şifreyi Girin", width=300, show="*")
        self.entry_pass_reveal.pack(pady=10)

        self.btn_reveal = ctk.CTkButton(self.tab_reveal, text="🔓 ÇÖZ VE OKU", fg_color="#27ae60", hover_color="#2ecc71", command=self.reveal_process)
        self.btn_reveal.pack(pady=20)

        self.lbl_result_title = ctk.CTkLabel(self.tab_reveal, text="GİZLİ MESAJ:", font=("Arial", 14, "bold"))
        self.lbl_result_title.pack()
        
        self.txt_result = ctk.CTkTextbox(self.tab_reveal, height=100, width=500, state="disabled")
        self.txt_result.pack(pady=5)

        self.selected_reveal_path = None

    # --- FONKSİYONLAR ---
    def select_image_hide(self):
        file = filedialog.askopenfilename(filetypes=[("Image Files", "*.png;*.jpg;*.jpeg")])
        if file:
            self.selected_image_path = file
            self.lbl_file_path.configure(text=os.path.basename(file), text_color="#2ecc71")

    def select_image_reveal(self):
        file = filedialog.askopenfilename(filetypes=[("Image Files", "*.png")])
        if file:
            self.selected_reveal_path = file
            self.lbl_reveal_path.configure(text=os.path.basename(file), text_color="#2ecc71")

    def text_to_bin(self, message):
        return ''.join(format(ord(i), '08b') for i in message)

    def hide_process(self):
        if not self.selected_image_path:
            messagebox.showerror("Hata", "Lütfen bir fotoğraf seçin!")
            return
        
        # Placeholder kontrolü: Eğer hala placeholder varsa mesaj boş demektir
        msg = self.entry_msg.get("1.0", "end-1c")
        if self.placeholder_active or not msg.strip():
            messagebox.showerror("Hata", "Lütfen gizlenecek bir mesaj yazın!")
            return
            
        password = self.entry_pass_hide.get()
        if not password:
            messagebox.showerror("Hata", "Şifre girmediniz!")
            return

        try:
            encrypted_msg = self.encrypt_message(msg, password) + "#####"
            binary_msg = self.text_to_bin(encrypted_msg)
            
            img = Image.open(self.selected_image_path).convert("RGB")
            pixels = img.load()
            
            data_index = 0
            msg_len = len(binary_msg)
            width, height = img.size

            if msg_len > width * height * 3:
                messagebox.showerror("Hata", "Mesaj çok uzun, daha büyük bir resim seçin!")
                return

            for y in range(height):
                for x in range(width):
                    r, g, b = pixels[x, y]
                    if data_index < msg_len:
                        r = int(bin(r)[2:-1] + binary_msg[data_index], 2)
                        data_index += 1
                    if data_index < msg_len:
                        g = int(bin(g)[2:-1] + binary_msg[data_index], 2)
                        data_index += 1
                    if data_index < msg_len:
                        b = int(bin(b)[2:-1] + binary_msg[data_index], 2)
                        data_index += 1
                    pixels[x, y] = (r, g, b)
                    if data_index >= msg_len: break
                if data_index >= msg_len: break
            
            save_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG Image", "*.png")])
            if save_path:
                img.save(save_path)
                messagebox.showinfo("Başarılı", f"Mesaj gizlendi ve kaydedildi!\n{os.path.basename(save_path)}")
                
        except Exception as e:
            messagebox.showerror("Hata", f"İşlem başarısız: {str(e)}")

    def reveal_process(self):
        if not self.selected_reveal_path:
            messagebox.showerror("Hata", "Lütfen şifreli bir fotoğraf seçin!")
            return
        password = self.entry_pass_reveal.get()
        if not password:
            messagebox.showerror("Hata", "Şifre girmediniz!")
            return

        try:
            img = Image.open(self.selected_reveal_path).convert("RGB")
            pixels = img.load()
            binary_data = ""
            width, height = img.size
            
            for y in range(height):
                for x in range(width):
                    r, g, b = pixels[x, y]
                    binary_data += bin(r)[-1] + bin(g)[-1] + bin(b)[-1]

            all_bytes = [binary_data[i: i+8] for i in range(0, len(binary_data), 8)]
            encrypted_extracted = ""
            for byte in all_bytes:
                encrypted_extracted += chr(int(byte, 2))
                if encrypted_extracted.endswith("#####"):
                    encrypted_extracted = encrypted_extracted[:-5]
                    break
            
            decrypted_msg = self.decrypt_message(encrypted_extracted, password)
            if decrypted_msg:
                self.txt_result.configure(state="normal")
                self.txt_result.delete("1.0", "end")
                self.txt_result.insert("1.0", decrypted_msg)
                self.txt_result.configure(state="disabled")
                messagebox.showinfo("Başarılı", "Gizli mesaj bulundu ve çözüldü!")
            else:
                messagebox.showerror("Hata", "Şifre yanlış veya gizli mesaj yok!")

        except Exception as e:
            messagebox.showerror("Hata", f"Okuma hatası: {str(e)}")

if __name__ == "__main__":
    app = ShadowBitApp()
    app.mainloop()