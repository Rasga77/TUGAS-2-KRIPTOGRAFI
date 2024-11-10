import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from cryptography.fernet import Fernet
import base64
import hashlib
import os

class CryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Encryption/Decryption")
        self.file_data = None
        self.file_path = None

        # Komponen GUI
        self.create_gui()

    def create_gui(self):
        key_label = tk.Label(self.root, text="Masukkan Kunci (panjang bebas):")
        key_label.pack(pady=5)
        
        self.key_entry = tk.Entry(self.root, width=50, show='*')
        self.key_entry.pack(pady=5)
        
        input_label = tk.Label(self.root, text="Masukkan teks atau unggah file:")
        input_label.pack(pady=5)

        self.input_text = scrolledtext.ScrolledText(self.root, width=60, height=10)
        self.input_text.pack(pady=5)
        
        upload_button = tk.Button(self.root, text="Unggah File", command=self.upload_file)
        upload_button.pack(pady=5)
        
        encrypt_button = tk.Button(self.root, text="Enkripsi Teks/File", command=self.encrypt_text_or_file)
        encrypt_button.pack(pady=5)
        
        decrypt_button = tk.Button(self.root, text="Dekripsi Teks/File", command=self.decrypt_text_or_file)
        decrypt_button.pack(pady=5)

        save_cipher_button = tk.Button(self.root, text="Simpan Ciphertext", command=self.save_ciphertext)
        save_cipher_button.pack(pady=5)

        output_label = tk.Label(self.root, text="Plaintext dan Ciphertext:")
        output_label.pack(pady=5)
        
        self.output_text = scrolledtext.ScrolledText(self.root, width=60, height=10)
        self.output_text.pack(pady=5)

    def upload_file(self):
        self.file_path = filedialog.askopenfilename()
        if not self.file_path:
            return

        with open(self.file_path, "rb") as file:
            self.file_data = file.read()
        
        try:
            content = self.file_data.decode("utf-8")
            self.input_text.delete("1.0", tk.END)
            self.input_text.insert(tk.END, content)
        except UnicodeDecodeError:
            self.input_text.delete("1.0", tk.END)
            self.input_text.insert(tk.END, "[File Biner Terunggah]")

    def get_cipher_key(self):
        user_key = self.key_entry.get().encode()
        if len(user_key) == 0:
            raise ValueError("Kunci tidak boleh kosong.")
        
        hashed_key = hashlib.sha256(user_key).digest()
        return base64.urlsafe_b64encode(hashed_key)
#---
    def encrypt_text_or_file(self):
        try:
            key = self.get_cipher_key()
            cipher = Fernet(key)
            
            if self.file_data:
                encrypted_data = cipher.encrypt(self.file_data)
                
                original_extension = os.path.splitext(self.file_path)[1]
                save_path = filedialog.asksaveasfilename(defaultextension=original_extension, filetypes=[("Encrypted Files", f"*{original_extension}")], initialfile=os.path.basename(self.file_path) + "_encrypted")
                if not save_path:
                    return
                
                with open(save_path, "wb") as file:
                    file.write(encrypted_data)
                messagebox.showinfo("Sukses", "File berhasil dienkripsi!")
            else:
                message = self.input_text.get("1.0", tk.END).strip().encode()
                encrypted_message = cipher.encrypt(message)
                
                self.output_text.delete("1.0", tk.END)
                self.output_text.insert(tk.END, f"Plaintext:\n{message.decode()}\n\n")
                self.output_text.insert(tk.END, f"Ciphertext:\n{base64.b64encode(encrypted_message).decode('utf-8')}\n")
                messagebox.showinfo("Sukses", "Pesan berhasil dienkripsi!")
                
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def decrypt_text_or_file(self):
        try:
            key = self.get_cipher_key()
            cipher = Fernet(key)
            
            if self.file_data:
                decrypted_data = cipher.decrypt(self.file_data)
                
                original_extension = os.path.splitext(self.file_path)[1]
                save_path = filedialog.asksaveasfilename(defaultextension=original_extension, filetypes=[("Original Files", original_extension)])
                if not save_path:
                    return
                
                with open(save_path, "wb") as file:
                    file.write(decrypted_data)
                messagebox.showinfo("Sukses", "File berhasil didekripsi!")
            else:
                encrypted_text = self.input_text.get("1.0", tk.END).strip()
                decrypted_message = cipher.decrypt(base64.b64decode(encrypted_text))
                
                self.output_text.delete("1.0", tk.END)
                self.output_text.insert(tk.END, f"Ciphertext:\n{encrypted_text}\n\n")
                self.output_text.insert(tk.END, f"Plaintext:\n{decrypted_message.decode('utf-8')}\n")
                messagebox.showinfo("Sukses", "Pesan berhasil didekripsi!")
                
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def save_ciphertext(self):
        try:
            ciphertext = self.output_text.get("1.0", tk.END).strip()
            if not ciphertext:
                raise ValueError("Tidak ada ciphertext yang dapat disimpan.")
            
            save_path = filedialog.asksaveasfilename(defaultextension=".enc", filetypes=[("Encrypted Files", "*.enc")])
            if not save_path:
                return
            
            with open(save_path, "w") as file:
                file.write(ciphertext)
            
            messagebox.showinfo("Sukses", "Ciphertext berhasil disimpan!")
        except Exception as e:
            messagebox.showerror("Error", str(e))

def main():
    root = tk.Tk()
    app = CryptoApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
