import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Optional
from crypto_parameters import CryptoParameters
from file_manager import FileManager


class DecryptionTab:
    def __init__(self, parent: ttk.Frame, crypto_params: CryptoParameters):
        self.crypto_params = crypto_params
        self.file_manager = FileManager()
        self.decrypted_bytes: Optional[bytes] = None
        self.selected_file: Optional[str] = None
        self.setup_ui(parent)
    
    def setup_ui(self, parent: ttk.Frame) -> None:
        self.save_format_var = tk.StringVar()
        
        ttk.Label(parent, text="Файл для дешифрования:").grid(row=0, column=0, padx=5, pady=5, sticky='w')
        ttk.Button(parent, text="Выбрать файл", command=self.select_file).grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Button(parent, text="Дешифровать", command=self.decrypt_file).grid(row=1, column=0, columnspan=2, pady=10)
        
        ttk.Label(parent, text="Шифротекст:").grid(row=4, column=0, padx=2, pady=5, sticky='w')
        ttk.Label(parent, text="Исходный текст:").grid(row=4, column=2, padx=2, pady=5, sticky='w')
        
        texts_frame = tk.Frame(parent)
        texts_frame.grid(row=5, column=0, columnspan=6, padx=5, pady=5, sticky="ew")
        
        self.setup_text_areas(texts_frame)
        self.setup_save_section(parent)
    
    def setup_text_areas(self, parent: tk.Frame) -> None:
        cipher_frame = tk.Frame(parent)
        cipher_frame.pack(side="left", fill="both", expand=True)
        
        cipher_scroll = tk.Scrollbar(cipher_frame, orient="vertical")
        self.cipher_text = tk.Text(cipher_frame, height=10, width=40, state='disabled', yscrollcommand=cipher_scroll.set)
        cipher_scroll.config(command=self.cipher_text.yview)
        
        self.cipher_text.pack(side="left", fill="both", expand=True)
        cipher_scroll.pack(side="right", fill="y")
        
        decrypt_frame = tk.Frame(parent)
        decrypt_frame.pack(side="right", fill="both", expand=True)
        
        decrypt_scroll = tk.Scrollbar(decrypt_frame, orient="vertical")
        self.decrypt_text = tk.Text(decrypt_frame, height=10, width=40, state='disabled', yscrollcommand=decrypt_scroll.set)
        decrypt_scroll.config(command=self.decrypt_text.yview)
        
        self.decrypt_text.pack(side="left", fill="both", expand=True)
        decrypt_scroll.pack(side="right", fill="y")
    
    def setup_save_section(self, parent: ttk.Frame) -> None:
        save_frame = tk.Frame(parent)
        save_frame.grid(row=6, column=0, columnspan=3, pady=10)
        
        ttk.Label(save_frame, text="Сохранить как:").pack(side="left", padx=5)
        
        format_combobox = ttk.Combobox(save_frame, textvariable=self.save_format_var, 
                                      values=["txt", "docx", "jpeg", "png"], state='readonly', width=8)
        format_combobox.current(0)
        format_combobox.pack(side="left", padx=5)
        
        ttk.Button(save_frame, text="Сохранить", command=self.save_decrypted).pack(side="left", padx=5)
    
    def select_file(self) -> None:
        filepath = filedialog.askopenfilename(title="Выбрать файл")
        if filepath:
            self.selected_file = filepath
            self.cipher_text.configure(state='normal')
            self.cipher_text.delete("1.0", tk.END)
            
            try:
                pairs = self.file_manager.read_encrypted_file(filepath)
                pairs_text = ' '.join([f"({a}, {b})" for a, b in pairs])
                self.cipher_text.insert(tk.END, pairs_text)
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось прочитать файл:\n{e}")
            finally:
                self.cipher_text.configure(state='disabled')
    
    def decrypt_file(self) -> None:
        if not self.selected_file:
            messagebox.showwarning("Ошибка", "Выберите файл для дешифрования.")
            return
        
        if not all([self.crypto_params.p, self.crypto_params.x]):
            messagebox.showwarning("Ошибка", "Заполните параметры p и x.")
            return
        
        try:
            pairs = self.file_manager.read_encrypted_file(self.selected_file)
            decrypted_data = self.crypto_params.cipher.decrypt(pairs, self.crypto_params.p, self.crypto_params.x)
            self.decrypted_bytes = bytes(decrypted_data)
            
            self.decrypt_text.configure(state='normal')
            self.decrypt_text.delete("1.0", tk.END)
            
            byte_numbers = [str(b) for b in self.decrypted_bytes]
            self.decrypt_text.insert(tk.END, " ".join(byte_numbers))
            self.decrypt_text.configure(state='disabled')
            
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка при расшифровке файла: {e}")
    
    def save_decrypted(self) -> None:
        if not self.decrypted_bytes:
            messagebox.showwarning("Ошибка", "Нет данных для сохранения.")
            return
        
        ext = self.save_format_var.get()
        if not ext:
            messagebox.showwarning("Ошибка", "Выберите формат для сохранения.")
            return
        
        filetypes = {
            "txt": [("Text files", "*.txt")],
            "png": [("PNG files", "*.png")],
            "jpeg": [("JPEG files", "*.jpeg"), ("JPG files", "*.jpg")],
            "docx": [("Word documents", "*.docx")],
            "mov": [("Movie files", "*.mov")]
        }
        
        if ext not in filetypes:
            messagebox.showerror("Ошибка", "Неподдерживаемый формат.")
            return
        
        path = filedialog.asksaveasfilename(defaultextension=f".{ext}", filetypes=filetypes[ext])
        
        if path:
            try:
                self.file_manager.save_decrypted_file(path, self.decrypted_bytes, ext)
                messagebox.showinfo("Успех", f"Файл успешно сохранён: {path}")
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось сохранить файл: {e}")
