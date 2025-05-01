import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Optional, List, Tuple
import io
from crypto_parameters import CryptoParameters
from file_manager import FileManager


class EncryptionTab:
    def __init__(self, parent: ttk.Frame, crypto_params: CryptoParameters):
        self.crypto_params = crypto_params
        self.file_manager = FileManager()
        self.encrypted_pairs: Optional[List[Tuple[int, int]]] = None
        self.selected_file: Optional[str] = None
        self.setup_ui(parent)
    
    def setup_ui(self, parent: ttk.Frame) -> None:
        self.save_format_var = tk.StringVar()
        
        ttk.Label(parent, text="Файл для шифрования:").grid(row=0, column=0, padx=5, pady=5, sticky='w')
        ttk.Button(parent, text="Выбрать файл", command=self.select_file).grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Button(parent, text="Зашифровать", command=self.encrypt_file).grid(row=3, column=0, columnspan=3, pady=10)
        
        ttk.Label(parent, text="Исходный текст:").grid(row=4, column=0, padx=2, pady=5, sticky='w')
        ttk.Label(parent, text="Шифротекст:").grid(row=4, column=2, padx=2, pady=5, sticky='w')
        
        texts_frame = tk.Frame(parent)
        texts_frame.grid(row=5, column=0, columnspan=6, padx=5, pady=5, sticky="ew")
        
        self.setup_text_areas(texts_frame)
        self.setup_save_section(parent)
    
    def setup_text_areas(self, parent: tk.Frame) -> None:
        plain_frame = tk.Frame(parent)
        plain_frame.pack(side="left", fill="both", expand=True)
        
        plain_scroll = tk.Scrollbar(plain_frame, orient="vertical")
        self.plain_text = tk.Text(plain_frame, height=10, width=40, state='disabled', yscrollcommand=plain_scroll.set)
        plain_scroll.config(command=self.plain_text.yview)
        
        self.plain_text.pack(side="left", fill="both", expand=True)
        plain_scroll.pack(side="right", fill="y")
        
        encrypt_frame = tk.Frame(parent)
        encrypt_frame.pack(side="right", fill="both", expand=True)
        
        encrypt_scroll = tk.Scrollbar(encrypt_frame, orient="vertical")
        self.encrypt_text = tk.Text(encrypt_frame, height=10, width=40, state='disabled', yscrollcommand=encrypt_scroll.set)
        encrypt_scroll.config(command=self.encrypt_text.yview)
        
        self.encrypt_text.pack(side="left", fill="both", expand=True)
        encrypt_scroll.pack(side="right", fill="y")
    
    def setup_save_section(self, parent: ttk.Frame) -> None:
        save_frame = tk.Frame(parent)
        save_frame.grid(row=6, column=0, columnspan=3, pady=10)
        
        ttk.Label(save_frame, text="Сохранить как:").pack(side="left", padx=5)
        
        format_combobox = ttk.Combobox(save_frame, textvariable=self.save_format_var, 
                                      values=["txt", "docx", "jpeg", "png"], state='readonly', width=8)
        format_combobox.current(0)
        format_combobox.pack(side="left", padx=5)
        
        ttk.Button(save_frame, text="Сохранить", command=self.save_encrypted).pack(side="left", padx=5)
    
    def select_file(self) -> None:
        filepath = filedialog.askopenfilename(title="Выбрать файл")
        if filepath:
            self.selected_file = filepath
            self.plain_text.configure(state='normal')
            self.plain_text.delete("1.0", tk.END)
            
            try:
                content = self.file_manager.read_file_as_bytes(filepath)
                buffer = io.StringIO()
                for byte in content:
                    buffer.write(f"{byte} ")
                self.plain_text.insert(tk.END, buffer.getvalue())
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось прочитать файл:\n{e}")
            finally:
                self.plain_text.configure(state='disabled')
    
    def encrypt_file(self) -> None:
        if not self.selected_file:
            messagebox.showwarning("Ошибка", "Выберите файл для шифрования.")
            return
        
        if not all([self.crypto_params.p, self.crypto_params.g, self.crypto_params.y, self.crypto_params.k]):
            messagebox.showwarning("Ошибка", "Заполните все параметры криптосистемы.")
            return
        
        try:
            plaintext = self.file_manager.read_file_as_bytes(self.selected_file)
            encrypted = self.crypto_params.cipher.encrypt(
                plaintext, self.crypto_params.p, self.crypto_params.g, 
                self.crypto_params.y, self.crypto_params.k
            )
            
            self.encrypt_text.configure(state='normal')
            self.encrypt_text.delete("1.0", tk.END)
            self.encrypt_text.insert(tk.END, "Результат шифрования (a, b):\n")
            for a, b in encrypted:
                self.encrypt_text.insert(tk.END, f"({a}, {b})\n")
            self.encrypt_text.configure(state='disabled')
            
            self.encrypted_pairs = encrypted
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка при шифровании: {e}")
    
    def save_encrypted(self) -> None:
        if not self.encrypted_pairs:
            messagebox.showwarning("Ошибка", "Нет данных для сохранения.")
            return
        
        ext = self.save_format_var.get()
        if not ext:
            messagebox.showwarning("Ошибка", "Выберите формат для сохранения.")
            return
        
        if ext != "txt":
            messagebox.showerror("Ошибка", "Для шифротекста поддерживается только формат TXT.")
            return
        
        filetypes = [(f"{ext.upper()} files", f"*.{ext}")]
        path = filedialog.asksaveasfilename(defaultextension=f".{ext}", filetypes=filetypes)
        
        if path:
            try:
                self.file_manager.save_encrypted_file(path, self.encrypted_pairs)
                messagebox.showinfo("Успех", f"Шифротекст успешно сохранён в файл: {path}")
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось сохранить файл: {e}")
