import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from Algorithm import PrimeChecker, NumberTheory, ElGamalKeyGenerator, ElGamalCipher
import struct
import io
import threading
import queue
from typing import Optional, List, Tuple

class FileManager:
    @staticmethod
    def read_file_as_bytes(filepath: str) -> bytes:
        with open(filepath, 'rb') as f:
            return f.read()
    
    @staticmethod
    def read_encrypted_file(filepath: str) -> List[Tuple[int, int]]:
        pairs = []
        with open(filepath, 'rb') as f:
            while True:
                a_bytes = f.read(2)
                if not a_bytes:
                    break
                if len(a_bytes) != 2:
                    raise ValueError("Некорректный размер данных для a")
                
                b_bytes = f.read(2)
                if len(b_bytes) != 2:
                    raise ValueError("Некорректный размер данных для b")
                
                a = int.from_bytes(a_bytes, byteorder='big')
                b = int.from_bytes(b_bytes, byteorder='big')
                pairs.append((a, b))
        return pairs
    
    @staticmethod
    def save_encrypted_file(filepath: str, encrypted_pairs: List[Tuple[int, int]]) -> None:
        with open(filepath, 'wb') as f:
            for a, b in encrypted_pairs:
                f.write(a.to_bytes(2, byteorder='big'))
                f.write(b.to_bytes(2, byteorder='big'))
    
    @staticmethod
    def save_decrypted_file(filepath: str, data: bytes, file_format: str) -> None:
        if file_format == "txt":
            with open(filepath, 'wb') as f:
                f.write(data)
        elif file_format in ["png", "jpeg", "jpg"]:
            from PIL import Image
            from io import BytesIO
            
            image_data = BytesIO(data)
            img = Image.open(image_data)
            img.save(filepath, format=file_format.upper())
        elif file_format == "docx":
            from docx import Document
            doc = Document()
            doc.add_paragraph(data.decode('utf-8', errors='ignore'))
            doc.save(filepath)
        elif file_format == "mov":
            with open(filepath, 'wb') as f:
                f.write(data)

class CryptoParameters:
    def __init__(self):
        self.p: Optional[int] = None
        self.g: Optional[int] = None
        self.x: Optional[int] = None
        self.y: Optional[int] = None
        self.k: Optional[int] = None
        self.primitive_roots: List[int] = []
        
        self.prime_checker = PrimeChecker()
        self.key_generator = ElGamalKeyGenerator(self.prime_checker)
        self.cipher = ElGamalCipher()
    
    def set_prime(self, p: int) -> bool:
        if self.prime_checker.is_prime(p):
            self.p = p
            self.primitive_roots = NumberTheory.find_primitive_roots(p)
            return True
        return False
    
    def set_primitive_root(self, g: int) -> None:
        self.g = g
    
    def set_private_key(self, x: int) -> bool:
        if self.p and self.g and 1 < x < self.p - 1:
            self.x = x
            self.y = self.key_generator.calculate_public_key(self.p, x, self.g)
            return True
        return False
    
    def set_random_k(self, k: int) -> bool:
        if self.p:
            gcd = NumberTheory.greatest_common_divisor(k, self.p - 1)
            if gcd == 1:
                self.k = k
                return True
        return False
    
    def get_public_key_string(self) -> str:
        if self.p and self.g and self.y:
            return f"({self.p}, {self.g}, {self.y})"
        return ""

class ParametersTab:
    def __init__(self, parent: ttk.Frame, crypto_params: CryptoParameters):
        self.crypto_params = crypto_params
        self.setup_ui(parent)
    
    def setup_ui(self, parent: ttk.Frame) -> None:
        self.p_var = tk.StringVar()
        self.g_var = tk.StringVar()
        self.x_var = tk.StringVar()
        self.y_var = tk.StringVar()
        self.public_key_var = tk.StringVar()
        self.k_var = tk.StringVar()
        ttk.Label(parent, text="Введите простое число p:").grid(row=0, column=0, padx=5, pady=5, sticky='w')
        p_entry = ttk.Entry(parent, textvariable=self.p_var)
        p_entry.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Button(parent, text="Проверить на простоту", command=self.check_prime).grid(row=0, column=2, padx=5, pady=5)
        
        ttk.Label(parent, text="Первообразные корни:").grid(row=1, column=0, padx=5, pady=5, sticky='w')
        self.roots_combobox = ttk.Combobox(parent, textvariable=self.g_var, state='readonly')
        self.roots_combobox.grid(row=1, column=1, padx=5, pady=5)
        
        ttk.Label(parent, text="Закрытый ключ x (1 < x < p-1):").grid(row=2, column=0, padx=5, pady=5, sticky='w')
        x_entry = ttk.Entry(parent, textvariable=self.x_var)
        x_entry.grid(row=2, column=1, padx=5, pady=5)
        
        ttk.Button(parent, text="Вычислить открытый ключ", command=self.calculate_y).grid(row=2, column=2, padx=5, pady=5)
        
        ttk.Label(parent, text="Открытый ключ:").grid(row=3, column=0, padx=5, pady=5, sticky='w')
        ttk.Label(parent, textvariable=self.public_key_var).grid(row=3, column=1, padx=5, pady=5, sticky='w')
        
        ttk.Label(parent, text="Число k (НОД(k, p-1) = 1):").grid(row=4, column=0, padx=5, pady=5, sticky='w')
        ttk.Entry(parent, textvariable=self.k_var).grid(row=4, column=1, padx=5, pady=5)
        ttk.Button(parent, text="Проверить k", command=self.check_k).grid(row=4, column=2, padx=5, pady=5)
    
    def check_prime(self) -> None:
        try:
            p = int(self.p_var.get())
            if p < 3:
                messagebox.showwarning("Ошибка", "Введите число больше 2.")
                return
            
            if self.crypto_params.set_prime(p):
                messagebox.showinfo("Проверка на простоту", f"{p} — простое число.")
                self.roots_combobox['values'] = self.crypto_params.primitive_roots
                if self.crypto_params.primitive_roots:
                    self.roots_combobox.current(0)
                    self.g_var.set(str(self.crypto_params.primitive_roots[0]))
            else:
                messagebox.showwarning("Проверка на простоту", f"{p} — не является простым.")
        except ValueError:
            messagebox.showerror("Ошибка", "Введите корректное целое число.")

    def calculate_y(self) -> None:
        try:
            x = int(self.x_var.get())
            g = int(self.g_var.get())
            
            if self.crypto_params.set_primitive_root(g) and self.crypto_params.set_private_key(x):
                self.y_var.set(str(self.crypto_params.y))
                self.public_key_var.set(self.crypto_params.get_public_key_string())
            else:
                messagebox.showwarning("Ошибка", "x должно быть в диапазоне (1, p - 1).")
                self.x_var.set("")
        except ValueError:
            messagebox.showwarning("Ошибка", "Введите целое число для x и g.")
            self.x_var.set("")
    
    def check_k(self) -> None:
        try:
            k = int(self.k_var.get())
            if self.crypto_params.set_random_k(k):
                messagebox.showinfo("Info", "НОД(k, p-1) = 1")
            else:
                messagebox.showwarning("Info", "k и p-1 НЕ взаимнопросты")
                self.k_var.set("")
        except ValueError:
            messagebox.showwarning("Ошибка", "Введите целое число для k.")

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

class ElGamalApp:

    def __init__(self, root: tk.Tk):
        
        self.root = root
        self.root.title("Криптосистема Эль-Гамаля")
        self.root.geometry("730x400")

        self.crypto_params = CryptoParameters()

        self.create_widgets()
    
    def create_widgets(self) -> None:
        
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill='both', expand=True)

        params_frame = ttk.Frame(notebook)
        notebook.add(params_frame, text="Параметры")
        self.params_tab = ParametersTab(params_frame, self.crypto_params)

        encrypt_frame = ttk.Frame(notebook)
        notebook.add(encrypt_frame, text="Шифрование")
        self.encrypt_tab = EncryptionTab(encrypt_frame, self.crypto_params)

        decrypt_frame = ttk.Frame(notebook)
        notebook.add(decrypt_frame, text="Дешифрование")
        self.decrypt_tab = DecryptionTab(decrypt_frame, self.crypto_params)

if __name__ == "__main__":
    root = tk.Tk()
    app = ElGamalApp(root)
    root.mainloop()