import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import Algorithm
import struct
import io
import threading
import queue


class ElGamalApp:
    def __init__(self, root):
        self.save_format = None
        self.root = root
        self.root.title("Криптосистема Эль-Гамаля")
        self.root.geometry("730x400")

        self.p = tk.StringVar()
        self.g = tk.StringVar()
        self.x = tk.StringVar()
        self.y = tk.StringVar()
        self.publicKey = tk.StringVar()
        self.k = tk.StringVar()
        self.primitiveRoots = []
        self.eFile = None
        self.dFile = None

        self.createWidgets()

    def createWidgets(self):
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill='both', expand=True)
        paramsFrame = ttk.Frame(notebook)
        notebook.add(paramsFrame, text="Параметры")
        self.setupParamsTab(paramsFrame)
        encryptFrame = ttk.Frame(notebook)
        notebook.add(encryptFrame, text="Шифрование")
        self.setupEncryptTab(encryptFrame)
        decryptFrame = ttk.Frame(notebook)
        notebook.add(decryptFrame, text="Дешифрование")
        self.setupDecryptTab(decryptFrame)

    def setupParamsTab(self, frame):
        ttk.Label(frame, text="Введите простое число p:").grid(row=0, column=0, padx=5, pady=5, sticky='w')
        pEntry = ttk.Entry(frame, textvariable=self.p)
        pEntry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Button(frame, text="Проверить на простоту", command=self.checkPrime).grid(row=0, column=2, padx=5, pady=5)

        ttk.Label(frame, text="Первообразные корни:").grid(row=1, column=0, padx=5, pady=5, sticky='w')
        self.rootsCombobox = ttk.Combobox(frame, textvariable=self.g, state='readonly')
        self.rootsCombobox.grid(row=1, column=1, padx=5, pady=5)

        ttk.Label(frame, text="Закрытый ключ x (1 < x < p-1):").grid(row=2, column=0, padx=5, pady=5, sticky='w')
        xEntry = ttk.Entry(frame, textvariable=self.x)
        xEntry.grid(row=2, column=1, padx=5, pady=5)

        ttk.Button(frame, text="Вычислить открытый ключ", command=self.calculateY).grid(row=2, column=2, padx=5, pady=5)

        ttk.Label(frame, text="Открытый ключ:").grid(row=3, column=0, padx=5, pady=5, sticky='w')
        ttk.Label(frame, textvariable=self.publicKey).grid(row=3, column=1, padx=5, pady=5, sticky='w')

        ttk.Label(frame, text="Число k (НОД(k, p-1) = 1):").grid(row=4, column=0, padx=5, pady=5, sticky='w')
        ttk.Entry(frame, textvariable=self.k).grid(row=4, column=1, padx=5, pady=5)
        ttk.Button(frame, text="Проверить k", command=self.generateK).grid(row=4, column=2, padx=5, pady=5)

    def setupEncryptTab(self, frame):
        ttk.Label(frame, text="Файл для шифрования:").grid(row=0, column=0, padx=5, pady=5, sticky='w')
        ttk.Button(frame, text="Выбрать файл", command=self.selectEncryptFile).grid(row=0, column=1, padx=5, pady=5)


        ttk.Button(frame, text="Зашифровать", command=self.encryptFile).grid(row=3, column=0, columnspan=3, pady=10)

        ttk.Label(frame, text="Исходный текст:").grid(row=4, column=0, padx=2, pady=5, sticky='w')
        ttk.Label(frame, text="Шифротекст:").grid(row=4, column=2, padx=2, pady=5, sticky='w')
        texts_frame = tk.Frame(frame)
        texts_frame.grid(row=5, column=0, columnspan=6, padx=5, pady=5, sticky="ew")

        plain_frame = tk.Frame(texts_frame)
        plain_frame.pack(side="left", fill="both", expand=True)

        plain_scroll = tk.Scrollbar(plain_frame, orient="vertical")
        self.plainText = tk.Text(plain_frame, height=10, width=40, state='disabled', yscrollcommand=plain_scroll.set)
        plain_scroll.config(command=self.plainText.yview)

        self.plainText.pack(side="left", fill="both", expand=True)
        plain_scroll.pack(side="right", fill="y")

        encrypt_frame = tk.Frame(texts_frame)
        encrypt_frame.pack(side="right", fill="both", expand=True)

        encrypt_scroll = tk.Scrollbar(encrypt_frame, orient="vertical")
        self.encryptText = tk.Text(encrypt_frame, height=10, width=40, state='disabled',
                                   yscrollcommand=encrypt_scroll.set)
        encrypt_scroll.config(command=self.encryptText.yview)

        self.encryptText.pack(side="left", fill="both", expand=True)
        encrypt_scroll.pack(side="right", fill="y")

        save_frame = tk.Frame(frame)
        save_frame.grid(row=6, column=0, columnspan=3, pady=10)

        ttk.Label(save_frame, text="Сохранить как:").pack(side="left", padx=5)

        self.save_format = tk.StringVar()
        format_combobox = ttk.Combobox(save_frame, textvariable=self.save_format, values=["txt", "docx", "jpeg", "png"],
                                       state='readonly', width=8)
        format_combobox.current(0)
        format_combobox.pack(side="left", padx=5)

        ttk.Button(save_frame, text="Сохранить", command=self.saveEncrypted).pack(side="left", padx=5)

    def setupDecryptTab(self, frame):
        ttk.Label(frame, text="Файл для дешифрования:").grid(row=0, column=0, padx=5, pady=5, sticky='w')
        ttk.Button(frame, text="Выбрать файл", command=self.selectDecryptFile).grid(row=0, column=1, padx=5, pady=5)

        ttk.Button(frame, text="Дешифровать", command=self.decryptFile).grid(row=1, column=0, columnspan=2, pady=10)

        ttk.Label(frame, text="Шифротекст:").grid(row=4, column=0, padx=2, pady=5, sticky='w')
        ttk.Label(frame, text="Исходный текст:").grid(row=4, column=2, padx=2, pady=5, sticky='w')
        texts_frame = tk.Frame(frame)
        texts_frame.grid(row=5, column=0, columnspan=6, padx=5, pady=5, sticky="ew")

        cipher_frame = tk.Frame(texts_frame)
        cipher_frame.pack(side="left", fill="both", expand=True)

        cipher_scroll = tk.Scrollbar(cipher_frame, orient="vertical")
        self.cipherText = tk.Text(cipher_frame, height=10, width=40, state='disabled', yscrollcommand=cipher_scroll.set)
        cipher_scroll.config(command=self.cipherText.yview)

        self.cipherText.pack(side="left", fill="both", expand=True)
        cipher_scroll.pack(side="right", fill="y")

        decrypt_frame = tk.Frame(texts_frame)
        decrypt_frame.pack(side="right", fill="both", expand=True)

        dencrypt_scroll = tk.Scrollbar(decrypt_frame, orient="vertical")
        self.decryptText = tk.Text(decrypt_frame, height=10, width=40, state='disabled',
                                   yscrollcommand=dencrypt_scroll.set)
        dencrypt_scroll.config(command=self.decryptText.yview)

        self.decryptText.pack(side="left", fill="both", expand=True)
        dencrypt_scroll.pack(side="right", fill="y")

        saveFrame = tk.Frame(frame)
        saveFrame.grid(row=6, column=0, columnspan=3, pady=10)

        ttk.Label(saveFrame, text="Сохранить как:").pack(side="left", padx=5)

        self.saveFormat = tk.StringVar()
        format_combobox = ttk.Combobox(saveFrame, textvariable=self.saveFormat, values=["txt", "docx", "jpeg", "png"],
                                       state='readonly', width=8)
        format_combobox.current(0)
        format_combobox.pack(side="left", padx=5)

        ttk.Button(saveFrame, text="Сохранить", command=self.saveDecrypted).pack(side="left", padx=5)

    def checkPrime(self):
        try:
            p = int(self.p.get())
            if p < 3:
                messagebox.showwarning("Ошибка", "Введите число больше 2.")
                return
            if Algorithm.isPrime(p):
                messagebox.showinfo("Проверка на простоту", f"{p} — простое число.")
                self.primitiveRoots = Algorithm.findPrimitiveRoots(p)
                self.rootsCombobox['values'] = self.primitiveRoots
                self.rootsCombobox.current(0)

            else:
                messagebox.showwarning("Проверка на простоту", f"{p} — не является простым.")

        except ValueError:
            messagebox.showerror("Ошибка", "Введите корректное целое число.")

    def calculateY(self):
        try:
            x = int(self.x.get())
            p = int(self.p.get())
            g = int(self.g.get())
            if 1 < x < p - 1:
                self.y.set(Algorithm.calculateY(p, x, g))
                self.publicKey.set(f"({self.p.get()}, {self.g.get()}, {self.y.get()})")
            else:
                messagebox.showwarning("Ошибка", "x должно быть в диапазоне (1, p - 1).")
                self.x.set("")
        except ValueError:
            messagebox.showwarning("Ошибка", "Введите целое число для x и p.")
            self.x.set("")


    def generateK(self):
        gcd = Algorithm.greatestCommonDivisor(int(self.k.get()), int(self.p.get()) - 1)
        if gcd == 1:
            messagebox.showinfo("Info", "НОД(k, p-1) = 1")
        else:
            messagebox.showwarning("Info", "k и p-1 НЕ взаимнопросты")
            self.k.set("")

    def selectEncryptFile(self):
        filepath = filedialog.askopenfilename(title="Выбрать файл")
        if filepath:
            self.eFile = filepath
            self.plainText.configure(state='normal')
            self.plainText.delete("1.0", tk.END)

            try:
                with open(filepath, 'rb') as f:
                    content = f.read()
                    buffer = io.StringIO()
                    for byte in content:
                        buffer.write(f"{byte} ")
                    self.plainText.insert(tk.END, buffer.getvalue())
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось прочитать файл:\n{e}")
            finally:
                self.plainText.configure(state='disabled')

    def selectDecryptFile(self):
        filepath = filedialog.askopenfilename(title="Выбрать файл")
        if filepath:
            self.dFile = filepath
            self.cipherText.configure(state='normal')
            self.cipherText.delete("1.0", tk.END)
            try:
                with open(filepath, 'rb') as f:
                    content = f.read()

                    pairs = []
                    for i in range(0, len(content), 4):
                        a = int.from_bytes(content[i:i + 2], byteorder='big')
                        b = int.from_bytes(content[i + 2:i + 4], byteorder='big')
                        pairs.append(f"({a}, {b})")

                    text = ' '.join(pairs)
                    self.cipherText.insert(tk.END, text)

            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось прочитать файл:\n{e}")
            finally:
                self.cipherText.configure(state='disabled')

    def encryptFile(self):
        filepath = self.eFile
        if not filepath:
            return

        try:
            with open(filepath, 'rb') as f:
                plaintext = f.read()
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка при чтении файла: {e}")
            return

        try:
            p = int(self.p.get())
            g = int(self.g.get())
            y = int(self.y.get())
            k = int(self.k.get())

            encrypted = Algorithm.ciphering(g, k, p, y, plaintext)
            self.encryptText.configure(state='normal')
            self.encryptText.delete("1.0", tk.END)
            self.encryptText.insert(tk.END, "Результат шифрования (a, b):\n")
            for a, b in encrypted:
                self.encryptText.insert(tk.END, f"({a}, {b})\n")
            self.encryptText.configure(state='disabled')
            self.encrypted_pairs = encrypted
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка при шифровании: {e}")

    def decryptFile(self):
        try:
            p_str = self.p.get().strip()
            x_str = self.x.get().strip()
            if not p_str or not x_str:
                messagebox.showerror("Ошибка", "Введите оба значения p и x.")
                return
            p = int(p_str)
            x = int(x_str)
            file_path = self.dFile
            if not file_path:
                return

            pairs = []

            with open(file_path, 'rb') as f:
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

            decrypted_data = Algorithm.deciphering(p, x, pairs)
            self.decrypted_bytes = bytes(decrypted_data) if isinstance(decrypted_data, list) else decrypted_data

            self.decryptText.configure(state='normal')
            self.decryptText.delete("1.0", tk.END)

            if isinstance(self.decrypted_bytes, bytes):
                byte_numbers = [str(b) for b in self.decrypted_bytes]
                self.decryptText.insert(tk.END, " ".join(byte_numbers))
            else:
                self.decryptText.insert(tk.END, str(self.decrypted_bytes))

        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка при расшифровке файла: {e}")

    def saveEncrypted(self):
        ext = self.save_format.get()
        if not ext:
            messagebox.showwarning("Ошибка", "Выберите формат для сохранения.")
            return

        filetypes = [(f"{ext.upper()} files", f"*.{ext}")]
        path = filedialog.asksaveasfilename(defaultextension=f".{ext}", filetypes=filetypes)

        if not path:
            return

        try:
            if ext == "txt":
                with open(path, 'wb') as f:
                    for a, b in self.encrypted_pairs:
                        f.write(a.to_bytes(2, byteorder='big'))
                        f.write(b.to_bytes(2, byteorder='big'))
            else:
                messagebox.showerror("Ошибка", "Для шифротекста поддерживается только формат TXT.")
                return

            messagebox.showinfo("Успех", f"Шифротекст успешно сохранён в файл: {path}")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось сохранить файл: {e}")

    def saveDecrypted(self):
        ext = self.saveFormat.get()
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

        if not path:
            return

        try:
            byte_stream = self.decrypted_bytes
            if ext == "txt":
                with open(path, 'wb') as f:
                    f.write(byte_stream)
            elif ext in ["png", "jpeg", "jpg"]:
                from PIL import Image
                from io import BytesIO

                image_data = BytesIO(byte_stream)
                img = Image.open(image_data)
                img.save(path, format=ext.upper())
            elif ext == "docx":
                from docx import Document
                doc = Document()
                doc.add_paragraph(byte_stream.decode('utf-8', errors='ignore'))
                doc.save(path)
            elif ext == "mov":
                with open(path, 'wb') as f:
                    f.write(byte_stream)

            messagebox.showinfo("Успех", f"Файл успешно сохранён: {path}")

        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось сохранить файл: {e}")


if __name__ == "__main__":
    root = tk.Tk()
    app = ElGamalApp(root)
    root.mainloop()