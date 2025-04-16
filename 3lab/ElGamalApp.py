import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import Algorithm
from Algorithm import *


class ElGamalApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Криптосистема Эль-Гамаля")
        self.root.geometry("700x400")

        self.p = tk.StringVar()
        self.g = tk.StringVar()
        self.x = tk.StringVar()
        self.y = tk.StringVar()
        self.k = tk.StringVar()
        self.primitive_roots = []

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
        self.roots_combobox = ttk.Combobox(frame, textvariable=self.g, state='readonly')
        self.roots_combobox.grid(row=1, column=1, padx=5, pady=5)

        ttk.Label(frame, text="Закрытый ключ x (1 < x < p-1):").grid(row=2, column=0, padx=5, pady=5, sticky='w')
        ttk.Entry(frame, textvariable=self.x).grid(row=2, column=1, padx=5, pady=5)

        ttk.Label(frame, text="Открытый ключ y:").grid(row=3, column=0, padx=5, pady=5, sticky='w')
        ttk.Label(frame, textvariable=self.y).grid(row=3, column=1, padx=5, pady=5, sticky='w')

        ttk.Button(frame, text="Вычислить y", command=self.calculate_y).grid(row=3, column=2, padx=5, pady=5)

    def setupEncryptTab(self, frame):
        ttk.Label(frame, text="Файл для шифрования:").grid(row=0, column=0, padx=5, pady=5, sticky='w')
        ttk.Button(frame, text="Выбрать файл", command=self.select_encrypt_file).grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(frame, text="Случайное k:").grid(row=1, column=0, padx=5, pady=5, sticky='w')
        ttk.Label(frame, textvariable=self.k).grid(row=1, column=1, padx=5, pady=5, sticky='w')

        ttk.Button(frame, text="Сгенерировать k", command=self.generate_k).grid(row=1, column=2, padx=5, pady=5)

        ttk.Button(frame, text="Зашифровать", command=self.encrypt_file).grid(row=2, column=0, columnspan=3, pady=10)

        self.encrypt_text = tk.Text(frame, height=10, width=60, state='disabled')
        self.encrypt_text.grid(row=3, column=0, columnspan=3, padx=5, pady=5)

    def setupDecryptTab(self, frame):
        ttk.Label(frame, text="Файл для дешифрования:").grid(row=0, column=0, padx=5, pady=5, sticky='w')
        ttk.Button(frame, text="Выбрать файл", command=self.select_decrypt_file).grid(row=0, column=1, padx=5, pady=5)

        ttk.Button(frame, text="Дешифровать", command=self.decrypt_file).grid(row=1, column=0, columnspan=2, pady=10)

        self.decrypt_text = tk.Text(frame, height=10, width=60, state='disabled')
        self.decrypt_text.grid(row=2, column=0, columnspan=2, padx=5, pady=5)

    def checkPrime(self):
        try:
            p = int(self.p.get())
            if p < 3:
                messagebox.showwarning("Ошибка", "Введите число больше 2.")
                return

            if Algorithm.isPrime(p):
                messagebox.showinfo("Проверка на простоту", f"{p} — простое число.")
            else:
                messagebox.showwarning("Проверка на простоту", f"{p} — не является простым.")

        except ValueError:
            messagebox.showerror("Ошибка", "Введите корректное целое число.")


    def calculate_y(self):
        messagebox.showinfo("Info", "Здесь будет вычисление y = g^x mod p")

    def generate_k(self):
        messagebox.showinfo("Info", "Здесь будет генерация случайного k")

    def select_encrypt_file(self):
        filepath = filedialog.askopenfilename()
        if filepath:
            messagebox.showinfo("Info", f"Выбран файл: {filepath}")

    def select_decrypt_file(self):
        filepath = filedialog.askopenfilename()
        if filepath:
            messagebox.showinfo("Info", f"Выбран файл: {filepath}")

    def encrypt_file(self):
        messagebox.showinfo("Info", "Здесь будет шифрование файла")

    def decrypt_file(self):
        messagebox.showinfo("Info", "Здесь будет дешифрование файла")


if __name__ == "__main__":
    root = tk.Tk()
    app = ElGamalApp(root)
    root.mainloop()