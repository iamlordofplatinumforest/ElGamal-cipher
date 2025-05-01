import tkinter as tk
from tkinter import messagebox, ttk
from crypto_parameters import CryptoParameters


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
