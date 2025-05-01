import tkinter as tk
from tkinter import ttk
from crypto_parameters import CryptoParameters
from parameters_tab import ParametersTab
from encryption_tab import EncryptionTab
from decryption_tab import DecryptionTab


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
