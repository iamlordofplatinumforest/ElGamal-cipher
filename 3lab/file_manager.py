from typing import List, Tuple


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
