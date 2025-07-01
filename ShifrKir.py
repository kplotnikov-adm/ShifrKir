# -*- coding: utf-8 -*-
import tkinter as tk
from tkinter import messagebox, scrolledtext, font, filedialog

DELTA = 0x9e3779b9
NUM_ROUNDS = 32

def encrypt_block(v, k):
    v0, v1 = v
    sum = 0
    for _ in range(NUM_ROUNDS):
        sum = (sum + DELTA) & 0xffffffff
        v0 = (v0 + (((v1 << 4) + k[0]) ^ (v1 + sum) ^ ((v1 >> 5) + k[1]))) & 0xffffffff
        v1 = (v1 + (((v0 << 4) + k[2]) ^ (v0 + sum) ^ ((v0 >> 5) + k[3]))) & 0xffffffff
    return [v0, v1]

def decrypt_block(v, k):
    v0, v1 = v
    sum = (DELTA * NUM_ROUNDS) & 0xffffffff
    for _ in range(NUM_ROUNDS):
        v1 = (v1 - (((v0 << 4) + k[2]) ^ (v0 + sum) ^ ((v0 >> 5) + k[3]))) & 0xffffffff
        v0 = (v0 - (((v1 << 4) + k[0]) ^ (v1 + sum) ^ ((v1 >> 5) + k[1]))) & 0xffffffff
        sum = (sum - DELTA) & 0xffffffff
    return [v0, v1]

def str_to_blocks(data):
    data = data.encode('utf-8')
    while len(data) % 8 != 0:
        data += b'\x00'
    return [[int.from_bytes(data[i:i+4], 'big'), int.from_bytes(data[i+4:i+8], 'big')] for i in range(0, len(data), 8)]

def blocks_to_str(blocks):
    data = b''.join([v0.to_bytes(4, 'big') + v1.to_bytes(4, 'big') for v0, v1 in blocks])
    return data.rstrip(b'\x00').decode('utf-8', errors='ignore')

class ShifrKirGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("ShifrKir - TEA шифрование")
        self.root.geometry("700x550")
        self.root.configure(bg="#2e3440")  # Темный фон

        self.key = [0x12345678, 0x9abcdef0, 0x0fedcba9, 0x87654321]

        # Шрифты
        self.title_font = font.Font(family="Segoe UI", size=14, weight="bold")
        self.text_font = font.Font(family="Consolas", size=11)
        self.button_font = font.Font(family="Segoe UI", size=11, weight="bold")

        # Метка для ввода
        self.label_input = tk.Label(root, text="Введите текст для шифрования:", fg="#d8dee9", bg="#2e3440", font=self.title_font)
        self.label_input.pack(anchor="w", padx=20, pady=(15,5))

        # Текстовое поле для ввода
        self.input_text = scrolledtext.ScrolledText(root, height=7, width=80, font=self.text_font, bg="#3b4252", fg="#eceff4", insertbackground="white")
        self.input_text.pack(padx=20, pady=(0, 15))

        # Контейнер для кнопок шифрования/расшифровки
        self.button_frame = tk.Frame(root, bg="#2e3440")
        self.button_frame.pack(pady=10)

        self.encrypt_button = tk.Button(self.button_frame, text="🔐 Зашифровать", bg="#5e81ac", fg="white",
                                        activebackground="#81a1c1", activeforeground="white",
                                        font=self.button_font, width=15, command=self.encrypt, relief="flat")
        self.encrypt_button.grid(row=0, column=0, padx=10)

        self.decrypt_button = tk.Button(self.button_frame, text="🔓 Расшифровать", bg="#a3be8c", fg="#2e3440",
                                        activebackground="#b48ead", activeforeground="#2e3440",
                                        font=self.button_font, width=15, command=self.decrypt, relief="flat")
        self.decrypt_button.grid(row=0, column=1, padx=10)

        # Новый контейнер для кнопок загрузки и сохранения
        self.file_button_frame = tk.Frame(root, bg="#2e3440")
        self.file_button_frame.pack(pady=10)

        self.load_button = tk.Button(self.file_button_frame, text="📂 Загрузить из файла", bg="#88c0d0", fg="#2e3440",
                                     activebackground="#81a1c1", activeforeground="#2e3440",
                                     font=self.button_font, width=20, command=self.load_file, relief="flat")
        self.load_button.grid(row=0, column=0, padx=10)

        self.save_button = tk.Button(self.file_button_frame, text="💾 Сохранить результат", bg="#8fbcbb", fg="#2e3440",
                                     activebackground="#81a1c1", activeforeground="#2e3440",
                                     font=self.button_font, width=20, command=self.save_file, relief="flat")
        self.save_button.grid(row=0, column=1, padx=10)

        # Метка для вывода результата
        self.label_output = tk.Label(root, text="Результат:", fg="#d8dee9", bg="#2e3440", font=self.title_font)
        self.label_output.pack(anchor="w", padx=20, pady=(20,5))

        # Текстовое поле для вывода
        self.output_text = scrolledtext.ScrolledText(root, height=7, width=80, font=self.text_font, bg="#3b4252", fg="#eceff4", insertbackground="white")
        self.output_text.pack(padx=20, pady=(0, 20))

        self.encrypted_blocks = []

    def encrypt(self):
        text = self.input_text.get("1.0", tk.END).strip()
        if not text:
            messagebox.showwarning("Пусто", "Введите текст для шифрования.")
            return

        blocks = str_to_blocks(text)
        self.encrypted_blocks = [encrypt_block(block, self.key) for block in blocks]

        result = "\n".join(f"{b[0]}, {b[1]}" for b in self.encrypted_blocks)
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert(tk.END, result)

    def decrypt(self):
        if not self.encrypted_blocks:
            messagebox.showwarning("Нет данных", "Сначала зашифруйте текст.")
            return

        decrypted_blocks = [decrypt_block(block, self.key) for block in self.encrypted_blocks]
        text = blocks_to_str(decrypted_blocks)

        self.output_text.delete("1.0", tk.END)
        self.output_text.insert(tk.END, text)

    def load_file(self):
        filepath = filedialog.askopenfilename(title="Выберите файл для загрузки", 
                                              filetypes=[("Текстовые файлы", "*.txt"), ("Все файлы", "*.*")])
        if not filepath:
            return
        try:
            with open(filepath, "r", encoding="utf-8") as file:
                content = file.read()
            self.input_text.delete("1.0", tk.END)
            self.input_text.insert(tk.END, content)
            messagebox.showinfo("Успех", "Файл успешно загружен.")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось загрузить файл:\n{e}")

    def save_file(self):
        content = self.output_text.get("1.0", tk.END).strip()
        if not content:
            messagebox.showwarning("Пусто", "Нет данных для сохранения.")
            return
        filepath = filedialog.asksaveasfilename(title="Сохранить результат как", defaultextension=".txt",
                                                filetypes=[("Текстовые файлы", "*.txt"), ("Все файлы", "*.*")])
        if not filepath:
            return
        try:
            with open(filepath, "w", encoding="utf-8") as file:
                file.write(content)
            messagebox.showinfo("Успех", "Результат успешно сохранён.")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось сохранить файл:\n{e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = ShifrKirGUI(root)
    root.mainloop()
