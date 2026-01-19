#--- python HansCryptGuard.py

import customtkinter as ctk
from tkinter import messagebox, filedialog
import os
import threading
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

class MotorCripto:
    def __init__(self, callback_progresso=None):
        self.chunk_size = 1024 * 1024  # 1MB por pedaço
        self.callback_progresso = callback_progresso

    def _gerar_chave(self, senha: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=310000,
        )
        return kdf.derive(senha.encode())

    def processar(self, caminho, senha, is_encrypt):
        tamanho_total = os.path.getsize(caminho)
        lido = 0
        
        try:
            if is_encrypt:
                saida = caminho + ".lock"
                salt = os.urandom(16)
                nonce = os.urandom(12)
                chave = self._gerar_chave(senha, salt)
                aes = AESGCM(chave)
                
                with open(caminho, 'rb') as f_in, open(saida, 'wb') as f_out:
                    f_out.write(salt + nonce)
                    while True:
                        chunk = f_in.read(self.chunk_size)
                        if not chunk: break
                        f_out.write(aes.encrypt(nonce, chunk, None))
                        lido += len(chunk)
                        if self.callback_progresso:
                            self.callback_progresso(lido / tamanho_total)
                return saida
            else:
                # CORREÇÃO DE EXTENSÃO: Restaura o nome original
                if caminho.lower().endswith(".lock"):
                    saida = caminho[:-5]
                else:
                    saida = caminho + ".decrypted"
                
                # Evita sobrescrever o arquivo original se ele ainda existir
                if os.path.exists(saida):
                    nome, ext = os.path.splitext(saida)
                    saida = f"{nome}_restored{ext}"

                with open(caminho, 'rb') as f_in:
                    salt = f_in.read(16)
                    nonce = f_in.read(12)
                    lido = 28
                    chave = self._gerar_chave(senha, salt)
                    aes = AESGCM(chave)
                    
                    with open(saida, 'wb') as f_out:
                        while True:
                            chunk = f_in.read(self.chunk_size + 16)
                            if not chunk: break
                            f_out.write(aes.decrypt(nonce, chunk, None))
                            lido += len(chunk)
                            if self.callback_progresso:
                                self.callback_progresso(lido / tamanho_total)
                return saida
        except Exception:
            if 'saida' in locals() and os.path.exists(saida): 
                os.remove(saida)
            raise ValueError("Erro: Senha incorreta ou arquivo corrompido.")

class HansCryptoGuard(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.motor = MotorCripto(callback_progresso=self.atualizar_barra)
        self.caminho_alvo = None

        ctk.set_appearance_mode("dark")
        self.title("Hans Crypto Guard")
        self.geometry("480x650")
        self.configure(fg_color="#080808")

        # UI
        self.label_header = ctk.CTkLabel(self, text="HANS CRYPTO GUARD", font=("Orbitron", 24, "bold"), text_color="#ffffff")
        self.label_header.pack(pady=(50, 5))
        
        self.label_sub = ctk.CTkLabel(self, text="MILITARY GRADE FILE PROTECTION", font=("Consolas", 10), text_color="#00FF00")
        self.label_sub.pack(pady=(0, 40))

        self.btn_select = ctk.CTkButton(self, text="SELECT TARGET FILE", command=self.escolher, 
                                        fg_color="#111111", border_width=1, border_color="#00FF00",
                                        hover_color="#1a1a1a", height=55, text_color="#00FF00")
        self.btn_select.pack(fill="x", padx=50)

        self.label_nome_arq = ctk.CTkLabel(self, text="STATUS: WAITING SELECTION", font=("Consolas", 11), text_color="#444444")
        self.label_nome_arq.pack(pady=15)

        self.entry_pass = ctk.CTkEntry(self, placeholder_text="ENCRYPTION KEY", show="*", width=340, height=50,
                                       fg_color="#000000", border_color="#333333", justify="center")
        self.entry_pass.pack(pady=20)

        self.progress_bar = ctk.CTkProgressBar(self, width=340, height=6, fg_color="#111111", progress_color="#00FF00")
        self.progress_bar.set(0)
        self.progress_bar.pack(pady=20)
        self.progress_bar.pack_forget()

        self.btn_lock = ctk.CTkButton(self, text="EXECUTE LOCK", command=lambda: self.iniciar_thread(True), 
                                      fg_color="#00FF00", text_color="#000000", hover_color="#00CC00", height=50, font=("Inter", 13, "bold"))
        self.btn_lock.pack(pady=10, fill="x", padx=50)

        self.btn_unlock = ctk.CTkButton(self, text="EXECUTE UNLOCK", command=lambda: self.iniciar_thread(False), 
                                        fg_color="#000000", border_width=1, border_color="#ffffff", height=50, font=("Inter", 13, "bold"))
        self.btn_unlock.pack(pady=5, fill="x", padx=50)

    def escolher(self):
        self.caminho_alvo = filedialog.askopenfilename()
        if self.caminho_alvo:
            nome = os.path.basename(self.caminho_alvo)
            self.label_nome_arq.configure(text=f"READY: {nome.upper()}", text_color="#00FF00")
            self.progress_bar.set(0)

    def atualizar_barra(self, valor):
        self.progress_bar.set(valor)

    def iniciar_thread(self, is_lock):
        senha = self.entry_pass.get()
        if not self.caminho_alvo or not senha:
            messagebox.showwarning("System", "Select file and enter key.")
            return
        
        self.progress_bar.pack(pady=20)
        self.btn_lock.configure(state="disabled")
        self.btn_unlock.configure(state="disabled")
        
        threading.Thread(target=self.executar, args=(senha, is_lock), daemon=True).start()

    def executar(self, senha, is_lock):
        try:
            res = self.motor.processar(self.caminho_alvo, senha, is_lock)
            messagebox.showinfo("Success", f"File processed successfully:\n{os.path.basename(res)}")
        except Exception as e:
            messagebox.showerror("Security Error", str(e))
        finally:
            self.progress_bar.pack_forget()
            self.btn_lock.configure(state="normal")
            self.btn_unlock.configure(state="normal")
            self.entry_pass.delete(0, 'end')

if __name__ == "__main__":
    app = HansCryptoGuard()
    app.mainloop()