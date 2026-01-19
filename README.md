# 🔒 Hans Crypto Guard (v1.0)

**Desenvolvido por: RAM**

O **Hans Crypto Guard** é uma solução robusta e minimalista para proteção de dados sensíveis. Projetado para oferecer segurança de nível militar com uma interface moderna e intuitiva inspirada no Google Gemini.

---

## 🚀 Funcionalidades

- **Criptografia Híbrida:** Utiliza o algoritmo **AES-GCM (256-bit)**, garantindo não apenas o sigilo, mas também a integridade dos seus arquivos.
- **Processamento em Chunks:** Capaz de criptografar vídeos e arquivos gigantes (10GB+) sem consumir excessivamente a memória RAM.
- **Identidade Digital:** Assinatura visual de autoria (RAM) e integridade verificável via Hash SHA-256.
- **Interface Moderna:** Design escuro, minimalista e fluido, com opção de visualização de senha e barra de progresso em tempo real.
- **Zero-Footprint:** Desenvolvido pensando na portabilidade, ideal para uso em ambientes como o Tails OS.

## 🛠️ Especificações Técnicas

- **Linguagem:** Python 3.x
- **Bibliotecas Base:** `cryptography`, `customtkinter`
- **Algoritmo de Derivação de Chave:** PBKDF2HMAC (SHA-256) com 310.000 iterações.
- **Modo de Operação:** AES-GCM (Authenticated Encryption with Associated Data).

---

## 🛡️ Verificação de Autenticidade

Para garantir que você está utilizando a versão oficial e inalterada do Hans Crypto Guard, verifique o Hash SHA-256 do executável.

**Hash Oficial (v1.0):**
`c2cbcd8057401773c599551b378e5f57f062bb3668c82b71e31fab8df8932873`

### Como verificar no Windows:
1. Abra o Terminal (PowerShell ou CMD).
2. Navegue até a pasta do arquivo e digite:
   ```cmd
   certutil -hashfile HansCryptoGuard.exe SHA256
Excelente escolha. O arquivo README.md é o que transforma um simples repositório em um projeto respeitado. Ele funciona como o manual de instruções e a vitrine do seu trabalho.

Aqui está um modelo profissional, escrito em Markdown, focado em segurança e transparência, seguindo a estética minimalista do seu projeto:

Markdown

# 🔒 Hans Crypto Guard (v1.0)

**Desenvolvido por: RAM**

O **Hans Crypto Guard** é uma solução robusta e minimalista para proteção de dados sensíveis. Projetado para oferecer segurança de nível militar com uma interface moderna e intuitiva.

---

## 🚀 Funcionalidades

- **Criptografia Híbrida:** Utiliza o algoritmo **AES-GCM (256-bit)**, garantindo não apenas o sigilo, mas também a integridade dos seus arquivos.
- **Processamento em Chunks:** Capaz de criptografar vídeos e arquivos gigantes (10GB+) sem consumir excessivamente a memória RAM.
- **Identidade Digital:** Assinatura visual de autoria (RAM) e integridade verificável via Hash SHA-256.
- **Interface Moderna:** Design escuro, minimalista e fluido, com opção de visualização de senha e barra de progresso em tempo real.
- **Zero-Footprint:** Desenvolvido pensando na portabilidade, ideal para uso em ambientes como o Tails OS.

## 🛠️ Especificações Técnicas

- **Linguagem:** Python 3.x
- **Bibliotecas Base:** `cryptography`, `customtkinter`
- **Algoritmo de Derivação de Chave:** PBKDF2HMAC (SHA-256) com 310.000 iterações.
- **Modo de Operação:** AES-GCM (Authenticated Encryption with Associated Data).

---

## 🛡️ Verificação de Autenticidade

Para garantir que você está utilizando a versão oficial e inalterada do Hans Crypto Guard, verifique o Hash SHA-256 do executável.

**Hash Oficial (v1.0):**
`c2cbcd8057401773c599551b378e5f57f062bb3668c82b71e31fab8df8932873`

### Como verificar no Windows:
1. Abra o Terminal (PowerShell ou CMD).
2. Navegue até a pasta do arquivo e digite:
  cmd certutil -hashfile HansCryptoGuard.exe SHA256
Compare o código gerado com o Hash oficial acima.

📖 Como Usar
Selecionar: Clique em "Escolher arquivo" e selecione qualquer tipo de arquivo (.mp4, .pdf, .zip, etc).

Senha: Digite uma chave secreta forte. Use o ícone de olho (👁) para conferir a digitação.

Bloquear: Clique em "Bloquear" para gerar o arquivo .lock.

Desbloquear: Para restaurar, selecione o arquivo .lock, digite a senha e clique em "Desbloquear".

⚖️ Licença e Contato
Este software é um projeto privado desenvolvido por RAM. O código é disponibilizado para fins de estudo e auditoria de segurança.

Para suporte ou contato, utilize os canais disponibilizados no site oficial.
