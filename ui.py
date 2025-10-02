import pwinput
import sqlite3 as sql
import secrets
import string

def create_private_key():
    while True:
        password = pwinput.pwinput("Ana şifrenizi oluşturunuz: ", mask="*")
        check_password = pwinput.pwinput("Şifreyi bir daha giriniz: ", mask="*")
        
        if password != check_password:
            print("Şifreler uyuşmadı, tekrar deneyiniz.")
        if len(password) < 8:
            print("Uyarı: Daha güçlü bir şifre seçiniz (en az 8 karakter).")
            continue
        return password

def generate_strong_password(length: int = 16) -> str:
    if length < 8:
        raise ValueError("Parola uzunluğu en az 8 olmalı.")
    alphabet_lower = string.ascii_lowercase
    alphabet_upper = string.ascii_uppercase
    digits = string.digits
    symbols = "!@#$%^&*()-_=+[]{};:,.<>?/|\\"

    # en az bir tane her gruptan ekleyelim
    password_chars = [
        secrets.choice(alphabet_lower),
        secrets.choice(alphabet_upper),
        secrets.choice(digits),
        secrets.choice(symbols),
    ]

    # kalan karakterleri rastgele doldur
    all_chars = alphabet_lower + alphabet_upper + digits + symbols
    for _ in range(length - len(password_chars)):
        password_chars.append(secrets.choice(all_chars))

    # karıştır ve stringe çevir
    secrets.SystemRandom().shuffle(password_chars)
    return ''.join(password_chars)