import sqlite3 as sql
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import string

DB_NAME = "vault.db"
PBKDF2_ITERATIONS = 100_000
KEY_LEN = 32

def init_db():
    conn = sql.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""CREATE TABLE IF NOT EXISTS accounts(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    service TEXT NOT NULL,
    username TEXT NOT NULL,
    password BLOB NOT NULL
    )
    """)

    conn.commit()
    conn.close()


def add_account(service, username, password):
    conn = sql.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO accounts (service, username, password)
    VALUES (?, ?, ?)
    """, (service, username, password))

    conn.commit()
    conn.close()

def delete_account(service, username=None):
    conn = sql.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM accounts WHERE service = ?", (service,))
    count = cursor.fetchone()[0]

    if count == 0:
        print("Bu servis bulunamadı.")
    elif count == 1 and username is None:
        cursor.execute("DELETE FROM accounts WHERE service = ?", (service,))
        print(f"{service} servisine ait hesap silindi.")
    else:
        while True:
            if username is None:
                print(f"{service} için birden fazla hesap bulundu, username belirtmelisin: ")
                cursor.execute("SELECT id, service, username, password FROM accounts WHERE service = ?",(service,))
                rows = cursor.fetchall()
                for row in rows:
                    print(row[2])
                username = input()


            cursor.execute("DELETE FROM accounts WHERE service = ? AND username = ?", (service, username))

            if cursor.rowcount == 0:
                print(f"{service} için '{username}' kullanıcı adı bulunamadı.")
                username = None  
            else:
                print(f"{service} - {username} hesabı silindi.")
                break

    conn.commit()
    conn.close()


def list_accounts(service: str = None):
    conn = sql.connect(DB_NAME)
    cursor = conn.cursor()
    if service: 
        cursor.execute("SELECT service, username, password FROM accounts WHERE service=?", (service,))
    else:  
        cursor.execute("SELECT service, username, password FROM accounts")
    rows = cursor.fetchall()
    conn.close()
    return rows

def get_services():
    conn = sql.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT DISTINCT service FROM accounts")
    rows = [r[0] for r in cursor.fetchall()]
    conn.close()
    return rows

def create_master_password_db():
    conn = sql.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""CREATE TABLE IF NOT EXISTS master_key(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    salt BLOB NOT NULL,
    hash BLOB NOT NULL
    )
    """)

    conn.commit()
    conn.close()


def create_master_password(master_password: str):
    if len(master_password) < 8:
        raise ValueError("Şifre en az 8 karakter olmalı")
    if not any(c.isupper() for c in master_password):
        raise ValueError("Şifre en az bir büyük harf içermeli")
    if not any(c.islower() for c in master_password):
        raise ValueError("Şifre en az bir küçük harf içermeli")
    if not any(c.isdigit() for c in master_password):
        raise ValueError("Şifre en az bir rakam içermeli")
    if not any(c in string.punctuation for c in master_password):
        raise ValueError("Şifre en az bir özel karakter içermeli")

    salt = get_random_bytes(16)
    hash_pw = PBKDF2(master_password, salt, dkLen=KEY_LEN, count=PBKDF2_ITERATIONS)

   
    conn = sql.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO master_key (salt, hash) VALUES (?, ?)", (salt, hash_pw))
    conn.commit()
    conn.close()

def verify_master_password(entered_password: str) -> bool:
    conn = sql.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("SELECT salt, hash FROM master_key LIMIT 1")
    row = cursor.fetchone()
    conn.close()

    if row is None:
        return False  

    salt, stored_hash = row
    entered_hash = PBKDF2(entered_password, salt, dkLen=KEY_LEN, count=PBKDF2_ITERATIONS)

    return entered_hash == stored_hash

