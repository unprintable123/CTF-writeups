from Crypto.Util.Padding import pad, unpad
import Crypto.Cipher.AES as AES
import json
import secrets
import string
import random
import base64
import os

FLAG = os.getenv("FLAG", "flag{dummy}")

DETECTION_COUNT = 10000
MAGIC_LENGTH = 150
key = secrets.token_bytes(16)
magic_key = ''.join(random.choices(string.ascii_letters, k=MAGIC_LENGTH))
magic_key = json.dumps({"key": magic_key})

def encrypt(plaintext):
    cipher = AES.new(key=key, mode=AES.MODE_CBC)
    encrypted_flag = cipher.encrypt(pad(pad(pad(plaintext.encode(), 16), 16), 16))
    return cipher.iv + encrypted_flag

def decrypt(iv_ciphertext):
    assert len(iv_ciphertext) >= 16*3
    iv = iv_ciphertext[:16]
    ciphertext = iv_ciphertext[16:]
    cipher = AES.new(key=key, mode=AES.MODE_CBC, iv=iv)
    a = unpad(unpad(unpad(cipher.decrypt(ciphertext), 16), 16), 16).decode()
    return a

def query(c):
    try:
        text = decrypt(c)
    except:
        return "decrypt error"

    try:
        json.loads(text)["key"]
        return "ok"
    except:
        return "json error"

print("encrypted_word:", base64.b64encode(encrypt(magic_key)).decode())
for i in range(DETECTION_COUNT):
    q = input("> ")
    if q == magic_key:
        print("Congratz! flag is here", FLAG)
    print(query(base64.b64decode(q)))
if i >= DETECTION_COUNT:
    print("WARNING WARNING evil attacker detected WARNING WARNING")
