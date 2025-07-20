import os
from Crypto.Util.number import bytes_to_long, long_to_bytes

FLAG = os.environ.get("FLAG", "Alpaca{***** REDACTED *****}").encode()
assert len(FLAG) <= 30 and FLAG.startswith(b"Alpaca{") and FLAG.endswith(b"}") and all(0x20 <= c <= 0x7f for c in FLAG)

while True:
    try:
        if long_to_bytes(int(input("Guess the flag in integer: ")) - bytes_to_long(FLAG)).decode():
            print("Wrong flag. :P")
        else:
            print("Yay, you found the flag! :3")
    except:
        print("Weird... :/") 
