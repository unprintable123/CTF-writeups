import random
import signal

signal.alarm(600)
import xxhash

MIN_PAYLOAD_LEN = 256
TARGET_DIGEST = b"Give me the flag"


class XXH3Challenge:
    def __init__(self):
        self.seed = random.getrandbits(64)

    def _read_hex_data(self, prompt: str) -> bytes:
        try:
            hex_str = input(prompt).strip()
            return bytes.fromhex(hex_str)
        except ValueError:
            print("[-] Invalid hex format.")
            return b""

    def hash_mode(self):
        data = self._read_hex_data("[*] Enter data (hex): ")
        if not data:
            return
        if len(data) <= MIN_PAYLOAD_LEN:
            print(
                f"[-] Data length must be strictly greater than {MIN_PAYLOAD_LEN} bytes."
            )
            return

        h = xxhash.xxh3_128(data, seed=self.seed).hexdigest()
        print(f"[+] Hash: {h}")

    def flag_mode(self):
        data = self._read_hex_data("[*] Enter data (hex): ")
        if not data:
            return
        if len(data) <= MIN_PAYLOAD_LEN:
            print(
                f"[-] Payload length must be strictly greater than {MIN_PAYLOAD_LEN} bytes."
            )
            return

        if xxhash.xxh3_128(data, seed=self.seed).digest() == TARGET_DIGEST:
            print("[+] Target verified.", open("flag.txt").read())
            exit()
        else:
            print("[-] Verification failed. Digest does not match target.")

    def run(self):
        while True:
            print("  1. Hash")
            print("  2. Get Flag")
            print("  3. Exit")
            choice = input("> ").strip()
            if choice == "1":
                self.hash_mode()
            elif choice == "2":
                self.flag_mode()
            elif choice == "3":
                print("[*] Goodbye.")
                break
            else:
                print("[-] Invalid choice.")


if __name__ == "__main__":
    challenge = XXH3Challenge()
    challenge.run()
