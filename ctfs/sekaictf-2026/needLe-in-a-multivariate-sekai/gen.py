from sig import Signature

sig = Signature()
sig.keygen()
sig.save("pk.sobj", "sk.sobj")

with open("output.txt", "w") as f:
    print([sig.sign(f"message {i}".encode()) for i in range(200)], file=f)