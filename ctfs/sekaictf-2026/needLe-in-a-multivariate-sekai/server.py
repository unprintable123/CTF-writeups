from sig import Signature

sig = Signature.load("./pk.sobj")

signature = list(map(int, input("Signature: ").split()))
if sig.verify(b"STAGE OF SEKAI", signature):
    print(open("flag.txt").read())
else:
    print("sorry")