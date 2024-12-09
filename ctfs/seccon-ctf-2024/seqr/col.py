from sage.all import *
from pwn import *

p = prod(prime_range(3, 196))

f = open("output.txt", "wb")

# io = process(["python3", "server.py"])
# nc seqr.seccon.games 13337
io = remote("seqr.seccon.games", 13337)
io.sendlineafter("> ", hex(p))

io.sendlineafter("> ", b"3")
f.write(io.recvline())
io.sendlineafter("> ", b"2")
f.write(io.recvline())

for i in range(3333):
    if i % 100 == 0:
        io.send(b"1\n00\n"*100)
    io.recvuntil("> ")
    f.write(io.recvline())
    if i % 100 == 0:
        f.flush()
        print(i)


f.close()
