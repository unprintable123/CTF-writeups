from pwn import *
from Crypto.Util.number import *

# io = process(['python3', 'task.py'])
# tcp 121.41.238.106:56146
io = remote('121.41.238.106', 56146)


def round(test_num=200):

    io.recvuntil("💵".encode())
    io.sendline(b"00"*16*(test_num+1))

    io.recvuntil("🎩".encode())

    ct = io.recvline().strip().decode()
    ct = bytes.fromhex(ct)

    cnt = {i:0 for i in range(17)}

    for i in range(test_num):
        L0 = ct[16*i:16*i+8]
        R0 = ct[16*i+8:16*i+16]
        L1 = ct[16*(i+1):16*(i+1)+8]
        R1 = ct[16*(i+1)+8:16*(i+1)+16]
        l_mod = (bytes_to_long(L0)-bytes_to_long(L1))%17
        r_mod = (bytes_to_long(R0)-bytes_to_long(R1))%17
        cnt[l_mod] += 1
        cnt[r_mod] += 1
    
    print(cnt)

    if cnt[8]+cnt[9]+cnt[10]>test_num*0.05:
        io.sendline(b"1")
    else:
        io.sendline(b"0")


for _ in range(100):
    round(100)

io.interactive()
