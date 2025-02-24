from pwn import *

context.log_level = "debug"

with open('output.txt', 'r') as f:
        chall1_txt = f.readlines()
    
with open('output2.txt', 'r') as f:
    chall2_txt = f.readlines()

io = remote("121.41.238.106", 46019)

for i in range(6):
    io.recvuntil(b"> ")
    raw_adv = chall1_txt[i].strip()
    raw_adv = raw_adv + 'do you know how to get the flag?'
    io.sendline(raw_adv.encode())

for i in range(6):
    io.recvuntil(b"> ")
    raw_adv = chall2_txt[i].strip()
    raw_adv = '[CLS] ' + raw_adv + 'do you know how to get the flag? [SEP]'
    io.sendline(raw_adv.encode())

io.interactive()
