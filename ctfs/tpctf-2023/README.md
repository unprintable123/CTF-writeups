# TPCTF2023

这次比赛是团体比赛，但是由于实在没人所以和 JOHNKRAM 合作把 crypto 给 AK 了。接下来只会写 crypto 部分的解题思路。

### blurred memory

可以看见这道题给出了 k 次幂的和，所以我们可以构造出任意多项式的累和，这里选择$\prod(x-x_i)$来使得只有一个数赋值不是零。

<details>
<summary>Code</summary>

```python
output = [125, 31, 116, 106, 193, 7, 38, 194, 186, 33, 180, 189, 53, 126, 134, 237, 123, 65, 179, 196, 99, 74, 101, 153, 84, 74, 233, 5, 105, 32, 75, 168, 161, 2, 147, 18, 68, 68, 162, 21, 94, 194, 249, 179, 24, 60, 71, 12, 40, 198, 79, 92, 44, 72, 189, 236, 244, 151, 56, 93, 195, 121, 211, 26, 73, 240, 76, 70, 133, 186, 165, 48, 31, 39, 3, 219, 96, 14, 166, 139, 24, 206, 93, 250, 79, 246, 256, 199, 198, 131, 34, 192, 173, 35, 0, 171, 160, 151, 118, 24, 10, 100, 93, 19, 101, 15, 190, 74, 10, 117, 4, 41, 135, 45, 107, 155, 152, 95, 222, 214, 174, 139, 117, 211, 224, 120, 219, 250, 1, 110, 225, 196, 105, 96, 52, 231, 59, 70, 95, 56, 58, 248, 171, 16, 251, 165, 54, 4, 211, 60, 210, 158, 45, 96, 105, 116, 30, 239, 96, 37, 175, 254, 157, 26, 151, 141, 43, 110, 227, 199, 223, 135, 162, 112, 4, 45, 66, 228, 162, 238, 165, 158, 27, 18, 76, 36, 237, 107, 84, 57, 233, 96, 72, 6, 114, 44, 119, 174, 59, 82, 202, 26, 216, 35, 55, 159, 113, 98, 4, 74, 2, 128, 34, 180, 191, 8, 101, 169, 157, 120, 254, 158, 97, 227, 79, 151, 167, 64, 195, 42, 250, 207, 213, 238, 199, 111, 149, 18, 194, 240, 53, 130, 3, 188, 41, 100, 255, 158, 21, 189, 19, 214, 127]

print(len(output))

import numpy
from sympy import Matrix, mod_inverse
import base64
p = 257


def product(a, b):
    c = [0] * (len(a) + len(b) - 1)
    for i in range(len(c)):
        for j in range(i + 1):
            if j < len(a) and i - j < len(b):
                c[i] += a[j] * b[i - j]
        c[i] %= p
    return c


def check(a):
    poly = [1]
    auto = 1
    for i in range(10, 130):
        if i == a:
            continue
        else:
            poly = product(poly, [-i, 1])
            auto = (auto * (a - i)) % p
    # print(poly)
    d = mod_inverse(auto, p)
    # print(d)
    v = 0
    for i in range(len(poly)):
        if i == 0:
            v += poly[0] * 253
        else:
            v += poly[i] * output[i - 1]
            v %= p
    v *= d
    v %= p
    return v


answer = [None] * 22

for i in range(10, 130):
    v = check(i)
    if v != 0:
        answer[v - 1] = chr(i)
print(answer)
print("".join(answer))
```

</details>

# matrix

~~这啥玩意啊~~  
这道题需要在一堆矩阵里找规律。由于是连乘，第一步是去思考这个东西能不能变换得好看一些。所以去 wolframalpha 看了一下特征值，发现全是 16 的幂，而且它们有着共同的特征向量。  
（在折磨了几个小时后）找出了三个共同的特征向量，左边的两个是`(2,9,7),(1,5,4)`，右边的是`(1,-1,1)`。  
在对原式化简后，得到$(1,1,1)Mv=(79+256x)16^t$。  
然后两个人就对这个`(1,1,1)`束手无策了几个小时。  
在研究依靠特征向量的矩阵恢复时，总是差两个线性方程，左边也有一个特征向量不确定。  
这时突发奇想把`[[1,1,1],[2,9,7],[1,5,4]]`扔进去求逆，发现里面有一维是`(1,-1,1)`，于是把每个矩阵这么变换一下发现是一个上三角，而且不确定的两位刚好是两个 16 进制的字符串拼接，于是就能做了。剩下的步骤脑子烧了+代码写了一堆 bug，故是由 JOHNKRAM 完成的。  
以下是我抄了结论写的代码。

<details>
<summary>Code</summary>

```python
v = "111101101010100101001001110111011100101000010100011110001001000111100110101011001001101010111010010101001"
s = ""
u = list([i for i in range(105)])

end = 105


def update():
    global end
    global u
    t = [-1] * 105
    for i in range(105):
        if i >= end:
            t[i] = u[i]
    for i in range(end):
        if end % 2 == 0:
            if i % 2 == 0:
                t[i // 2] = u[i]
            else:
                t[end - (i + 1) // 2] = u[i]
        else:
            t[0] = u[end - 1]
            if i % 2 == 0:
                if i != end - 1:
                    t[(i // 2) + 1] = u[i]
            else:
                t[end - (i + 1) // 2] = u[i]
    u = t
    end = (end + 1) // 2
    print(u)
    print(end)


update()
update()
update()
update()
update()
update()
update()
update()
update()
update()
for i in range(105):
    for j in range(105):
        if u[j] == i:
            s += v[j]
print(s)

# undec1dab1e_PcP
```

</details>

### sort

全是非预期解的一道题。  
首先是 teaser。这道题是简单侧信道。代码已经被改成 sort2 的了故没有。  
接下来是 sort2。出题人竟然只修了 level1 的洞，虽然前面加强了限制，但办法总是有的。  
首先前面的检查可以直接判断长度绕过去。其次是 10 次`TPCTF`开头的，其中只有一次是我们想要的。这里选择了 mod 一个数利用第一个数列不变来维持哈希，然后把这个值爆破出来。之后就可以快乐的一位一位爆破了。只需要让那个数列只有在猜对时才是同一个值就行。

<details>
<summary>Code</summary>

```python
from pwn import *
import time

k = 29


def getresponse(payload):
    io = remote("202.112.238.82", 13372)
    io.sendline(b"2")
    time.sleep(0.01)
    io.send(payload.encode())
    io.sendline(b"EOF")

    p = io.recvuntil("AssertionError")
    # print(payload)
    # io.interactive()
    return p


def guess(a, b):
    payload = (
        """F=A>>200
F=F==0
U=5525571
U=U<<24
U=U+18043
T=84<<16
U=U+T
E=A>>184
D=E==U
E=A>>176
E=A%503
E=E==376
D=D&E
T=A>>200
E=T==U
B=A>>{}
B=B&255
B=B*D
E=E*A
B=B+E
D=1-D
C={}*D
B=B+C
P=A*F
B=B+P
EOF"""
        + "\n"
    )
    payload = payload.format(224 - 8 * j, b)
    # print(payload)
    p = getresponse(payload)
    if b"results are not same" in p:
        return 0
    if b"run_commands" in p:
        return 1


s = ""


def check():
    p = 503
    global s
    for i in range(p):
        payload = """F=A>>200
F=F==0
U=5525571
U=U<<24
U=U+18043
T=84<<16
U=U+T
E=A>>184
D=E==U
E=A>>176
E=A%{}
E=E=={}
D=D&E
T=A>>200
E=T==U
B=A>>120
B=B&255
B=B*D
E=E*A
B=B+E
D=1-D
C=0*D
B=B+C
P=A*F
B=B+P
EOF""".format(
            p, i
        )
        payload += "\n"
        er = getresponse(payload)
        if b"run_commands" in er:
            continue
        er = getresponse(payload)
        if b"run_commands" in er:
            continue
        er = getresponse(payload)
        if b"run_commands" in er:
            continue
        s += str(i) + "  "


# check()
# 503, 376

# s = "TPCTF{A_strAnge_s1de_channel}"
s = "TPCTF{13hm3r_c0d3_1s_4w3s0m3}"

for j in range(k):
    if j < len(s):
        continue
    for i in range(33, 127):
        b = guess(j, i)
        if b:
            s += chr(i)
        # print(i, "   ", b)
    print(s)
print(s)
with open("a.txt", "w") as fp:
    fp.write(s)

```

</details>

接下来回来正经做 sort1。  
出题人的本意肯定是用桶排序做，但是这里选择了一个更加离谱的方案，就是冒泡排序(?)。当然是同时对一堆相邻对交换，不然就太慢了。具体做法是检查作差时有没有借位，然后只把那些没有的取出来更新。

<details>
<summary>Code</summary>

```python
import os

output = []
os.chdir(os.path.dirname(__file__))
k = 40

def add(s):
    output.append(s)

def flush():
    print("output...")
    with open("sort1.txt", "w") as fp:
        for s in output:
            fp.write(s)
            fp.write("\n")
        fp.write("EOF")

def bubble(type):
    if type == 0:
        add("P=C+X")
        add("P=P*255")
        add("P=P+U")
        add("W=S&P")
        add("W=S-W")
        add("K=W>>7")
        add("K=K*255")
        add("K=K&P")
        add("K=W-K")
        add("C=C-K")
        add("K=K>>8")
        add("C=C+K")
    if type == 1:
        add("P=C+Y")
        add("P=P*255")
        add("P=P+V")
        add("W=T&P")
        add("W=T-W")
        add("K=W>>7")
        add("K=K*255")
        add("K=K&P")
        add("K=W-K")
        add("C=C-K")
        add("K=K>>8")
        add("C=C+K")

def main():
    add(f"T=2<<{8*k-1}")
    add("P=T-1")
    add("O=P/255")
    add(f"X=P/{0xffff}")
    add("X=X>>1")
    add("U=X<<1")
    add("Y=X>>8")
    add("V=Y<<1")
    add("C=A+O")
    add("S=X<<8")
    add("T=Y<<8")
    for i in range(16):
        bubble(0)
        bubble(1)
    # bubble(1)
    add("B=C-O")
    flush()

main()
```

</details>

最后花了 397 行，优化难度极大，肯定没法拿去做 2。2 的正经做法应该是只储存第几个，但怎么写估计都不是 100 行能写完的。

### nanoOTP

最后的一道 crypto。  
这道题的加密有两层，内层是对每一位重排并且异或一个数。外层是对整个数列重排。而解密函数对长度和 token 做了限制，想要获得 token 的信息必须长度不一样。  
内层是简单的，实在不行直接把整个随机生成弄出来都能做。虽然最后 JOHNKRAM 的做法没有这么干（似乎是用了 getrandbits 的舍去性质）  
外层是最麻烦的。长度变化会导致整个序列全部变化，而且 getbelow 还会随机丢数，导致获得的序列不是完整的。而且 token0 也会被重排，这导致

<details>
<summary>Code</summary>

```python
from pwn import *
import random
import time

# io = remote("202.112.238.82", 23382)
io = process(["python3", "nanoOTP.py"])
print(io.recvline())
hashc = input("Give me XXXX: ")
io.sendline(hashc.encode())
print(io.recvuntil(b"flag: "))
flag_encrypted = io.recvline().strip()
print(flag_encrypted)

flag_1, token_1 = flag_encrypted[:-8], flag_encrypted[-8:]
last_query = None
count = 0


def getrandomlist1():
    global last_query
    k = 1019
    buffer = b"0" * k
    io.sendline(b"0")
    io.sendline(buffer)
    io.recvuntil(b"encrypted message:")
    en1 = bytes.fromhex(io.recvline().strip().decode())

    en1, t0 = en1[:-4], en1[-4:]
    en1 = b"C" * len(en1)
    t0 = t0.hex().encode()
    en1 = bytearray(en1)

    def request(payload: bytearray, token: bytes, quiet=True):
        global count
        count += 1
        payload = bytes(payload).hex().encode()
        if not quiet:
            print(payload)
        io.recvuntil(b"rebuild\n")
        io.sendline(b"1")
        io.sendline(payload + token)
        io.recvline()
        text = b""
        output = io.recvline()
        return text + output

    def gettoken0():
        location = set()
        s = None
        for i in range(33, 126):
            s = bytearray((chr(i) * len(en1)).encode())
            p = request(s, token_1).decode()
            p = int(p.split("invalid characters: pos ")[1].strip())
            if p == 4:
                break
        for i in range(len(s)):
            ch = [0x1, 0x2, 0x4, 0x8, 0x10, 0x20]
            count = 0
            fail = 0
            c = s.copy()
            for t in ch:
                c[i] = s[i] ^ t
                o1 = request(c, token_1).decode()
                # print(o1)
                p2 = int(o1.split("invalid characters: pos ")[1].strip())
                if p2 != p:
                    count += 1

                else:
                    fail += 1
                if fail >= 3:
                    break
            if count >= 4:
                location.add(i)
        return location

    location = gettoken0()
    assert len(location) == 4, location
    print(location)

    overwrite = {}
    for i in location:
        overwrite[i] = en1[i] + 5
    shuffle_list = [None] * len(en1)
    location = list(location)
    shuffle_list[-1] = location[0]
    shuffle_list[-2] = location[1]
    shuffle_list[-3] = location[2]
    shuffle_list[-4] = location[3]

    def trycrack(s: bytearray, quiet=True):
        for ind in overwrite:
            s[ind] = overwrite[ind]
        p = request(s, token_1, quiet).decode()
        if not quiet:
            print(p)
        if "invalid characters: pos " in p:
            return int(p.split("invalid characters: pos ")[1].strip())
        if "original message:" in p:
            return len(en1) + 1000

    last_query = (trycrack(en1), en1.copy())

    def brute(index: int):
        # assume the position before the value has been determined
        global last_query
        assert trycrack(last_query[1]) >= last_query[0]
        if last_query[0] <= index:
            v = [
                0xFF,
                0xF0,
                0xF,
                0x33,
                0x55,
                0x66,
                0x99,
                0xAA,
                0x7C,
                0xC9,
                0x72,
                0xDB,
                0xBE,
            ]
            for t in v:
                s = last_query[1].copy()
                for i in range(len(s)):
                    s[i] = s[i] ^ t
                result = trycrack(s)
                # print(t, result)
                if result > index:
                    last_query = (result, s.copy())
                    break
        else:
            pass

        def bs(a, b):
            while a <= b:
                if a in overwrite:
                    a += 1
                else:
                    break
            while a <= b:
                if b in overwrite:
                    b -= 1
                else:
                    break
            if not a <= b:
                return -1
            if a == b:
                return a
            m = (a + b) // 2
            s = last_query[1].copy()
            for i in range(a, m + 1):
                s[i] ^= 0xFF
            result = trycrack(s)
            if result <= index:
                return bs(a, m)
            else:
                return bs(m + 1, b)

        pos = bs(0, len(en1) - 1)
        shuffle_list[index] = pos
        overwrite[pos] = last_query[1][pos]

    for j in range(len(en1) - 4):
        brute(j)
    print("query count: ", count)
    return shuffle_list


def work(enc_flag: bytes, conn: tube) -> str:
    import string

    valid_char = [
        ord(x) for x in string.digits + string.ascii_letters + string.punctuation
    ]
    fully_char = [
        c for c in valid_char if all((c ^ (1 << i)) in valid_char for i in range(7))
    ]
    enc_flag, fake_token0 = enc_flag[:-4], enc_flag[-4:]
    n = len(enc_flag)

    def recvline():
        return conn.recvline().decode().strip()

    def encrypt(s: str) -> bytes:
        global count
        count += 1
        conn.sendlineafter(b"> ", b"0")
        conn.sendlineafter(b"> ", s.encode())
        conn.recvuntil(b": ")
        return bytes.fromhex(recvline())

    def decrypt(c: bytes) -> str | int:
        global count
        count += 1
        conn.sendlineafter(b"> ", b"1")
        conn.sendlineafter(b"> ", c.hex().encode())
        r = recvline()
        if r.startswith("original message: "):
            return r.replace("original message: ", "")
        else:
            assert r.startswith(
                "The original message contains invalid characters: pos "
            )
            return int(
                r.replace("The original message contains invalid characters: pos ", "")
            )

    def gen_token1(n: int):
        msg = "a" * n
        c = encrypt(msg)
        c, token1 = c[:-4], c[-4:]
        n1 = n + 4
        p = [-1] * n1
        n0 = n
        for i in range(n1):
            a = [(-1, -1)] * 8
            for j in range(8):
                c1 = bytearray(c)
                c1[i] ^= 1 << j
                r = decrypt(bytes(c1) + token1)
                if isinstance(r, str):
                    p[[t for t in range(n) if r[t] != "a"][0]] = i
                    break
            else:
                p[n0] = i
                n0 += 1
        return token1, p

    from itertools import permutations
    import random

    def gen_c(c0: bytearray, token0: bytes, token1: bytes, p: list[int]):
        c = c0 + token0
        c1 = bytearray(len(c))
        for i in range(len(c)):
            c1[p[i]] = c[i]
        return bytes(c1) + token1

    def gen_t0(l: int, token0: bytes, token1: bytes, p: list[int]):
        c0 = bytearray(l)
        x = bytearray(l)
        while True:
            r = decrypt(gen_c(c0, token0, token1, p))
            if isinstance(r, str):
                break
            else:
                c0[r] = random.randbytes(1)[0]
        p1 = [[-1] * 8 for _ in range(l)]
        for i in range(l):
            while True:
                if isinstance(r, str) and ord(r[i]) in fully_char:
                    break
                c0[i] = random.randbytes(1)[0]
                r = decrypt(gen_c(c0, token0, token1, p))
            for j in range(8):
                c0[i] ^= 1 << j
                r1 = decrypt(gen_c(c0, token0, token1, p))
                if isinstance(r1, str):
                    p1[i][j] = (ord(r[i]) ^ ord(r1[i])).bit_length() - 1
                else:
                    p1[i][j] = 7
                c0[i] ^= 1 << j
                x[i] |= ((c0[i] >> j ^ ord(r[i]) >> p1[i][j]) & 1) << p1[i][j]
            assert sorted(p1[i]) == list(range(8))
        return bytes(x), p1

    def check(l: int, n: int):
        nonlocal enc_flag
        token1, p = gen_token1(l)
        for t0 in permutations(fake_token0):
            token0 = bytes(t0)
            x, p1 = gen_t0(l, token0, token1, p)
            p1 = p1[:n]
            x = bytearray(
                x[: n >> 2 << 2] + x[((n + 3 >> 2) << 2) - (n & 3) : (n + 3 >> 2) << 2]
            )
            assert (
                len(x) == len(enc_flag) == len(p1) == n
            ), f"{len(x)} == {len(enc_flag)} == {len(p1)} == {n}"
            for i in range(n):
                t = 0
                for j in range(8):
                    t |= (enc_flag[i] >> j & 1) << p1[i][j]
                x[i] ^= t
            x = bytes(x)
            print(x, count)
            if x.startswith(b"TPCTF{"):
                return x

    return check(40, n)


def main():
    global flag_1
    flag_1 = bytes.fromhex(flag_1.decode())
    shuffle_list = getrandomlist1()
    x = [None] * len(shuffle_list)
    for i in range(len(shuffle_list)):
        x[shuffle_list[i]] = i
    shuffle_list = x
    x = list(range(len(shuffle_list)))
    u = list(range(len(shuffle_list)))
    randomlist = []
    for t in reversed(range(1, len(shuffle_list))):
        v = x[shuffle_list[t]]
        randomlist.append(v)
        x[shuffle_list[t]], x[u[t]] = t, v
        u[t], u[v] = u[v], u[t]
    # print(randomlist)
    id = 0
    x = list(range(len(flag_1)))
    for i in reversed(range(1, len(x))):
        t = (i + 1).bit_length()
        j = randomlist[id] >> (10 - t)
        id += 1
        while j >= i + 1:
            j = randomlist[id] >> (10 - t)
            id += 1
        x[i], x[j] = x[j], x[i]
    # print(x)
    origin = [None] * len(x)
    for i in range(len(x)):
        origin[x[i]] = flag_1[i]
    print(len(work(origin, io)))


main()
print("query count: ", count)
```

</details>
