from hashlib import sha256

class F:
    def __init__(self, id, type="const", parent=None):
        self.id = id
        self.type = type
        self.parent = parent
        if self.type == "const":
            self.value = parent
        else:
            f1, f2 = parent
            self.value = f1.value - f2.value
    
    def __str__(self) -> str:
        return f"<F_{self.id} {self.type} {self.value}>"

class Tape:
    def __init__(self):
        self.mem = []
        self.program = []

    def append_const(self, x, ignore_program=False):
        float_x = float(x)
        new_f = F(len(self.mem), type="const", parent=float_x)
        self.mem.append(new_f)
        if not ignore_program:
            self.program.append(x)
        return new_f
    
    def minus(self, F1, F2):
        idx1 = F1.id
        idx2 = F2.id
        new_f = F(len(self.mem), type="var", parent=(F1, F2))
        self.mem.append(new_f)
        self.program.append((idx1, idx2))
        return new_f
    
    @property
    def size(self):
        return len(self.mem)

T = Tape()

data = []

import os

target = os.urandom(32)

for i in range(32):
    data.append(T.append_const(target[i], ignore_program=True))

CONST_0 = T.append_const(0)
CONST_0_4 = T.append_const("0.4")
CONST_0_51 = T.append_const("0.51")
CONST_1_49 = T.append_const("1.49")
CONST_N0_1 = T.append_const("-0.1")
CONST_2_POWER = [T.append_const(2**i) for i in range(128)]
CONST_N2_POWER = [T.append_const(-2**i) for i in range(128)]

def neg(F):
    return T.minus(CONST_0, F)

def add(F1, F2):
    return T.minus(F1, neg(F2))

def nadd(F1, F2):
    return T.minus(neg(F1), F2)

def not_(F):
    return T.minus(CONST_2_POWER[0], F)

def lshift(F, bits):
    for _ in range(bits):
        F = add(F, F)

def check_1(F):
    # check is F in [-1.0, 0.5] or (0.5, 1.5)
    f2 = T.minus(F, CONST_2_POWER[53])
    f3 = T.minus(f2, CONST_N2_POWER[53])
    return f3

def check_2(F):
    # check F is in [0, 1] or (1, 3) return 0 or 2
    f2 = T.minus(F, CONST_2_POWER[54])
    f3 = T.minus(f2, CONST_N2_POWER[54])
    return f3

def check_2_53(F):
    # check F is 0 or 2**53
    f1 = T.minus(CONST_0_4, F)
    f2 = add(f1, F) # 0.4 or 0
    f3 = add(f2, f2) # 0.8 or 0
    f4 = check_1(f3) # 1 or 0
    return not_(f4)

def and_(F1, F2):
    f_sum = add(F1, F2)
    f_s = T.minus(f_sum, CONST_0_51)
    return check_1(f_s)

def or_(F1, F2):
    f_sum = add(F1, F2)
    f_s = T.minus(CONST_1_49, f_sum)
    return not_(check_1(f_s))

def xor(F1, F2):
    f_sum = add(F1, F2)
    high_bit = check_2(f_sum)
    return T.minus(f_sum, high_bit)

def and_xor(F1, F2):
    f_sum = add(F1, F2)
    high_bit = check_2(f_sum)
    f_s = T.minus(f_sum, CONST_0_51)
    return check_1(f_s), T.minus(f_sum, high_bit)

def add_gate(f1, f2, f3):
    f4, f5 = and_xor(f1, f2)
    f6, f7 = and_xor(f5, f3)
    f8 = xor(f4, f6)
    return f8, f7

def extract_bit(F: F, idx):
    if idx == 0:
        return None, F
    f2 = T.minus(F, CONST_N0_1)
    f3 = T.minus(f2, CONST_2_POWER[idx-1])
    f4 = T.minus(f3, CONST_2_POWER[idx+53])
    f5 = T.minus(f4, CONST_N2_POWER[idx+53]) # high bit
    low_bit = T.minus(F, f5)
    for _ in range(53-idx):
        f5 = and_(f5, f5)
    high_bit = check_2_53(f5)
    return low_bit, high_bit


class BitNum:
    def __init__(self, num):
        if isinstance(num, list):
            self.bits = num
        if isinstance(num, int):
            assert num >= 0 and num < 2**32, "Invalid number"
            self.bits = []
            for i in range(32):
                if (num >> i) & 1:
                    self.bits.append(CONST_2_POWER[0])
                else:
                    self.bits.append(CONST_0)

    def __str__(self) -> str:
        num = 0
        for i, bit in enumerate(self.bits):
            if bit.value == 1.0:
                num += 2**i
            elif bit.value == 0:
                continue
            else:
                raise ValueError("Invalid bit: {}".format(bit.value))
        return f"<BitNum {hex(num)} >"
    
    def not_(self):
        return BitNum([not_(bit) for bit in self.bits])

    def xor_(self, other):
        assert len(self.bits) == len(other.bits), "Invalid length"
        return BitNum([xor(a, b) for a, b in zip(self.bits, other.bits)])
    
    def and_(self, other):
        assert len(self.bits) == len(other.bits), "Invalid length"
        return BitNum([and_(a, b) for a, b in zip(self.bits, other.bits)])
    
    def or_(self, other):
        assert len(self.bits) == len(other.bits), "Invalid length"
        return BitNum([or_(a, b) for a, b in zip(self.bits, other.bits)])
    
    def right_rotate(self, l):
        return BitNum(self.bits[l:] + self.bits[:l])
    
    def right_shift(self, l):
        return BitNum(self.bits[l:] + [CONST_0]*l)
    
    def add(self, other):
        sum = []
        inbit = None
        for i in range(32):
            if inbit is None:
                a, b = and_xor(self.bits[i], other.bits[i])
                sum.append(b)
                inbit = a
            else:
                a, b = add_gate(inbit, self.bits[i], other.bits[i])
                sum.append(b)
                inbit = a
        return BitNum(sum)

    def to_bytes(self):
        def make_byte(bits):
            f = bits[7]
            for i in reversed(range(7)):
                f = add(f, f)
                f = add(f, bits[i])
            return f
        
        bytes = [make_byte(self.bits[i*8:i*8+8]) for i in range(4)]
        bytes.reverse()
        return bytes

def to_bits(f1:F, iter=8, reverse=True):
    low_bits = f1
    bits = []
    for i in reversed(range(8)):
        low_bits, high_bits = extract_bit(low_bits, i)
        bits.append(high_bits)
    if reverse:
        bits.reverse()
    return bits


block_data: list[BitNum] = []

for i in range(8):
    bits = to_bits(data[4*i+3]) + to_bits(data[4*i+2]) + to_bits(data[4*i+1]) + to_bits(data[4*i])
    block_data.append(BitNum(bits))

block_data.append(BitNum(0x80000000))
for _ in range(6):
    block_data.append(BitNum(0))
block_data.append(BitNum(0x100))

for i in range(16, 64):
    s0 = block_data[i-15].right_rotate(7).xor_(block_data[i-15].right_rotate(18)).xor_(block_data[i-15].right_shift(3))
    s1 = block_data[i-2].right_rotate(17).xor_(block_data[i-2].right_rotate(19)).xor_(block_data[i-2].right_shift(10))
    block_data.append(block_data[i-16].add(s0).add(block_data[i-7]).add(s1))

a = BitNum(0x6a09e667)
b = BitNum(0xbb67ae85)
c = BitNum(0x3c6ef372)
d = BitNum(0xa54ff53a)
e = BitNum(0x510e527f)
f = BitNum(0x9b05688c)
g = BitNum(0x1f83d9ab)
h = BitNum(0x5be0cd19)

K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]
K = [BitNum(k) for k in K]

for i in range(64):
    s1 = e.right_rotate(6).xor_(e.right_rotate(11)).xor_(e.right_rotate(25))
    ch = e.and_(f).xor_(e.not_().and_(g))
    temp1 = h.add(s1).add(ch).add(K[i]).add(block_data[i])
    s0 = a.right_rotate(2).xor_(a.right_rotate(13)).xor_(a.right_rotate(22))
    maj = a.and_(b).xor_(a.and_(c)).xor_(b.and_(c))
    temp2 = s0.add(maj)

    h = g
    g = f
    f = e
    e = d.add(temp1)
    d = c
    c = b
    b = a
    a = temp1.add(temp2)

a = a.add(BitNum(0x6a09e667))
b = b.add(BitNum(0xbb67ae85))
c = c.add(BitNum(0x3c6ef372))
d = d.add(BitNum(0xa54ff53a))
e = e.add(BitNum(0x510e527f))
f = f.add(BitNum(0x9b05688c))
g = g.add(BitNum(0x1f83d9ab))
h = h.add(BitNum(0x5be0cd19))


result = a.to_bytes() + b.to_bytes() + c.to_bytes() + d.to_bytes() + e.to_bytes() + f.to_bytes() + g.to_bytes() + h.to_bytes()
result = [T.minus(f, CONST_0) for f in result]


print(sha256(target).hexdigest())
print(*T.mem[-32:])
print(T.size)

with open("program.txt", "w") as f:
    for p in T.program:
        if isinstance(p, str):
            f.write(p)
        elif isinstance(p, float):
            f.write(str(p))
        elif isinstance(p, int):
            f.write(str(p))
        elif isinstance(p, tuple):
            f.write(f"{p[0]} {p[1]}")
        else:
            raise NotImplementedError
        f.write("\n")
    f.write("EOF")
        





