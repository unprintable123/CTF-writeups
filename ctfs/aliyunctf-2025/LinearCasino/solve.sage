from sage.coding.information_set_decoder import LeeBrickellISDAlgorithm
import signal
from pwn import process, remote, context
n, d1, d2 = 100, 60, 50

# context.log_level = "debug"

def timed_call(fn, args, timeout=1):
    def handler(signum, frame):
        raise TimeoutError()

    signal.signal(signal.SIGALRM, handler)
    signal.alarm(timeout)
    try:
        return fn(*args)
    finally:
        signal.alarm(0)


def guess(M):
    def try_solve():
        C = codes.LinearCode(M)
        A = LeeBrickellISDAlgorithm(C, (1, 15))
        r = vector(GF(2), [0] *2*n)
        return A.decode(r)
    
    try:
        timed_call(try_solve, (), 1)
    except TimeoutError:
        return 0
    return 1

# io = process(["sage", "task.sage"])
# 121.41.238.106:18618
io = remote("121.41.238.106", 18618)

for i in range(100):
    io.recvuntil("🎩".encode())
    mint = int(io.recvline().strip().decode())
    m_list = list(map(int, list(bin(mint)[2:].zfill(2*n*(d1+d2)))))

    M = matrix(GF(2), d1+d2, 2*n, m_list)
    decision = guess(M)
    print("Round", i, "Decision", decision)
    if decision:
        io.sendline(b"1")
    else:
        io.sendline(b"0")

io.interactive()
