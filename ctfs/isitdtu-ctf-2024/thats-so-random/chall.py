import random
import os

os.chdir(os.path.dirname(os.path.abspath(__file__)))

flag  = random.randbytes(random.randint(13, 1337))
# flag += open("flag.txt", "rb").read()
flag += b"flag{for_testing_purposes_only}"
flag += random.randbytes(random.randint(13, 1337))
random.seed(flag)
assert len(flag) < 1337*1.733
with open("output_test.txt", "w") as f:
    f.write(str([random.randrange(0, int(0x13371337*1.337)) for _ in range(0x13337)]))

