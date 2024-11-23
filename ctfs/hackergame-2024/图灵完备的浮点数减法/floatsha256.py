import os
from hashlib import sha256

LIMIT = 1000000

def read_program():
    print('Your program:')
    program = []
    with open("program.txt", "r") as f:
        ps = f.read().split("\n")
    idx = 0
    while True:
        # line = input().strip()
        line= ps[idx]
        idx += 1
        if idx % 1000 == 0:
            print(idx)
        if line == 'EOF':
            break
        if len(program) >= LIMIT:
            raise ValueError('Program too long')
        nums = line.split()
        if len(nums) == 1:
            program.append(float(nums[0]))
        elif len(nums) == 2:
            program.append((int(nums[0]), int(nums[1])))
        else:
            raise ValueError('Invalid input')
    return program

def run_program(program, data, output_size):
    mem = [float(b) for b in data]
    for line in program:
        if isinstance(line, float):
            mem.append(line)
        else:
            index0, index1 = line
            assert index0 in range(len(mem)), 'Index out of range'
            assert index1 in range(len(mem)), 'Index out of range'
            mem.append(mem[index0] - mem[index1])
    assert len(mem) >= output_size
    output = []
    for x in mem[-output_size:]:
        b = int(x)
        assert float(b) == x, 'Output is not an integer'
        assert b in range(256), 'Output not in range'
        output.append(b)
    return bytes(output)

def main():
    prog = read_program()
    for i in range(10):
        print(f'Testing {i}')
        data = os.urandom(32)
        if sha256(data).digest() != run_program(prog, data, 32):
            print(f'Wrong answer at input {data.hex()}')
            exit(-1)
    print(open('flag').read())

if __name__ == "__main__":
    main()
