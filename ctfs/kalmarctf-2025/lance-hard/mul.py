from concurrent.futures import ThreadPoolExecutor, as_completed
import os
import subprocess
import sys
from sage.all import *
from polynomial import fast_polynomial_gcd
from functools import lru_cache
from tqdm import tqdm
from subprocess import check_output
from sage.misc.persist import SagePickler, SageUnpickler
import pickle
import base64
import time, threading
from random import randbytes

orig_samples = []

with open("output.txt", "r") as f:
    p, a, b = map(int, f.readline().strip().split())

R0 = PolynomialRing(GF(p), 'r')
r = R0.gen(0)

def fast_hash(i, j):
    c = (i<<32)|j
    c += 0x9e3779b9
    c = (c ^ (c >> 16)) * 0x85ebca6b
    c &= (1<<64)-1
    c = (c ^ (c >> 47)) * 0xc2b2ae35
    c &= (1<<64)-1
    return c ^ (c >> 29)

class fast_MV_Element:
    def __init__(self, base, yvals, yval_prods, coeffs):
        self.base = base
        self.yvals = yvals
        self.yval_prods = yval_prods
        self.coeffs = coeffs
    
    def copy(self):
        return fast_MV_Element(self.base, self.yvals, self.yval_prods, self.coeffs[:])
    
    def degree(self):
        degs = [0]
        for p in self.coeffs:
            if hasattr(p, "degree"):
                degs.append(p.degree())
        return max(degs)
    
    def has_yval(self, idx):
        for i in range(2 ** len(self.yvals)):
            if i & (1 << idx) and self.coeffs[i] != 0:
                return True
        return False
    
    def flip(self, idx):
        new_coeffs = self.coeffs[:]
        for i in range(2 ** len(self.yvals)):
            if i & (1 << idx):
                new_coeffs[i] = -new_coeffs[i]
        return fast_MV_Element(self.base, self.yvals, self.yval_prods, new_coeffs)

    def count_nonzero(self):
        cnt = 0
        for i in range(2 ** len(self.yvals)):
            if self.coeffs[i] != 0:
                cnt += 1
        return cnt

    def __add__(self, other):
        new_coeffs = [a + b for a, b in zip(self.coeffs, other.coeffs)]
        return fast_MV_Element(self.base, self.yvals, self.yval_prods, new_coeffs)
    
    def __sub__(self, other):
        new_coeffs = [a - b for a, b in zip(self.coeffs, other.coeffs)]
        return fast_MV_Element(self.base, self.yvals, self.yval_prods, new_coeffs)
    
    def __neg__(self):
        return fast_MV_Element(self.base, self.yvals, self.yval_prods, [-a for a in self.coeffs])

    def __mul__(self, other):
        if not isinstance(other, fast_MV_Element):
            other = self.base.uni_poly(other)
        cnt = self.count_nonzero() * other.count_nonzero()
        if cnt > 256:
            num_threads = 3
            if cnt > 1024:
                num_threads = 11
            deg1 = self.degree()
            deg2 = other.degree()
            if (deg1>100 and deg2>100 and deg1+deg2>400) or (cnt>2**16 and deg1+deg2>80):
                print("Info: high degree polynomial multiplication", self.degree(), other.degree())
                return self.mt_mul(other, num_threads=num_threads)
        new_coeffs = [0] * (2 ** len(self.yvals))
        for i in range(2 ** len(self.yvals)):
            if self.coeffs[i]==0:
                continue
            for j in range(2 ** len(self.yvals)):
                if other.coeffs[j]==0:
                    continue
                m = self.coeffs[i] * other.coeffs[j] * self.yval_prods[i & j]
                new_coeffs[i ^ j] += m
        return fast_MV_Element(self.base, self.yvals, self.yval_prods, new_coeffs)

    def mul_part(self, other, index, num_threads, log_file=None):
        new_coeffs = [0] * (2 ** len(self.yvals))
        cnt = 0
        last_log = time.time()
        for i in range(2 ** len(self.yvals)):
            if self.coeffs[i]==0:
                if index == 0:
                    cnt += 2 ** len(self.yvals)
                continue
            for j in range(2 ** len(self.yvals)):
                if fast_hash(i, j)%num_threads != index:
                    continue
                cnt += 1
                if time.time() - last_log > 1:
                    last_log = time.time()
                    with open(log_file, "w") as f:
                        f.write(str(cnt))
                if self.coeffs[i]==0 or other.coeffs[j]==0:
                    continue
                m = self.coeffs[i] * (other.coeffs[j] * self.yval_prods[i & j])
                new_coeffs[i ^ j] += m
        with open(log_file, "w") as f:
            f.write(str(cnt))
        return fast_MV_Element(self.base, self.yvals, self.yval_prods, new_coeffs)

    def mt_mul(self, other, num_threads=17):
        if not isinstance(other, fast_MV_Element):
            other = self.base.uni_poly(other)
        n = 2 ** len(self.yvals)
        new_coeffs = [0] * n
        procs = []
        logs = []


        tmp_file = f"/tmp/{randbytes(16).hex()}.sobj"
        
        save([self, other], tmp_file)
        for proc_index in range(num_threads):
            log_file = f"/tmp/{randbytes(16).hex()}.log"
            logs.append(log_file)
            proc = subprocess.Popen(["sage", "mt_mul.py", str(proc_index), str(num_threads), tmp_file, log_file],
                                    stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
            procs.append(proc)
            # print(f"Process {proc_index} started")
        
        def log_status():
            status = [0] * num_threads
            pbar = tqdm(total=2**(2*len(self.yvals)))

            while any(proc.poll() is None for proc in procs):
                time.sleep(0.5)
                for i, log_file in enumerate(logs):
                    if os.path.exists(log_file):
                        with open(log_file, "r") as f:
                            txt = f.read().strip()
                            if txt:
                                status[i] = int(txt)
                pbar.n = sum(status)
                pbar.refresh()
                
            pbar.close()
        job = threading.Thread(target=log_status)
        job.start()

        for i, proc in enumerate(procs):
            out, err = proc.communicate()
            out = out
            if proc.returncode != 0:
                sys.stderr.write("Error: \n" + err.decode())
                continue
            out = out.strip()
            # partial = SageUnpickler.loads(base64.b64decode(out))
            partial = pickle.loads(base64.b64decode(out))
            assert len(partial) == n
            new_coeffs = [a + R0(b) for a, b in zip(new_coeffs, partial)]
        job.join()
        for log_file in logs:
            if os.path.exists(log_file):
                os.remove(log_file)
        os.remove(tmp_file)
        return fast_MV_Element(self.base, self.yvals, self.yval_prods, new_coeffs)


            


    def __pow__(self, n):
        if n == 0:
            return self.base.uni_poly(1)
        elif n == 1:
            return self.copy()
        else:
            t = self.__pow__(n // 2)
            if n % 2 == 0:
                return t * t
            else:
                return t * self.__pow__(n // 2+1)
    
    def __str__(self):
        return str(self.coeffs)
    
    def __repr__(self):
        return str(self.coeffs)


class fast_MV_Ring:
    def __init__(self, yvals):
        self.base_ring = R0
        self.yvals = [R0(y) for y in yvals]
        self.yval_prods = [1] * (2 ** len(self.yvals))
        for i in range(2 ** len(self.yvals)):
            for j in range(len(self.yvals)):
                if i & (1 << j):
                    self.yval_prods[i] *= self.yvals[j]
    
    def uni_poly(self, poly):
        return fast_MV_Element(self, self.yvals, self.yval_prods, [self.base_ring(poly)]+[0]*(2**len(self.yvals)-1))

    def yval(self, idx):
        assert 0 <= idx < len(self.yvals)
        self.coeffs = [0] * (2 ** len(self.yvals))
        self.coeffs[2**idx] = 1
        return fast_MV_Element(self, self.yvals, self.yval_prods, self.coeffs)

if __name__ == "__main__":
    RR = fast_MV_Ring([r**3+r+1])
    f1 = RR.uni_poly(r+1)
    f2 = RR.uni_poly(r+2)+RR.yval(0)
    print(f1*f2)
    print(f2**2)
    for _ in tqdm(range(2**16)):
        f1 = R0([randint(0,p) for _ in range(10000)]+[1])
        f2 = R0([randint(0,p) for _ in range(10000)]+[1])
        f = f1 * f2

