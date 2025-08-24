# from sage.all import *
from math import log2, inf
import random, json
from bisect import bisect_left
from pwn import *
from ast import literal_eval
from tqdm import tqdm
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor

from fastecdsa.curve import secp256k1
from fastecdsa.point import Point

p = secp256k1.p
q = secp256k1.q
G = secp256k1.G
field_bytes = (p.bit_length() + 7) // 8
scalar_bytes = (q.bit_length() + 7) // 8

def encode_point(pt: Point):
    return pt.x.to_bytes(field_bytes, "big") + pt.y.to_bytes(field_bytes, "big")


def decode_point(data: bytes):
    if len(data) != 2 * field_bytes:
        raise ValueError("Invalid point encoding")
    x = int.from_bytes(data[:field_bytes], "big")
    y = int.from_bytes(data[field_bytes:], "big")
    return Point(x, y, secp256k1)

def hash_point(pt: Point):
    h = hashlib.sha256(encode_point(pt)).digest()
    return int.from_bytes(h, "big") % q


def hash_points_to_scalars(pts: list[Point], n: int):
    s = sum([hash_point(pt) for pt in pts]) % q
    ret = []
    for _ in range(n):
        ret.append(s)
        s = (1337 * s + 7331) % q
    return ret

class Lineage(int):
  """
  Lineage represents an integer and pointers to ancestor objects which created it.
  """
  def __new__(cls, x, *ancestors):
    el = int.__new__(cls, x)
    el._ancestors = ancestors
    return el

  def ancestors(self):
    """
    Returns any ancestor values which were used to create the instance.
    Operates recursively, walking up to the oldest ancestor values.
    """
    if len(self._ancestors) == 0:
      return [self]
    ancestors = []
    for ancestor in self._ancestors:
      if type(ancestor) == Lineage:
        ancestors.extend(ancestor.ancestors())
      else:
        ancestors.append(ancestor)
    return ancestors


def find_best_tree_height(n):
  """
  Finds the optimal tree height for a given modulus of n to
  minimize the computations required to find a solution.
  """
  log_n = int(log2(n))
  min_computations = inf
  best_tree_height = 1
  for tree_height in range(2, log_n):
    k = 2 ** tree_height
    lamda = n ** (1 / (1 + tree_height))
    computations = round((k - 2) * (2 * lamda * (log2(lamda) + 1)))

    if computations < min_computations:
      min_computations = computations
      best_tree_height = tree_height
    else:
      return best_tree_height
  return log_n


def ListFactory(n, desired_sum=0, tree_height=None):
  """
  Creates a List class used to solve a given class of birthday problem, over the
  given modulus n. Most use-cases will want to use the top-level solve method
  instead.
  """
  if tree_height is None:
    tree_height = find_best_tree_height(n)

  list_length = round(n ** (1 / (1 + tree_height)))
  k = 2 ** tree_height
  half_n = n >>  1

  if desired_sum >= n:
    raise RuntimeError("desired sum is greater than modulus")


  def filter_range(h):
    if h == tree_height:
      return (n, 0)
    divisor = 2 * (list_length ** h)
    base = round(n / divisor)
    a = n - base
    b = base - 1
    return (a, b)

  # cache the filter ranges in advance so we don't
  # recompute them for every merge operation.
  filter_ranges = [None] + [filter_range(h) for h in range(1, tree_height + 1)]


  class List:
    """
    List represents a list of random elements, either the result of previous list merging
    operations, or a freshly generated leaf list itself.

    Most use cases should use the top-level solve method instead.
    """

    def __init__(self, items, height):
      self.items = items
      self.height = height

    @staticmethod
    def generate(index):
      """
      Generates a new list at height zero (a leaf list) with the given
      index. If the index indicates the List will be the last in the whole
      set of k lists (i.e. index == k - 1), then the desired sum will be
      subtracted from each element after it is generated.
      """
      print("Generating list %d/%d" % (index + 1, k), list_length)
      items = point_generator(n, index, list_length)
      # The last list must be modified to produce a set with our desired sum.
      # Include a pointer back to the original random number.
      if index+1 == k:
        for (i, x) in enumerate(items):
          items[i] = Lineage((x - desired_sum) % n, x)

      return List(items, 0)

    def __iter__(self):
      return iter(self.items)
    def __len__(self):
      return len(self.items)
    def __getitem__(self, i):
      return self.items[i]

    # inefficient example merging operator.
    # merges lists by iterating through every sum.
    def __xor__(L1, L2):
      a, b = filter_ranges[L1.height + 1]
      sums = []
      for e1 in L1:
        for e2 in L2:
          z = (e1 + e2) % n
          if z >= a or z <= b:
            sums.append(Lineage(z, e1, e2))
      return List(sums, L1.height + 1)


    # fast merge using sorting and binary-search.
    def __and__(L1, L2):
      a, b = filter_ranges[L1.height + 1]
      sums = []

      # sort L2 so we can perform binary searches on it.
      sorted_other_items = sorted(L2)

      l2_min = sorted_other_items[0]
      l2_max = sorted_other_items[-1]

      for e1 in L1:
        # find the range in L2 within which e1 + e2 could fall into [a, b].
        # e2 = a - e1 will be the minimum number needed so that e1 + e2 = a.
        #
        # bisect_left will return the index of (a - e1) if it exists in sorted_other_items.
        # Otherwise it will return the location in L2 where (a - e1) would exist.
        #
        # Explore to the right through this range, wrapping around the end of the list
        # until we run out of useful elements.
        min_e2 = (a - e1) % n
        min_index = bisect_left(sorted_other_items, min_e2)
        index = min_index

        # Give up once we cycle through the whole list.
        while index < min_index + len(sorted_other_items):
          e2 = sorted_other_items[index % len(sorted_other_items)]
          z = (e1 + e2) % n
          if z >= a or z <= b:
            sums.append(Lineage(z, e1, e2))
          else:
            break # no more useful elements to be found.
          index += 1

      return List(sums, L1.height + 1)

    def at_height(height, index=None):
      """
      Recursively build a List at a given height in the tree. If height > 1,
      this function builds parent Lists and merges them together recursively
      until finally merging a List at the desired height, which is then
      returned to the caller.
      """
      if height < 1:
        raise RuntimeError("invalid height %d" % height)

      # Each leaf list should be passed an index from 0 to (k-1) to help
      # parameterize list generation. Since leaf lists are generated lazily,
      # we need to compute which index should be given to each parent list.
      #
      # - Start at the root node with the maximum index k - 1.
      # - The right-side parent's index should be the same as the child's index.
      # - The left parent's index should be: child_index - (2 ** parent_height)
      #
      # This propagates the correct list indices up the tree to the leaf lists.
      #
      # 0     1   2     3   4     5   6     7     h = 0
      # │     │   │     │   │     │   │     │
      # └─ 1 ─┘   └─ 3 ─┘   └─ 5 ─┘   └─ 7 ─┘     h = 1
      #    │         │         │         │
      #    └─── 3 ───┘         └─── 7 ───┘        h = 2
      #         │                   │
      #         └──────── 7 ────────┘             h = 3
      if index is None:
        index = (1 << height) - 1
      right_index = index
      left_index = index - (1 << (height - 1))

      merged = List([], height)
      while len(merged) == 0:
        if height == 1:
          left = List.generate(left_index)
          right = List.generate(right_index)
        else:
          left = List.at_height(height - 1, left_index)
          right = List.at_height(height - 1, right_index)

        # Uncomment to use the binary-search driven merge.
        merged = left & right

        # Uncomment to use the naive sequential merge.
        # merged = left ^ right

      return merged

  return List

def solve(n, desired_sum=0, tree_height=None):
  """
  Compute a solution to the generalized birthday problem modulo n. Outputs
  a list of integers which sum to the given desired_sum modulo n.

  By default solve will automatically compute the optimal number of lists needed for
  computing a solution quickly. If the caller would like to specify a certain number
  of output values k, simply supply the tree_height parameter such that k = 2 ** tree_height,
  (k must be a power of two).

  Leaf elements will be generated randomly by default. Callers may pass a generator
  function g(n, i). This function takes the modulus n and the list index i (lists are
  indexed from zero) and should output a random integer or Lineage instance.

  If the caller wishes to generate pseudo-random list elements by hashing randomized
  input data, they can make solve return the hash function's input data by returning
  Lineage instances in the generator function. See the readme for details.
  """
  if tree_height is None:
    tree_height = find_best_tree_height(n)
  print("Using tree height %d" % tree_height)

  List = ListFactory(n, desired_sum, tree_height)
  root = List.at_height(tree_height)
  return root[0].ancestors()

io = process(['sage', 'server.py'])
# nc pedantic.chal.hitconctf.com 1337
# io = remote('pedantic.chal.hitconctf.com', 1337)

io.recvuntil(b"Here is the proof:\n")

def serialize_proof(proof):
    return json.dumps([(encode_point(pt).hex(), z) for pt, z in proof])


def deserialize_proof(s: str):
    return [(decode_point(bytes.fromhex(pt)), z) for pt, z in json.loads(s)]

proof = deserialize_proof(io.recvline().decode().strip())

io.recvuntil(b"proof:")
io.close()

# print(proof)

proofs = []

cs = hash_points_to_scalars([pt for pt, z in proof], 10)

# pk = G * 1222223

for (pt, z), c in zip(proof, cs):
    # assert G * z == pt + c * pk
    c_inv = pow(c, -1, q)
    z_scaled = (z * c_inv) % q
    pt_scaled = pt * c_inv
    proofs.append((pt_scaled, z_scaled))

s = 1
n = 66000
ret = []
for _ in range(n):
    ret.append(s)
    s = (1337 * s + 7331) % q

base_comm = []
pt0, z0 = proofs[0]
pt, z = pt0, z0
for i in tqdm(range(n)):
    # assert G * z == pt + ret[i] * pk
    base_comm.append((pt, z))
    pt = pt * 1337 + pt0 * 7331
    z = (z * 1337 + z0 * 7331) % q


pts = [G*0]
for i in tqdm(range(2**18)):
    pts.append(pts[-1] + G)

history = [None] * n

def generate_point(n, index, num_elms):
    items = []
    for i in range(num_elms):
        pt, z = base_comm[index]
        z2 = (z + i) % q
        pt2 = pt + pts[i]
        items.append(Lineage(hash_point(pt2), (pt2, z2)))
    return items

# executor = ProcessPoolExecutor(max_workers=12)

# def point_generator(n, index, num_elms):
#     if history[index] is None:
#        for i in range(145):
#             history[index+i] = executor.submit(generate_point, n, index+i, num_elms)

    
#     u = history[index]
#     history[index] = None
#     return u.result()

for i in tqdm(range(2**16)):
    t = generate_point(n, i, 34444)

sols = solve(q, desired_sum=1, tree_height=16)

with open('sols.txt', 'w') as f:
  print(str(sols), file=f)
