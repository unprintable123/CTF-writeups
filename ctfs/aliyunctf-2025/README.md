# Aliyun CTF 2025

Played with Redbud and got third place.
The challenges are really difficult and out of my distribution.
I solved `PRFCasino`, `LinearCasino`, `OhMyDH`, `softHash` and `hashgame` and here's the writeup.

## softHash

Just a simulated annealing.

## LinearCasino

The challenge asks to distinguish a McEliece-like matrix from a random one but I'm not good at McEliece.

My first attempt is to directly solve B using algos like ISD.
Let's first consider solving $B=\begin{bmatrix}D_1&0\\0&D_2\end{bmatrix}$, where the `D1` and `D2` parts are orthogonal.
It is possible to solve it by finding low-weight vectors. All of the 1s should be in `D1` or `D2` because we can find a lower weight vector if it's not.
It's called the low-weight codeword problem.

But the `D1` and `D2` vectors are not orthogonal to each other in our case.
Luckily, we only need to distinguish it from random, so the idea of finding low-weight vectors still works because half of the `D2` parts are 0.
Therefore, we guess that it has lower weight vector than the random matrix and the experiment supports the idea.

The code is at `LinearCasino/solve.sage`.
In the code, we try to solve the low-weight codeword problem of weight 15 in 1s. If it fails, it's random matrix.

## hashgame (哈基游)

You can do two things with the index php:

- inject something to the eval function
- calculate the hash of a file with selected algorithm and print nothing

To me, the most strange thing is we can choose the hash algorithm.
So I checked the `hash_algo` provided by php and find 3 different crc32.
We all know that crc32 is affine, and 3 crc32 gives 96 bit of information, while the flag has only 90bit randomness.
Therefore, we can recover the flag from hashes.

However, the initial problem is still unsolved: how to get the file hash?
There's no bypass or weakness of `preg_match` and it only allows letters, digits and `$_` up to 5 chars.
So it's completely safe and I can't print anything.

It is finally solved when I randomly send cached_key and find a error traceback.
When I send `c=a$a`, it parses the first `a` as type notation and throws error because type mismatch.
In the traceback, it prints the function inputs and gives me the file hash.

The rest is simple crypto so I'll skip it. Check the code at `hashgame`.

## PRFCasino

The challenge asks to distinguish a cipher stream from random bytes.

The challenge uses CBC encryption, so we can only control the first block and the rest are random plaintext and ciphertext pairs.
So it's hard to apply any differential attack or special crafted plaintext.

After exclusion, I guess that maybe the encryption is not that bijective, espesially the `i*T+lrot(T,17)`.

How could it not be bijective?
For example, if `T<2**(64-17)`, it equals to `(2**17+i)*T`.
It can be extended to `T<2**64` if we consider `lrot(T,17)=(2**17)*T%(2**64-1)`, thus we get `i*T+lrot(T,17)=(2**17+i)*T%(2**64-1)`.
It is not always correct because we have wraparound after the sum, but it'll at most happen once and +1 to the result.
If `gcd(2**17+i,2**64-1)>1`, the encryption is not bijective because the +1 can't make the distribution uniform.

We have found some non-bijective issues of the encryption, how can we identify it?

There're two `lrot` used in the encryption and we should focus on the second one, which is `T+lrot(T,20)`.
Similar to the analysis above, `gcd(2**20+1,2**64-1)=17`. If there's no wraparound, `T+lrot(T,20)%17==0`. So there's some problem with mod 17.

In each interation, `L%17,R%17=(R-wraparound)%17,L%17`, where wraparound happens at most twice. So after 30 rounds addition the distribution of `wraparound` is not uniform and we can recognize it.
So we count $(L_30-L_0)\pmod{17}$ statistically and check the distribution.

I write a simple counter at `PRFCasino/test.py` to check the statistics. The full solution is at `PRFCasino/solve.py`.

## OhMyDH

A quaternion CISDH. The best way to learn it is reading the preliminaries of papers.[^1][^2][^3][^4][^5]
It's the first time I know why there's quaternion in SQISign.
The most useful thing is the Deuring Correspondence(check the Table 1 in SQISign[^2]), and you can understand why the isogeny works on quaternion and what's the code doing.

In quaternion, each ideal is an "isogeny" and it connects its left and right order. What you can do on isogeny pathes is also true for the ideal by Deuring Correspondence.
You can feel ideal is more structural than curve, hence DH seems solvable on quaternion.

The most important algorithm stated in these papers is the KLPT algorithm[^1]. It looks equivalent to find a smooth isogeny path of small primes with given start and end curve.
But that doesn't help because in quaternion, we can do "isogeny" on any prime as long as you give me the ideal. We don't need to map back to curve.

If you check the repository of SQISign-Sagemath, every function takes connecting ideal as input.
However, the challenge didn't give me the connecting ideal of $O$ and $O_a$, so we need to figure out the connecting ideal first.
The good news is in some papers they claim computing the connecting ideal of two orders is easy. But they just skipped it!!!
Finally I find the algorithm in Section 3.2 of this paper.[^5]

The algorithm for the next step is found in the blog of SQISign-Sagemath[^6], where it gives me graph that takes two ideal starting from $O_0$ and outputs their composition.
This is exact what we want for DH. So just use the function we can get the shared secret.

The whole steps are:

1. Find the connecting ideal $I_a$ of $O$ and $O_a$.
2. Push forwards $I_a$ and $I_b$ to get the shared secret.

The final solution is quite simple and every function you need can be found in the SQISign-Sagemath repo, but it takes time to find the resources and understand the solution.
The script is attached at `OhMyDH/solve.sage`.

[^1]: https://eprint.iacr.org/2014/505.pdf
[^2]: https://eprint.iacr.org/2020/1240.pdf
[^3]: https://eprint.iacr.org/2023/1268.pdf
[^4]: https://eprint.iacr.org/2022/234.pdf
[^5]: https://eprint.iacr.org/2023/106.pdf
[^6]: https://learningtosqi.github.io/posts/pushforwards/
