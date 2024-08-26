# SekaiCTF 2024

I played as [`Twilight Light`](https://www.youtube.com/watch?v=dk13KyWwZn4) and solved 3.5 crypto challenges.
The crypto is very hard and I can't fully understand why everything works, so I will mainly focus on how I found these properties heuristically.
All of the scripts are attached in the `code` folder.

## はやぶさ

The challenge uses a standard Falcon implementation with only degree 64(too small), which makes it possible to break the lattice using BKZ/flatter.
To pass the verification we want to find a small coeficient polynomial $f(x)$ such that the coeficients of $f(x)h(x)-hashed$ are also small.
So we can build the lattice like this,

$$
\begin{pmatrix}
I_{64}&M\\
0&pI_{64}
\end{pmatrix}
$$

where the $i$-th row of $M$ if the coeficients of $x^ih(x)$.
After the reduction, we only need to find a cvp to `[0]*64+hashed`.
Coding is omitted and check `hayabusa.sage` for more details.

## マスタースパーク

The challenge asks you to provide a prime for CSIDH with some requirements, and then it will perform a key exchange with a point, where one of the point is multiplied with `secret`.

The most important fact is that isogeny will keep the group structure, so `secret*P=Q` still holds after the isogeny.

The rest part is straightforward, just get the modulus of `secret` for many small `p` and recover it using CRT.
For CSIDH, the order of the curve is `p+1=4*prod(prime_list)`, which is exactly the small primes we provided. Therefore, a Pohlig–Hellman is enough to solve the discrte log.
However, the sign of the discrete log may flip due to the x-axis can't full determine a point on the curve, and the solution is just finding some big `p` and enumerate all possible flips.

Check `master-spark.sage` for more details.

## Squares vs. Cubes

The most difficult 3 challenges are authored by Neobeo. All of them are intersesting and I really like(not solving) them. Here is [Neobeo's writeup](https://github.com/Neobeo/SekaiCTF2024).

### First attempt

The challenge performs an OT with a square sum and a cude sum. The first question is how to get the flag if I have these two value. My method is to calculate $(p^2+C^2)^3-(p^3+C^3)^2=p(...)$ and gcd with $N$ to get $p$, but the problem is that you can't eliminate $v-x0$ and $v-x1$ when trying to get the expression. You can only control relations like `(v-x0)=-(v-x1)` and get the sum of two equations.

But it suggests that $p$ maybe the first target of the challenge, so instead of $\pmod{N}$, we may consider it as $\pmod{p}$, which makes it univarate with a $C=q+r\times padded\_flag$.

### Step 1

Then I find this [blog](https://blog.maple3142.net/2023/01/16/idekCTF-2022-writeups/)(I was finding scripts for multivarate coppersmith at that time and somehow he wrote a challenge about OT) and the unintended solution seems useful for this too. If we write this out, it will look like this,

$$
(M_1-p^3-C^3)^N\equiv x0-x1\pmod{N}
$$

However, $e$ is change to $N$, thus Half GCD won't work.
But this time we also have another equation $p^2+C^2\equiv M_0\pmod{N}$, which can be used to do something like `pow(M_1-p^3-C^3, N, p^2+C^2-M_0)`. Remember that our target is to get p, so we are actually running the pow under mod $p$, so it should like this

$$
\begin{align*}
C^2-M_0&\equiv 0\pmod{p}\\
(M_1-C^3)&\equiv x0-x1\pmod{p}
\end{align*}
$$

So we can solve $C\pmod{p}$ and get another number which is a multiple of $p$.
After extracting $p$, we can rerun the pow but this time under mod $N$ with accurate $M_1-P^3$ value.
This time we get $C\pmod{N}$, considering that $C\approx2^{1536}$, we can throw mod $N$ and $C$.
So the first step ends with know the value of $p$ and $C$.
Now we can't get more from the OT and we have to solve $q,r$ using $C, N$.

### Step 2

Then I stucked for 3 hours and didn't solve it before the end of contest, hence 0.5 challenges. I was hoping the coppersmith would work and asked Neobeo whether the length of flag matters. He says 7 is enough, but he uses a different coppersmith. So the rest of the challenge please check his writeup.

The code of the first step is in `svc.sage`.

## zerodaycrypto

It will become my favourite crypto of this year.
~~Though I would say it is a reverse engineering after releasing the hint.~~

### Some Basic Analysis

The challenge gives us high bits of 14 distinct $(x+i)^{-1}\pmod{p}$ and asks to recover the $x$.
We can write the equations as follows,

$$
(x+i)a_i-1\equiv0\pmod{p}
$$

We know the high bits of $a_i$, and it will later be replaced from $a_i$ to $N_i+a_i$ for simplicity.
The problem looks like a multivarate coppersmith, but it has fewer known bits than multivarate coppersmith required. Therefore, we need to find more good polynomials which is low degree.

### Recover the Lattice

Now let's reverse engineering the lattice. The hint decribes a linear space called SBG, and one of the big property of SBG is that it is sqaure-free for all variables. The paper also claims that $SBG_{10}$ has exact 232 rank, which is the same as lattice, thus we can assume that the row of lattice represents the basis decomposition of the polynomials and the other steps is the same as the coppersmith method.

The next thing is to find what are the polynomials of the lattice.
The key of the coppersmith is using the product of polynomial to find a multiple of $p^k$.
Following SBG's idea, it should be sqaure-free, thus here it will be something like,

$$
((x+i)a_i-1)((x+j)a_j-1)\equiv0\pmod{p^2}
$$

and it shouldn't contain $x$, so we need to eliminate $x$ using $2d-2$ variables because SBG says that $k\geq 2d-2$. For this case, we need $4$ variables to get a degree $3$ symmetric polynomial that is a multiple of $p^2$.

I wrote a function `F` to interpolate the desired beetle, and it turns out it's a sum of $(4,3)$ beetle and a $(4,2)$ beetle.
Dig deeper we can find it is always a sum or subtraction of a $(2d-2,d)$ beetle and a $(2d-2,d-1)$ beetle.
The hint also says that SBG is closed under translation, so it will be ok to replace $a_i$ to $N_i+a_i$.

Now we've fully understand the detail of the lattice and the next step is to solve it in the real field.

### Solve Multivarate Polynomial in Real Field

In general, we will get some polynomials and use Groebner basis to solve it.
But for unknown reasons, it is extremely slow.
When I check the lattice, I find that except the last row, the others are correct in real field. It is quite weird and When I asked Neobeo, he says that it is even true for $1500\times1500$ lattice.
Whatever, just `right_kernel` gives me the $a_i$ and that's solved.

You can get the code in `zeroday.sage`.
