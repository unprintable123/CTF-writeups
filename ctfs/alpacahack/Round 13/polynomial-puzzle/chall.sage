import os

K = GF(random_prime(2 ^ 35))
R = K["x"]

d = 20
f = R.random_element(degree=d)

print("Welcome to the Polynomial Puzzle!")
print(f"f(x) is a univariate degree {d} polynomial with coefficients in K = {K}")

for _ in range(d + 3):
		x = next_prime(K.random_element())
		mixed = [K.random_element() for _ in "apch"]
		mixed[1] = f(x) - mixed[0]
		shuffle(mixed)
		print(f"f({x}) is sum of some two values of {mixed}")

guess = int(input("What is f(42)?\n> "))
if guess == f(42):
		flag = os.environ.get("FLAG", "Alpaca{***** REDACTED *****}")
		print(f"You won! The flag is {flag}")
else:
		print("You lost :(")
