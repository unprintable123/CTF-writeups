#!/usr/bin/env python3

from dataclasses import dataclass
from random import *
from math import log2
# from secret import FLAG

N = 2**32
times = 64
r = .1
h1 = 'your number is too big'
h2 = 'your number is too small'
h3 = 'you win'
print("=== Welcome to D3CTF 2025 ===")
print("You have at most 1 hour to solve this challenge.")
print("Can you defeat the biased oracle?\n")
rr = Random()

def challge(rounds, times, N, r, mode=0):
    wins = 0
    f = lambda x: [0.075, 0.15, 0.225, 0.3, 0.375, 0.45][5 - x * 6 // 2**32]
    print(["Now let's play a simple number-guessing game", "Let's play a relatively simple number-guessing game again"][mode])
    for round_idx in range(rounds):
        x = rr.randint(1, N - 1)
        print(f"[*] Starting Round {round_idx + 1} of {rounds}")
        for _ in range(times):
            try:
                guess = int(input('[d3ctf@oracle] give me a number > '))
            except:
                print("[!] Invalid input detected. Session terminated.")
                exit()
            if guess > x:
                print([f(abs(guess - x)), [h1, h2][rr.random() < r]][mode])
            elif guess < x:
                print([f(abs(guess - x)), [h2, h1][rr.random() < r]][mode])
            else: 
                print(h3)
                wins += 1
                break
    return wins


def challge_player(rounds, times, N, r, player):
    wins = 0
    h1 = 0
    h2 = 1
    mode = 1
    f = lambda x: [0.075, 0.15, 0.225, 0.3, 0.375, 0.45][5 - x * 6 // 2**32]
    # print(["Now let's play a simple number-guessing game", "Let's play a relatively simple number-guessing game again"][mode])
    for round_idx in range(rounds):
        player.reset()
        x = rr.randint(1, N - 1)
        # print(f"[*] Starting Round {round_idx + 1} of {rounds}")
        for _ in range(times):
            guess = player.guess_number()
            if guess > x:
                player.send([h1, h2][rr.random() < r])
                # print([f(abs(guess - x)), [h1, h2][rr.random() < r]][mode])
            elif guess < x:
                player.send([h2, h1][rr.random() < r])
                # print([f(abs(guess - x)), [h2, h1][rr.random() < r]][mode])
            else: 
                # print(h3)
                wins += 1
                break
        # player.check(x, guess == x)
    return wins


class Player:
    def __init__(self):
        self.reset()
    
    def reset(self):
        self.last_guess = None
        self.guesses = []
    
    def guess_number(self):
        probs = [1.0] * (len(self.guesses) + 1)
        r = 0.1

        for ind in range(len(probs)):
            left = 0 if ind == 0 else self.guesses[ind - 1][0]
            right = N if ind == len(probs) - 1 else self.guesses[ind][0]
            probs[ind] = (right - left - 1)
            if right - left <= 1:
                probs[ind] = 0.0
        for ind, (g, sign) in enumerate(self.guesses):
            if sign:
                for i in range(ind + 1):
                    probs[i] *= r
                for i in range(ind + 1, len(self.guesses) + 1):
                    probs[i] *= 1-r
            else:
                for i in range(ind + 1):
                    probs[i] *= 1-r
                for i in range(ind + 1, len(self.guesses) + 1):
                    probs[i] *= r
        
        norm = sum(probs)
        probs = [p / norm for p in probs]
        acc = 0.0
        for ind in range(len(probs)):
            if acc + probs[ind] > 0.5:
                left = 0 if ind == 0 else self.guesses[ind - 1][0]
                right = N if ind == len(probs) - 1 else self.guesses[ind][0]
                ratio = (0.5 - acc) / probs[ind]
                guess = left + 1 + int((right - left - 1) * ratio)
                break
            acc += probs[ind]
        assert left < guess < right

        # ind = probs.index(max(probs))
        # left = 0 if ind == 0 else self.guesses[ind - 1][0]
        # right = N if ind == len(probs) - 1 else self.guesses[ind][0]
        # guess = left + 1 + int((right - left - 1) * 0.5)

        self.last_guess = guess
        return guess

    def send(self, sign):
        self.guesses.append((self.last_guess, sign))
        self.guesses = sorted(self.guesses, key=lambda x: x[0])
    
    def check(self, x, success):
        probs = [1.0] * (len(self.guesses) + 1)
        r = 0.1

        for ind in range(len(probs)):
            left = 0 if ind == 0 else self.guesses[ind - 1][0]
            right = N if ind == len(probs) - 1 else self.guesses[ind][0]
            probs[ind] = (right - left - 1)
            if right - left <= 1:
                probs[ind] = 0.0
        for ind, (g, sign) in enumerate(self.guesses):
            if sign:
                for i in range(ind + 1):
                    probs[i] *= r
                for i in range(ind + 1, len(self.guesses) + 1):
                    probs[i] *= 1-r
            else:
                for i in range(ind + 1):
                    probs[i] *= 1-r
                for i in range(ind + 1, len(self.guesses) + 1):
                    probs[i] *= r
        
        norm = sum(probs)
        probs = [p / norm for p in probs]
        acc = 0.0
        for ind in range(len(probs)):
            if acc + probs[ind] > 0.5:
                left = 0 if ind == 0 else self.guesses[ind - 1][0]
                right = N if ind == len(probs) - 1 else self.guesses[ind][0]
                ratio = (0.5 - acc) / probs[ind]
                guess = left + 1 + int((right - left - 1) * ratio)
                print(left, right, f"{probs[ind]:5f}", success)
                break
            acc += probs[ind]
        
        assert left < guess < right






print(challge_player(488, 64, N, 0.1, Player()))


# if challge(350, 32, N, r) == 350 and challge(2200, 64, N, r, mode=1) > 2112:
#     print(f"[!] You have proven your power over probability. This is your {FLAG}. Congratulations!")
# else:
#     print("[X] The oracle remains unbeaten. Try again, challenger.")
#     exit()

