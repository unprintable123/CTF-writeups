from Crypto.Util.number import *
from random import randint
import os

p = 4718527636420634963510517639104032245020751875124852984607896548322460032828353
j = 4667843869135885176787716797518107956781705418815411062878894329223922615150642

flag = os.getenv("FLAG", "SECCON{test_flag}")


def interstellar_flight(j, flight_plans=None):
    planet = EllipticCurve(GF(p), j=j)
    visited_planets = []
    if flight_plans == None:
        flight_plans = [randint(0, 2) for _ in range(160)]

    for flight_plan in flight_plans:
        flight = planet.isogenies_prime_degree(2)[flight_plan]
        if len(visited_planets) > 1:
            if flight.codomain().j_invariant() == visited_planets[-2]:
                continue
        planet = flight.codomain()
        visited_planets.append(planet.j_invariant())
    return visited_planets[-1]


print("Currently in interstellar flight...")

vulcan = interstellar_flight(j)
bell = interstellar_flight(j)

print(f"vulcan's planet is here : {vulcan}")
print(f"bell's planet is here : {bell}")


final_flight_plans = list(map(int, input("Master, please input the flight plans > ").split(", ")))

if interstellar_flight(vulcan, final_flight_plans) == bell:
    print(f"FIND THE BELL'S SIGNAL!!! SIGNAL SAY: {flag}")
else:
    print("LOST THE SIGNAL...")