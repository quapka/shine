#!/usr/bin/env python3

from shine import Shine

shine = Shine(lamb=32)
print(f"q: {shine.q}")

coal = {1: 1, 2: 2, 3: 3, 4: 4}
for i in range(4):
    print(f"i: {i}")
    print(shine.ith_langrange_coefficient(i, 2, coal))
