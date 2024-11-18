#!/usr/bin/env python3

import hashlib
import secrets
import operator
import functools


from itertools import combinations, product
from typing import List, Mapping, Tuple, Optional, Iterable

from Crypto.Util import number as crypto_number


def t_sized_subsets_of_s(s: List[int], t: int) -> List[List[int]]:
    if t > len(s):
        raise ValueError("t <= len(s)")

    return list(combinations(s, t))


def prod(factors: Iterable[int]) -> int:
    """
    Multiplies all the `factors` together.
    """
    return functools.reduce(operator.mul, factors, 1)


class Shine:
    def __init__(self, lamb: int = 32):
        self.q, self.g = self.__setup(lamb)

    # NOTE: This key_gen is a trusted dealer setting.
    #       However, decentralization seems straightforward
    def key_gen_dealer(self, n: int, t: int, mju: int) -> Optional[Mapping[int, set]]:
        # Track users explicitly and do not use 0th index for the first user
        users = range(1, n + 1)
        # 1st step
        if mju < (2 * t - 1):
            raise ValueError("mju must be greater than (2t - 1)")

        # 2nd (S over t) means the set that consists of all size-t subsets of S.
        A = t_sized_subsets_of_s(s=users, t=(t - 1))
        gamma = len(A)

        # 3rd step
        phis = []
        for _ in range(gamma):
            phis.append(secrets.randbelow(self.q))

        # 4th step
        shares = {user: set() for user in users}

        # 5th step
        for i, subset in enumerate(A):
            for user in users:
                if user in subset:
                    continue
                shares[user].add((subset, phis[i]))

        # 6th step
        return shares

    # NOTE should return also the group G, but we use the implicit one
    @staticmethod
    def __setup(lamb: int) -> Tuple[int, int]:
        q = crypto_number.getPrime(lamb)
        g = 2
        return q, g

    @staticmethod
    def key_gen_hash(phi_i, w):
        domain_separator = b"SHINE_KEYGEN_HASH_FUNCTION"
        sha256 = hashlib.sha256()
        sha256.update(domain_separator)
        # FIXME how many bytes to use?
        sha256.update(phi_i.to_bytes(8, "big"))
        # FIXME how many bytes to use?
        sha256.update(w.to_bytes(8, "big"))
        return int.from_bytes(sha256.digest(), "big")

    def gen(self, k, sk, w) -> Tuple[int, int]:
        # 1st step parse sk
        # 2n step calculate polynomials, can be precomputed
        L_polynomials = []
        for value in sk:
            subset, phi = value
            pol = lambda x: product(((j - x) / j) for j in subset)
            if pol(0) != 1:
                raise ValueError
            for j in subset:
                if pol(j) != 0:
                    raise ValueError

        # 3rd step, obtain the share_dk
        share_dk = 0
        for ind, item in sk.items():
            share_dk += self.key_gen_hash(item[0], w) * L_polynomials[ind](k)

        # 4th step derive the commitment
        share_commitment_Dk = pow(self.g, share_dk, self.q)

        return share_dk, share_commitment_Dk

    @staticmethod
    def ith_langrange_coefficient(
        i_coeff: int,
        j_lag: int,
        coalition: Mapping[int, Tuple[int, int]],
    ) -> int:
        """
        Returns the ith coefficient of the x^i term for the jth Lagrange polynomial L_j(x)
        for the coalition C.

        i_coeff, j_lag are 1-indexed?
        """
        # 1 for x^n
        # prod

        # get i = 2, j = 3, for C
        # jth Lagrange: Lj(x) = Prod over k, k != j (x - x_k)/(x_j - x_k)
        # C = [a, b, c, d, e, ...]
        # (x-a)(x-b)(x-c)

        values = [item for k, item in coalition.items() if k != j_lag]
        order = len(coalition)
        denominator = prod([coalition[j_lag] - x_k for x_k in values])

        assert denominator != 0, "Division by zero"

        # n is the order of the Lagrange polynomial Lj(x)
        n = len(coalition)
        # Absolute value of the ith term is the sum of the multiplication of all (n-i) combinations of the values
        comb_size = n - i_coeff
        ith_coeff = sum(prod(t) for r in combinations(values, comb_size))
        # The ith coefficient sign is determined by the size of the combined values
        sign = (-1) ** comb_size
        return sign * ith_coeff / denominator

    def verify(self, t: int, mju: int, C, Djs: Mapping[int, int]) -> bool:
        # NOTE: I suppose that C is a coalition, that is C is a subset of [n]
        # 1st step
        if len(C) < mju:
            return False

        # 2nd step, compute B evaluation
        B_polynomials = []
        for i in range(len(C)):
            B_i = prod(
                D_j ** self.ith_langrange_coefficient(i, j, Djs) for j, D_j in Djs
            )
            B_polynomials.append(B_i)

        # 3rd step
        l = len(C) - t
        for i in range(1, l + 1):
            ind = t - 1 + i
            if B_polynomials[ind] != 1:
                return False
        return True

    def aggregate(self) -> int:
        pass

    def recover(self) -> Optional[Tuple[int, int]]:
        pass


if __name__ == "__main__":
    shine = Shine(lamb=32)
    t = 3
    n = 7
    mju = 5
    secret_shares = shine.key_gen_dealer(n=n, t=t, mju=mju)
    dks = {}
    Dks = {}
    for user, share in secret_shares.items():
        # FIXME: what the heck is this `w` value? Guess: Participant supplied randomness?
        w = 1
        dk, Dk = shine.gen(user, share, w)
        dks[user] = dk
        Dks[user] = Dk

    print(shine.verify(t, mju, range(len(secret_shares)), Dks))
