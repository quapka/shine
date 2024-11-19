#!/usr/bin/env python3

import hashlib
import secrets
import operator
import functools


from itertools import combinations
import math
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
    # print(f" factors: {factors}")
    return functools.reduce(operator.mul, factors, 1)


class Shine:
    def __init__(self, lamb: int = 32):
        # self.q, self.g = self.__setup(lamb)
        # FIXME do not hardcode the values?
        self.q = 3538415753
        self.g = 3
        print(pow(self.g, self.q - 1, self.q))

    # NOTE: This key_gen is a trusted dealer setting.
    #       However, decentralization seems straightforward
    def key_gen_dealer(self, n: int, t: int, mju: int) -> Optional[Mapping[int, set]]:
        # Track users explicitly and do not use 0th index for the first user
        users = range(1, n + 1)
        # 1st step
        if mju < (2 * t - 1):
            raise ValueError("mju must be greater than (2t - 1)")

        # 2nd (S over t) means the set that consists of all t-sized subsets of the set S.
        A = t_sized_subsets_of_s(s=users, t=(t - 1))
        print(f"A: {A}")
        gamma = len(A)

        # 3rd step
        phis = {}
        for subset in A:
            phis[subset] = secrets.randbelow(self.q)
        print(f"Phis: {phis}")

        # 4th step
        shares = {user: set() for user in users}

        # 5th step
        for subset in A:
            if len(subset) != t - 1:
                raise ValueError(
                    f"The subset {subset} is not of the expected size {t-1}, but {len(subset)}"
                )
            for user in users:
                if user in subset:
                    continue
                shares[user].add((subset, phis[subset]))

        # verify the number of sets in the share
        exp_share_size = math.comb(n - 1, t - 1)
        for user, share in shares.items():
            print(share)
            for subset in share:
                if user in subset:
                    raise ValueError
            if len(share) != exp_share_size:
                raise ValueError
        # 6th step
        print(f"shares: {shares}")
        return shares

    # NOTE should return also the group G, but we use the implicit one
    @staticmethod
    def __setup(lamb: int) -> Tuple[int, int]:
        q = crypto_number.getPrime(lamb)
        g = 3
        if q == g:
            raise ValueError
        return q, g

    def key_gen_hash(self, phi_i: int, w: int) -> int:
        domain_separator = b"SHINE_KEYGEN_HASH_FUNCTION"
        sha256 = hashlib.sha256()
        sha256.update(domain_separator)
        # FIXME how many bytes to use?
        sha256.update(phi_i.to_bytes(8, "big"))
        # FIXME how many bytes to use? Should be bytes anyway and use the smallest
        sha256.update(w.to_bytes(8, "big"))
        return int.from_bytes(sha256.digest(), "big") % self.q

    def gen(self, k, sk, w: int) -> Tuple[int, int]:
        # 1st step parse sk
        # 2n step calculate polynomials, can be precomputed
        L_polynomials = {}
        for value in sk:
            subset, phi = value
            # FIXME, this is giving float values, shouldn't it be in ZZq?
            pol = lambda x: prod(
                ((j - x) * pow(j, -1, self.q)) % self.q for j in subset
            )
            L_polynomials[subset] = pol

            # NOTE add exception reasons
            # print(f"pol: {pol(0), self.q}")
            if pol(0) != 1:
                raise ValueError
            for j in subset:
                if pol(j) != 0:
                    raise ValueError

        # 3rd step, obtain the share_dk
        share_dk = 0
        print(f"delta: {len(sk)} sk: {sk} ")
        for value in sk:
            subset, phi = value
            share_dk += self.key_gen_hash(phi, w) * L_polynomials[subset](k)
            # print(L_polynomials[subset](k))

        # share_dk %= self.q

        # 4th step derive the commitment
        # print(self.g)
        # print(share_dk)
        # print(self.q)
        share_commitment_Dk = pow(self.g, share_dk, self.q)

        return share_dk % self.q, share_commitment_Dk

    def ith_langrange_coefficient(
        self,
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
        denominator = prod([coalition[j_lag] - x_k for x_k in values])

        assert denominator != 0, "Division by zero"

        # n is the order of the Lagrange polynomial Lj(x)
        n = len(coalition) - 1
        # Absolute value of the ith term is the sum of the multiplication of all (n-i) combinations of the values
        comb_size = n - i_coeff
        print(f"n:{n} i: {i_coeff}, values: {values}, comb_size: {comb_size}")
        # print(f"combinations: {list(combinations(values, comb_size))}")
        ith_coeff = sum(prod(c) for c in combinations(values, comb_size))
        # The ith coefficient sign is determined by the size of the combined values
        sign = (-1) ** comb_size
        # FIXME: occasionally the base is not invertible in the following expression
        out = (sign * ith_coeff * pow(denominator, -1, self.q)) % self.q
        # out = sign * ith_coeff / denominator
        return out

    def verify(self, t: int, mju: int, C, Djs: Mapping[int, int]) -> bool:
        # NOTE: I suppose that C is a coalition, that is C is a subset of [n]
        # 1st step
        if len(C) < mju:
            return False

        # 2nd step, compute B evaluation
        B_polynomials = []
        # NOTE: the B polynomials are explicitly 0-indexed
        for i in range(len(C)):
            # direct computation
            # B_i_direct = (
            #     prod(
            #         # pow(D_j, self.ith_langrange_coefficient(i, j, Djs), self.q)
            #         D_j ** self.ith_langrange_coefficient(i, j, Djs)
            #         for j, D_j in Djs.items()
            #     )
            #     % self.q
            # )

            # sequential computation
            B_i = 1
            for j, Dj in Djs.items():
                Lji = self.ith_langrange_coefficient(i, j, Djs)
                print(f"Dj: {Dj}")
                print(f"Lji: {Lji}")
                B_i *= pow(Dj, Lji, self.q)  # pow(Dj, Lji, self.q)

            B_i %= self.q
            print(f"B_i: {B_i}")
            B_polynomials.append(B_i)
            # if B_i_direct != B_i:
            #     raise ValueError

        # 3rd step
        l = len(C) - t
        print(f"l: {l}")
        print(B_polynomials)
        for i in range(1, l + 1):
            ind = t - 1 + i
            print(f"ind: {ind} : B_ind: {B_polynomials[ind]} q: {self.q}")
            # print(pow(self.g, B_polynomials[ind], self.q))
            if B_polynomials[ind] != 1:
                return False
        return True

    def aggregate(self) -> int:
        pass

    def recover(self) -> Optional[Tuple[int, int]]:
        pass


if __name__ == "__main__":
    shine = Shine(lamb=32)

    # coalition = {i: i for i in range(1, 5)}
    # for i in range(1, 5):
    #     for j in range(1, 5):
    #         print(shine.ith_langrange_coefficient(i, j, coalition))
    # import sys

    # sys.exit()

    t = 2
    n = 3
    mju = 3
    secret_shares = shine.key_gen_dealer(n=n, t=t, mju=mju)
    dks = {}
    Dks = {}
    for user, share in secret_shares.items():
        # FIXME: what the heck is this `w` value? Guess: Participant supplied randomness?
        w = 1
        if not (1 <= user <= n):
            raise ValueError
        dk, Dk = shine.gen(user, share, w)
        # dks[user] = dk
        Dks[user] = Dk
        # print(f"d_k: {dk} D_k: {Dk}")

    full_coalition = range(1, len(secret_shares) + 1)
    print(shine.verify(t, mju, range(1, len(secret_shares) + 1), Dks))
