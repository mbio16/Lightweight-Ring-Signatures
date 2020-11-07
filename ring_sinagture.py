from dataclasses import dataclass
from enum import Enum
from cryptography.hazmat.primitives.asymmetric import rsa
from hashlib import sha256
from functools import reduce
import os
import sys
import time


class KeySize(Enum):
    KEY_SIZE_1024 = 1024
    KEY_SIZE_2048 = 2048
    KEY_SIZE_4096 = 4096
    KEY_SIZE_512 = 512


@dataclass
class Signature:
    I: int
    c_1: int
    x: list


class LightweightRingSingatures:

    def __init__(self):
        self.p = None
        self.q = None
        self.N = None
        self.I = dict()
        self.public_keys = list()
        self.params_time = dict()
        self.rj = None

    def test_numbers(self, p: int, q: int) -> None:
        self.p = p
        self.q = q
        self.N = self.p * self.q

    def generate_key(self, key_size: KeySize) -> None:
        start = time.process_time()
        private_key = rsa.generate_private_key(
            key_size=key_size.value, public_exponent=65537)
        self.p = private_key.private_numbers().p
        self.q = private_key.private_numbers().q
        self.N = self.p*self.q
        end = time.process_time()
        self.params_time["key_generation"] = end - start

    def import_public_key(self, public_key: int) -> None:
        self.public_keys.append(public_key)

    def import_public_keys(self, public_keys: list) -> None:
        for item in public_keys:
            self.public_keys.append(item)

    def get_public_key(self) -> int:
        return self.N

    def print_all(self) -> None:
        print("\np: {} \n\n\nq: {}\n\nN:{}\nI:{}\n".format(
            self.p, self.q, self.N, self.I))
        print("Users public keys: ")
        print("Process time:" + str(self.params_time))

    def sign(self, message: str, event_id: int, k: int = None) -> Signature:
        if (k is None):
            k = len(self.public_keys)
        assert (k <= len(self.public_keys)
                ), "K has to be lower or equeal of all public keys imported"

        if(self.I.get(event_id, None)) is None:
            self.key_image(event_id)
        c = list()
        x = list()
        # part  1

        r_j = self._get_urandom_for_platform(self.N)
        h = sha256(str(self._get_all_public_keys_as_one_int()) +
                   message+str(event_id)).digest().decode("utf-8")
        c.append(int(sha256(h + str(r_j)).hexdigest()), 16)

        for i in k:
            N_i = self.public_keys[i]
            # part 2

            x.append(self._get_urandom_for_platform(N_i))
            # part 3
            c.append(
                int(sha256(str(h) + str((c[-1]*self.I[event_id]) + pow(x[-1], 2, N_i))).hexdigest()), 16)
            # part 4
            while(True):
                residues = list()
                a = int(int(r_j-(c[-1]*self.I)) % self.N)
                try:
                    residues.append(Tonelli.calc(a, self.p))
                    residues.append(Tonelli.calc(a, self.q))
                    break
                except:
                    x[-1] = os.urandom(self.public_keys[k-1])
                    c[-1] = int(sha256(str(h)+str((c[-2]*self.I[event_id]
                                                   ) + pow(x[-1], 2, N_i))).hexdigest(), 16)
            c.insert(Chinnese_reminder_theorem().calc(
                residues, (self.p, self.q)))
            return Signature(
                I=self.I[event_id],
                c_1=c[0],
                x=x
            )

    def _get_urandom_for_platform(self, max_number: int) -> int:
        if (max_number > sys.maxsize):
            return os.urandom(sys.maxsize)
        else:
            return os.urandom(max_number)

    def _get_all_public_keys_as_one_int(self) -> int:
        result = ""
        for element in self.public_keys:
            result = result + str(element)
        return int(result)

    def key_image(self, event_id: int) -> None:
        start = time.time()
        a = int((str(self.p)+str(self.N)+str(event_id))) % self.N
        while(True):
            while(True):
                residues = list()
                try:
                    residues.append(Tonelli.calc(a, self.p))
                    residues.append(Tonelli.calc(a, self.q))
                    break
                except Exception as e:
                    a = a + 1
            try:
                self.I[event_id] = Chinnese_reminder_theorem().calc(
                    residues, (self.p, self.q))
                break
            except:
                a = a + 1
        end = time.time()
        self.params_time["key_image"] = end-start


class Tonelli:
    @ staticmethod
    def legendre(a, p):
        return pow(a, (p - 1) // 2, p)

    @ staticmethod
    def calc(n: int, p: int) -> int:
        assert Tonelli.legendre(n, p) == 1, "not a square (mod p)"
        q = p - 1
        s = 0
        while q % 2 == 0:
            q //= 2
            s += 1
        if s == 1:
            return pow(n, (p + 1) // 4, p)
        for z in range(2, p):
            if p - 1 == Tonelli.legendre(z, p):
                break
        c = pow(z, q, p)
        r = pow(n, (q + 1) // 2, p)
        t = pow(n, q, p)
        m = s
        t2 = 0
        while (t - 1) % p != 0:
            t2 = (t * t) % p
            for i in range(1, m):
                if (t2 - 1) % p == 0:
                    break
                t2 = (t2 * t2) % p
            b = pow(c, 1 << (m - i - 1), p)
            r = (r * b) % p
            c = (b * b) % p
            t = (t * c) % p
            m = i
        return r


class Chinnese_reminder_theorem:
    @ staticmethod
    def egcd(a: int, b: int):
        if a == 0:
            return (b, 0, 1)
        else:
            g, y, x = Chinnese_reminder_theorem().egcd(b % a, a)
            return (g, x - (b // a) * y, y)

    @ staticmethod
    def modInverse(a: int, m: int):
        g, x, y = Chinnese_reminder_theorem().egcd(a, m)
        if g != 1:
            raise Exception('modular inverse does not exist')
        else:
            return x % m

    @ staticmethod
    def calc(a: list, b: list, n=2) -> int:
        b1 = []
        b2 = []
        m = 1
        y = 0
        for i in range(n):
            m = m * b[i]
        for i in range(n):
            b1.append(int(m / b[i]))
            b2.append(Chinnese_reminder_theorem().modInverse(b1[i], b[i]))
        for i in range(n):
            x = int(a[i] * b1[i] * b2[i])
            y = y + x
        y = y % m
        return y
