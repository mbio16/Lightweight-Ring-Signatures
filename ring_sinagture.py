from dataclasses import dataclass
from enum import Enum
from cryptography.hazmat.primitives.asymmetric import rsa
from hashlib import sha512
from functools import reduce
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

    def test_numbers(self, p: int, q: int) -> None:
        self.p = p
        self.q = q
        self.N = self.p * self.q

    def generate_key(self, key_size: KeySize) -> None:
        start = time.time()
        private_key = rsa.generate_private_key(
            key_size=key_size.value, public_exponent=65537)
        self.p = private_key.private_numbers().p
        self.q = private_key.private_numbers().q
        self.N = self.p*self.q
        end = time.time()
        self.params_time["key_generation"] = end - start

    def import_public_key(self, public_key: int) -> None:
        self.public_keys.append(public_key)

    def import_public_keys(self, public_keys: list) -> None:
        for item in public_keys:
            self.public_keys.append(item)

    def get_public_key(self) -> int:
        return self.N

    def print_all(self) -> None:
        print("\n\np: {} \n\n\nq: {}\n\n\nN:{}\n\nI:{}\n\n".format(
            self.p, self.q, self.N, self.I))
        print("Users public keys: ")
        for (i, item) in enumerate(self.public_keys):
            print("{}: {}\n".format(i, item))

    def sign(self, message: str, event_id: int) -> Signature:
        if(self.I.get(event_id, None)) is None:
            self.key_image(event_id)

    def key_image(self, event_id: int) -> None:
        a = int((str(self.p)+str(self.N)+str(event_id))) % self.N
        while(True):
            while(True):
                residoas = list()
                try:
                    residoas.append(Tonelli.calc(a, self.p))
                    residoas.append(Tonelli.calc(a, self.q))
                    break
                except Exception as e:
                    a = a + 1
            print("Chineese reminder")
            try:
                # print(str(residoas))
                # print(str((self.p, self.q)))
                self.I[event_id] = Chinnese_reminder_theorem().calc(
                    residoas, (self.p, self.q))
                break
            except:
                exit()
                a = a + 1

    def _hash_and_return_int(self, a: int) -> int:
        b = sha512(str(a).encode()).hexdigest()
        return int(b, 16)


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
        # print(str(a) + " mod " + str(m))
        print("a: " + str(a))
        print("m: " + str(m))
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
