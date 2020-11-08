from dataclasses import dataclass
from enum import Enum
from cryptography.hazmat.primitives.asymmetric import rsa
from hashlib import sha256
from functools import reduce
import os
import sys
import time
import random


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
    message: str
    event_id: int
    public_keys: list


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
        start = time.time()
        if (k is None):
            k = len(self.public_keys)
        assert (k <= len(self.public_keys)
                ), "K has to be lower or equeal of all public keys imported"

        if(self.I.get(event_id, None)) is None:
            self.key_image(event_id)

        # create array with no elements of size of all users
        c = len(self.public_keys) * [None]
        x = len(self.public_keys) * [None]
        I = self.I.get(event_id)
        # find index of singing user in public key array
        j_index = self._find_index_of_signing_user()
        # part  1
        (h, c, r_j) = self._sign_part_1(message, event_id, c, j_index)
        # print(str(h))
        # print(str(c))
        # print(str(r_j))

        # part 2
        x = self._sign_part_2(j_index, x)

        # part 3
        c = self._sign_part_3(j_index, x, c, str(h), I)

        # part 4
        (c, x) = self._sign_part_4(j_index, I, c, x, r_j, str(h))
        self._write_time_sign(start, event_id)

        print("array c")
        print(str(c))
        print("array x")
        print(str(x))
        return Signature(
            I=I,
            c_1=c[0],
            x=x,
            message=message,
            event_id=event_id,
            public_keys=self.public_keys
        )

    def verify_signature(self, signature: Signature) -> bool:
        (c, x, event_id, public_keys,
         message, I) = self._verify_get_parts_from_signature(signature)
        r = len(public_keys) * [None]

        # part 1
        h = self._verify_part_1(public_keys, message, event_id)

        # part 2 and 3
        r = self._verify_part_2_and_3(c, x, r, I, public_keys, h)

        # part 4
        (result) = self._verify_part_4(c, r, h)

    def _sign_part_1(self, message: str, event_id: int, c: list, j_index: int) -> (str, list, int):
        string_to_hash = (
            str(self._get_all_public_keys_as_one_int), message, str(event_id))
        h = self._hash(string_to_hash)
        r_j = self._get_urandom_for_platform(self.N)
        c[(j_index+1) % len(self.public_keys)
          ] = int(self._hash((str(h), str(r_j))) % self.N)
        return (h, c, r_j)

    def _sign_part_2(self, j_index: list, x: list) -> list:
        for i in range(len(self.public_keys)):
            if (i == j_index):
                continue
            else:
                x[i] = self._get_urandom_for_platform(self.public_keys[i])
        return x

    def _sign_part_3(self, j_index: int, x: list, c: list, h: str, I: int) -> list:
        # print(I)
        for i in range(j_index+1, len(self.public_keys)):
            # print("First for")
            # print(str(i))
            # print(str(x[i]))
            # print(str(c[i]))
            # print("------------")
            c[(i+1) % len(self.public_keys)
              ] = self._sign_part_3_subpart_1(c[i], I, x[i], self.public_keys[i], h)

        for i in range(0, j_index):
            c[(i+1) % len(self.public_keys)
              ] = self._sign_part_3_subpart_1(c[i], I, x[i], self.public_keys[i], h)
            # print("second for")
            # print(str(i))
            # print(str(x[i]))
            # print(str(c[i]))
            # print("------------")
        return c

    def _sign_part_3_subpart_1(self, c_i: int, I: int, x_i: int, N: int, h: str) -> int:
        # print("subpart")
        # print(str(c_i))
        # print(str(x_i))
        sub = int(((c_i*I) + pow(x_i, 2)) % N)
        return int(self._hash((str(h), str(sub))) % N)

    def _sign_part_4(self, j_index: int, I: int, c: list, x: list, r_j: int, h: str):
        while(True):
            t_j = int(r_j-(c[j_index]*I) % self.N)
            (residuo_exists, x_j) = self._calculate_sqrt_mod_p(t_j)
            if(residuo_exists):
                x[j_index] = x_j
                return (c, x)
            else:
                j_minus_one_index = (j_index - 1) % len(self.public_keys)
                x[j_minus_one_index] = self._get_urandom_for_platform(
                    self.public_keys[j_minus_one_index])
                c[j_index] = self._sign_part_3_subpart_1(
                    c[j_minus_one_index], I, x[j_minus_one_index], self.public_keys[j_minus_one_index], h)

    def _verify_get_parts_from_signature(self, signature: Signature) -> (list, list, int, list, str):
        c = len(signature.public_keys) * [None]
        c[0] = signature.c_1
        x = signature.x
        event_id = signature.event_id
        public_keys = signature.public_keys
        message = signature.message
        I = signature.I
        return (c, x, event_id, public_keys, message, I)

    def _verify_part_1(self, public_keys: list, message: str, event_id: int) -> str:
        to_be_hashed = (str(self._get_all_public_keys_as_one_int(
            public_keys)), message, str(event_id))
        return str(self._hash(to_be_hashed))

    def _verify_part_2_and_3(self, c: list, x: list, r: list, I: int, public_keys: int, h: str) -> (list):
        for i in range(len(public_keys)):
            r[i] = int((c[i]*I)+pow(x[i], 2)) % public_keys[i]
            if (i+1 == len(public_keys)):
                return r
            else:
                c[i+1] = int(self._hash((h, str(r[i]))) % public_keys[i])

    def _verify_part_4(self, c: list, r: list, h: str) -> bool:
        res = self._hash((h, str(r[-1])))
        # print(str(res))
        # print(str(c[1]))
        print("Array c")
        print(str(c))
        return

    def _hash(self, parts: list) -> int:
        s = ""
        for part in parts:
            s = s + part
        return int(sha256(s.encode()).hexdigest(), 16)

    def _calculate_sqrt_mod_p(self, a: int) -> (bool, int):
        residues = list()
        try:
            residues.append(Tonelli.calc(a, self.p))
            residues.append(Tonelli.calc(a, self.q))
            return (True, Chinnese_reminder_theorem().calc(residues, (self.p, self.q)))
        except:
            return (False, None)

    def _find_index_of_signing_user(self) -> int:
        try:
            return self.public_keys.index(self.N)
        except Exception as e:
            print("User who wants to sign is not in RING GROUP")
            print("Nothing to do in signing... exiting program")
            exit()

    def _write_time_sign(self, start: float, event_id: int) -> None:
        if(self.params_time.get("sign", None) is None):
            self.params_time["sign"] = dict()
            self.params_time["sign"][str(event_id)] = time.time() - start
        else:
            self.params_time["sign"][str(event_id)] = time.time() - start

    def _get_urandom_for_platform(self, max_number: int) -> int:
        rng = random.SystemRandom()
        if (max_number > sys.maxsize):
            return rng.randint(0, sys.maxsize)
        else:
            return rng.randint(0, sys.maxsize)

    def _get_all_public_keys_as_one_int(self, keys=None) -> int:
        if(keys is None):
            keys = self.public_keys
        result = ""
        for element in keys:
            result = result + str(element)
        return int(result)

    def key_image(self, event_id: int) -> None:
        start = time.time()
        a = int((str(self.p)+str(self.N)+str(event_id))) % self.N
        while(True):
            (success, result) = self._calculate_sqrt_mod_p(a)
            if(success):
                self.I[event_id] = result
                break
            else:
                a += 1
                pass
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
