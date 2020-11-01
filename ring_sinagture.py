from cryptography.hazmat.primitives.asymmetric import rsa
from models import KeySize, Signature
from hashlib import sha256
from tonneli import Tonneli


class LightweightRingSingatures:

    def __init__(self):
        self.p = None
        self.q = None
        self.N = None
        self.I = None
        self.public_keys = list()

    def generate_key(self, key_size: KeySize) -> None:
        private_key = rsa.generate_private_key(
            key_size=key_size.value, public_exponent=65537)
        self.p = ((private_key.private_numbers().p) * 2) + 1
        self.q = ((private_key.private_numbers().q) * 2) + 1
        self.N = self.p*self.q

    def get_public_key(self) -> int:
        return self.N

    def print_all(self) -> None:
        print("p: {} \n\n\nq: {}\n\n\nN:{}\n\nI:{}\n\n".format(
            self.p, self.q, self.N, self.I))

    def sign(self, message: str, event_id: int) -> Signature:
        self.__calc_key_image(message, event_id)

    def __calc_key_image(self, message, event_id: int) -> None:
        a = int((str(self.p)+str(self.N)+str(event_id)))
        # print(str(i)+"\n\n")
        b = sha256(str(a).encode()).hexdigest()
        # print(str(i)+"\n\n")
        c = int(b, 16)
        # print(str(i))
        self.I = Tonneli.compute(c, self.N)
