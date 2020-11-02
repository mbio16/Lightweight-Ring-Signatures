from enum import Enum
from dataclasses import dataclass


class KeySize(Enum):

    KEY_SIZE_1024 = 1024
    KEY_SIZE_2048 = 2048
    KEY_SIZE_4096 = 4096


@dataclass
class Signature:
    I: int
    c_1: int
    x: list
