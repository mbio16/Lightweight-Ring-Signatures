from ring_sinagture import LightweightRingSingatures
from ring_sinagture import KeySize
from tonneli import Tonneli
a = LightweightRingSingatures()
a.generate_key(KeySize.KEY_SIZE_1048)
# print(str(a.get_public_key()))

a.sign("ahoj", 16)

a.print_all()
