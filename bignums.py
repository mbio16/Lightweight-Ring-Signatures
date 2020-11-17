import gmpy2
from gmpy2 import  mpz
from ring_sinagture import  LightweightRingSingatures,KeySize, Chinnese_reminder_theorem, Tonelli
import dataclasses
import json
a = LightweightRingSingatures()
a.generate_key(KeySize.Size_32)
a.key_image(3)

b = LightweightRingSingatures()
b.generate_key(KeySize.Size_32)

c = LightweightRingSingatures()
c.generate_key(KeySize.Size_32)

keys = (a.get_public_key(),b.get_public_key(),c.get_public_key())

b.import_public_keys(keys)

s = b.sign("Hello world",3)

# print(dataclasses.asdict(s))

print(c.verify_signature(s))