import gmpy2
from gmpy2 import  mpz
from ring_sinagture import  LightweightRingSingatures,KeySize, Chinnese_reminder_theorem

# a = LightweightRingSingatures()
# a.generate_key(KeySize.Size_512)
# a.import_public_key(mpz(6))

print(str(type(Chinnese_reminder_theorem.calc((mpz(5),mpz(4)),(mpz(2),mpz(3))))))