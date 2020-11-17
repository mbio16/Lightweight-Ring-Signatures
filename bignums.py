import gmpy2
from gmpy2 import  mpz
from ring_sinagture import  LightweightRingSingatures,KeySize, Chinnese_reminder_theorem, Tonelli

# a = LightweightRingSingatures()
# a.generate_key(KeySize.Size_512)
# a.import_public_key(mpz(6))


a = Tonelli.calc(mpz(1223),mpz(29))
b = Tonelli.calc(mpz(1223),mpz(53))
print((Chinnese_reminder_theorem.calc((a,b),(29,53))))