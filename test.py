from ring_sinagture import *
Bob = LightweightRingSingatures()
Bob.test_numbers(29, 53)
Bob.key_image(3)
#s.sign("a", 3)


Alice = LightweightRingSingatures()
Alice.test_numbers(51, 11)
Alice.key_image(3)
Alice.print_all()


Tom = LightweightRingSingatures()
Tom.test_numbers(23, 19)
Tom.key_image(3)
Tom.print_all()

BobPublicKey = Bob.get_public_key()
TomPublicKey = Tom.get_public_key()
AlicePublicKey = Alice.get_public_key()
public_keys = (BobPublicKey, TomPublicKey, AlicePublicKey)
Bob.import_public_keys(public_keys)

print(Bob.N)
print(str(Bob.public_keys))
s = Bob.sign("1", 3)

Alice.verify_signature(s)
