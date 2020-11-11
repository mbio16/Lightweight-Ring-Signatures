from ring_sinagture import *
Bob = LightweightRingSingatures()
Bob.test_numbers(
    479,587)
Bob.key_image(3)
#s.sign("a", 3)


Alice = LightweightRingSingatures()
Alice.test_numbers(
    953,1307)
Alice.key_image(3)


Tom = LightweightRingSingatures()
Tom.test_numbers(
    1523,1907)
Tom.key_image(3)


BobPublicKey = Bob.get_public_key()
TomPublicKey = Tom.get_public_key()
AlicePublicKey = Alice.get_public_key()
public_keys = (BobPublicKey, TomPublicKey, AlicePublicKey)
Bob.import_public_keys(public_keys)
Alice.import_public_keys(public_keys)

s = Alice.sign("Volím Ancap", 3)
Bob.verify_signature(s)

Bob.print_all()