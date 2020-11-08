from ring_sinagture import *

# Definuj uživatele
Bob = LightweightRingSingatures()
Tom = LightweightRingSingatures()
Alice = LightweightRingSingatures()

# Generuj klíče
Bob.generate_key(KeySize.KEY_SIZE_512)
Tom.generate_key(KeySize.KEY_SIZE_512)
Alice.generate_key(KeySize.KEY_SIZE_512)

# Export veřejných klíčů
BobPublicKey = Bob.get_public_key()
TomPublicKey = Tom.get_public_key()
AlicePublicKey = Alice.get_public_key()

# import veřejných klíčů ostatních uživatelů
public_keys = (BobPublicKey, TomPublicKey, AlicePublicKey)
Bob.import_public_keys(public_keys)
Tom.import_public_keys(public_keys)
Alice.import_public_keys(public_keys)


s: Signature = (Bob.sign("ahoj", 3))
# print(str(s))
Tom.verify_signature(s)
# print(str(Bob.params_time))
# Bob.print_all()
