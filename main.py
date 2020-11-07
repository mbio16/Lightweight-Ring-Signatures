from ring_sinagture import *

# Definuj uživatele
Bob = LightweightRingSingatures()
Tom = LightweightRingSingatures()
Alice = LightweightRingSingatures()

# Generuj klíče
Bob.generate_key(KeySize.KEY_SIZE_2048)
Tom.generate_key(KeySize.KEY_SIZE_2048)
Alice.generate_key(KeySize.KEY_SIZE_2048)

# Export veřejných klíčů
BobPublicKey = Bob.get_public_key()
TomPublicKey = Tom.get_public_key()
AlicePublicKey = Alice.get_public_key()

# import veřejných klíčů ostatních uživatelů
Bob.import_public_keys((TomPublicKey, AlicePublicKey))
Tom.import_public_keys((BobPublicKey, AlicePublicKey))
Alice.import_public_keys((BobPublicKey, TomPublicKey))


Bob.sign("ahoj", 3)

Bob.print_all()
