from ring_sinagture import LightweightRingSingatures, KeySize
from tonneli import Tonneli

# Definuj uživatele
Bob = LightweightRingSingatures()
Tom = LightweightRingSingatures()
Alice = LightweightRingSingatures()

# Generuj klíče
Bob.generate_key(KeySize.KEY_SIZE_1024)
Tom.generate_key(KeySize.KEY_SIZE_1024)
Alice.generate_key(KeySize.KEY_SIZE_1024)

# Export veřejných klíčů
BobPublicKey = Bob.get_public_key()
TomPublicKey = Tom.get_public_key()
AlicePublicKey = Alice.get_public_key()

# import veřejných klíčů ostatních uživatelů
Bob.import_public_keys((TomPublicKey, AlicePublicKey))
Tom.import_public_keys((BobPublicKey, AlicePublicKey))
Alice.import_public_keys((BobPublicKey, TomPublicKey))


Bob.print_all()

Bob.sign("ahoj", 25)
