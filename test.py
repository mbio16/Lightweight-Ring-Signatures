from ring_sinagture import *
s = LightweightRingSingatures()
s.test_numbers(29, 53)
s.key_image(3)
#s.sign("a", 3)
s.print_all()
