from ring_sinagture import LightweightRingSingatures,Signature
from tqdm import  tqdm
import dataclasses
import json
import random

keys = list()
users = list()

num_of_users = list()
time_key = list()
time_key_image = list()
time_sign = list()
recalc_x = list()
time_verify = list()

NUMBER_OF_GROUP_MEMBERS_MAX = 201

MESSAGE_TO_SIGN = "Hello world"
EVENT_ID = 5

rng = random.SystemRandom()
for i in tqdm(range(2,NUMBER_OF_GROUP_MEMBERS_MAX)):
    index_of_signer = rng.randint(0,i-1)
    while(True):
        index_of_verier = rng.randint(0,i-1)
        if (index_of_signer != index_of_verier):
            break

    for j in range(i):
        user = LightweightRingSingatures()
        user.generate_key()
        keys.append(user.get_public_key())
        users.append(user)

    signer: LightweightRingSingatures = users[index_of_signer]
    verifier:LightweightRingSingatures = users[index_of_verier]

    signer.import_public_keys(keys)
    s: Signature= signer.sign(MESSAGE_TO_SIGN,EVENT_ID)
    verifier.verify_signature(s)

    num_of_users.append(i)
    time_key.append(signer.params_time["key_generation"])
    time_key_image.append(signer.params_time["key_image"])
    time_sign.append(signer.params_time["sign"][str(EVENT_ID)]["time"])
    recalc_x.append(signer.params_time["sign"][str(EVENT_ID)]["recalculatated_x"])
    time_verify.append(verifier.params_time["verify"][-1]["verify_time"])
    #verifier.print_all()

with  open("results.csv","w") as file:
    for (i,k,image,sign,x,v) in zip(num_of_users,time_key,time_key_image,time_sign,recalc_x,time_verify):
        file.write("{};{};{};{};{};{}\n".format(i,k,image,sign,x,v))