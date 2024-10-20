import random

from hashlib import sha256

g = 22500 # generator of the finite group
P = 3213876088517980551083924184682325205044405987565585670609523 # Order of the finite group. A big prime number.

# using ZKP to verify master password
def verify_master_pass(h, k):
    """
    h: the public knowlege from master key. h = pow(g, master_pass, P)
    k: the password to verify
    """

    master_num = int((sha256(k.encode())).hexdigest(), 16)
    
    # step 1: prover create randome value r and then calculate a = pow(g, r, P) sending to prover
    r = random.SystemRandom().randrange(P)
    a = pow(g, r, P)

    # step 2: verifier create random value e sending to prover
    e = random.SystemRandom().randrange(P) # true random source from os.

    # step 3: prover calculate z = r + e * input_to_verify and send to verifier
    z = r + e * master_num

    # step 4: verifier verifies the input
    return pow(g, z, P) == (a * pow(h, e, P)) % P

def get_master_public_info(master_pass):
    master_num = int((sha256(master_pass.encode())).hexdigest(), 16)
    h = pow(g, master_num, P)
    return h
