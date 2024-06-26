import numpy as np
import hashlib
from Crypto.Util import number
import gmpy2
from gmpy2 import mpz
import random

def setup_phase(bit):
    p = number.getPrime(bit)
    prime_number = mpz(p)
    security_number = gmpy2.isqrt(prime_number)
    log_p_10 = gmpy2.log10(p)
    m = security_number*log_p_10
    n = 2*m
    m = int(m)
    n = int(n)
    return p, m, n

def key_generation(m, n, q):
    B = generate_random_matrix(m, n, q)
    t = generate_random_matrix(n, 1, q)
    Pu = np.dot(np.transpose(t), np.transpose(B))  
    return B, t, Pu

def sign_message(P, t, s):
    r = generate_random_matrix(n, 1, q)
    r[0][0] = 0  
    G1 = np.dot(s, np.transpose(r))  
    G2 = P - np.dot(np.transpose(G1), np.transpose(t)) 
    return G1, G2

def verify_signature( P, G1, G2, Pu, B):
    W = np.dot(np.transpose(G1), Pu)
    w_modp = W % q
    if (W.shape == (n, m) and (np.all((w_modp >= 0) & (w_modp < q)))):
        P1_B_T = (np.dot(G2,np.transpose(B)) + W) % q
        P_B_T = np.dot(P,np.transpose(B)) % q
        #print("P1_B_T", P1_B_T)
        #print("P_B_T", P_B_T)
        return np.array_equal(hash_function(P1_B_T.tolist()), hash_function(P_B_T.tolist()))
    else :
        print("check 1 false")
        return False

def hash_function(input_matrix):

    input_bytes = bytearray()
    for row in input_matrix:
        for num in row:
            if isinstance(num, int):
                input_bytes.extend(num.to_bytes((num.bit_length() + 7) // 8, byteorder='big'))
    
    # Compute hash using SHA-256
    hashed_bytes = hashlib.sha256(input_bytes).digest()
    
    hashed_vector = []
    for i in range(len(input_matrix[0])):
        idx = i * len(input_matrix) * 2  # Each element occupies 2 bytes
        hashed_int = int.from_bytes(hashed_bytes[idx:idx+2], byteorder='big') % q
        hashed_vector.append(hashed_int)
    
    #print("hashed_vector: ", hashed_vector)
    return hashed_vector

def generate_random_matrix(n, m, p):
    n = int(n)
    m = int(m)
    return [[random.randint(0, p-1) for _ in range(m)] for _ in range(n)]

def generate_zero_matrix(n, m):
    return [[0 for _ in range(m)] for _ in range(n)]


q, m, n = setup_phase(12)
B, t, Pu = key_generation(m, n, q)
P = generate_random_matrix(n, n, q)
s = generate_random_matrix(1, 1, q)
G1, G2 = sign_message(P, t, s)

verification_result = verify_signature(P, G1, G2, Pu, B)

print("Verification Result:", verification_result)
