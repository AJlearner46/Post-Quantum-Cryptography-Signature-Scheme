import numpy as np
import hashlib
from Crypto.Util import number
import gmpy2
from gmpy2 import mpz
import random
import timeit

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


def key_generation(m, n, p):
    #B = np.random.randint(0, p, (n, m))
    B = generate_random_matrix(n, m, p)
    #C = np.random.randint(0, p, (m, n))
    C = generate_random_matrix(m, n, p)
    D = np.dot(B, C)  
    return B, C, D

def sign_message(P, B, D):
    n = len(P)
    #a = np.random.randint(0, p, n)
    a = generate_random_matrix(n, 1, p)
    A1 = np.dot(np.transpose(B),a)  
    A2 = np.transpose(P) + np.dot(np.transpose(a), D)
    #print("A1: ", A1) #m*1
    #print("A2: ", A2) #1*n
    return A1, A2

def verify_signature( P, A1, A2, C):
    W = np.dot(np.transpose(A1), C) #1*n
    print("W: ", W)
    w_modp = W % p
    if (W.shape == (1, n) and (np.all((w_modp >= 0) & (w_modp < p)))):
        P1_T = (A2 - W) % p 
        #print("P1_T: ", P1_T)
        #print("P: ", P) 
        return np.array_equal(hash_function((np.transpose(P1_T.tolist())).tolist()), hash_function(P))
    else :
        print("check 1 false")
        return False


def hash_function(input_vector):

    """
    Hash function that takes input from Z_q^m and outputs in Z_q^m.

    Args:
    - input_vector: Input vector from Z_q^m (list of integers)
    - q: Prime number representing the modulus

    Returns:
    - hashed_vector: Hashed vector in Z_q^m (list of integers)
    """
    # Convert input vector to bytes
    input_bytes = bytearray()
    for num in input_vector:
        if isinstance(num, int):
            input_bytes.extend(num.to_bytes((num.bit_length() + 7) // 8, byteorder='big'))
        

    # Compute hash using SHA-256
    hashed_bytes = hashlib.sha256(input_bytes).digest()
    
    # Convert hashed bytes back to integers in Z_q
    hashed_vector = []
    for i in range(len(input_vector)):
        #hashed_int = int.from_bytes(hashed_bytes[i:i+2], byteorder='big') % p
        hashed_int = int.from_bytes(hashed_bytes[i*2:(i+1)*2], byteorder='big') % p
        hashed_vector.append(hashed_int)
    
    print("hashed_vector: ", hashed_vector)
    return hashed_vector

def generate_random_matrix(n, m, p):
    n = int(n)
    m = int(m)  # Convert p to an integer
    return [[random.randint(0, p-1) for _ in range(m)] for _ in range(n)]


start_time = timeit.default_timer()
p, m, n = setup_phase(12)
#p =  number.getPrime(2048)
#m = 5
#n = 3
B, C, D = key_generation(m, n, p)
#P = np.random.randint(0, p, (n, 1))
P = generate_random_matrix(n, 1, p)

A1, A2 = sign_message(P, B, D)

verification_result = verify_signature(P, A1, A2, C)

print("Verification Result:", verification_result)
end_time = timeit.default_timer()

execution_time = end_time - start_time
print("execution time: ", execution_time)