import numpy as np
import hashlib
from Crypto.Util import number
import gmpy2
from gmpy2 import mpz
import random
import timeit
import math


def setup_phase(bit):
    p = number.getPrime(bit)
    prime_number = mpz(p)
    security_number = gmpy2.isqrt(prime_number)
    log_p_10 = gmpy2.log10(p)
    n = security_number*log_p_10
    m = math.ceil(n * math.log(p))
    m= int(m)
    n= int(n)
    return p, m, n

def key_generation(m, n, p):
    B = generate_random_matrix(n, n, p)
    C = generate_random_matrix(n, m, p)
    D = np.dot(B, C)  
    return B, C, D

def mod_dot(A, B, p):
    return np.mod(np.dot(A, B), p)


def sign_message(P, B, D):
    a = generate_random_matrix(n, 1, p) 

    A1 = mod_dot(B,P, p)
    A2 = mod_dot(a.T, A1, p)
    A3 = mod_dot(a.T, B, p)  
    A4 = mod_dot(a.T, D, p)

    A5= hash_function(A2.flatten(), m)

    A6 = (A4 + A5) % p

    return  A3, A6

def verify_signature(P, A3, A6):
    A4_dash = mod_dot(A3, C, p)
    A5_dash = (A6 - A4_dash) % p

    W = mod_dot(A3, P, p).flatten()

    if ((np.all((W >= 0) & (W < p)))): 
        return np.array_equal(hash_function(W, m), A5_dash.flatten())
    else :
        print("check 1 false")
        return False

def hash_function(input_vector, m):
    input_bytes = bytearray()
    for num in input_vector:
        num = int(num)
        input_bytes.extend(num.to_bytes((num.bit_length() + 7) // 8, 'big'))

    hashed = hashlib.sha256(input_bytes).digest()

    hashed_vector = []
    counter = 0
    while len(hashed_vector) < m:
        h = hashlib.sha256(hashed + counter.to_bytes(4, 'big')).digest()
        for i in range(0, len(h), 2):
            if len(hashed_vector) < m:
                hashed_vector.append(int.from_bytes(h[i:i+2], 'big') % p)
        counter += 1
    print("hashed_vector: ", hashed_vector)
    return hashed_vector
 
    
# def hash_function(input_vector):

#     """
#     Hash function that takes input from Z_p and outputs in Z_p^m.

#     Args:
#     - input_vector: Input vector from Z_p (list of integers)
#     - p: Prime number representing the modulus

#     Returns:
#     - hashed_vector: Hashed vector in Z_p^m (list of integers)
#     """
#     # Convert input vector to bytes
#     input_bytes = bytearray()
#     for num in input_vector:
#         if isinstance(num, (int, np.integer)):
#             input_bytes.extend(num.to_bytes((int(num).bit_length() + 7) // 8, byteorder='big'))

#     # Compute hash using SHA-256
#     hashed_bytes = hashlib.sha256(input_bytes).digest()
    
#     # Convert hashed bytes back to integers in Z_q
#     hashed_vector = []
#     for i in range(len(input_vector)):
#         hashed_int = int.from_bytes(hashed_bytes[i*2:(i+1)*2], byteorder='big') % p
#         hashed_vector.append(hashed_int)
    
#     print("hashed_vector: ", hashed_vector)
#     return np.array(hashed_vector)

def generate_random_matrix(n, m, p):
    p = int(p) 
    n= int(n)
    m= int(m)
    return np.array([[random.randint(0, p-1) for _ in range(m)] for _ in range(n)])

start_time = timeit.default_timer()
p, m, n = setup_phase(8)
B, C, D = key_generation(m, n, p)
P = generate_random_matrix(n, 1, p)
A3, A6 = sign_message(P, B, D)

verification_result = verify_signature(P, A3, A6)
print("Verification Result:", verification_result)

end_time = timeit.default_timer()

execution_time = end_time - start_time
print("execution time: ", execution_time)