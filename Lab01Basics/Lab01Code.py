#####################################################
# GA17 Privacy Enhancing Technologies -- Lab 01
#
# Basics of Petlib, encryption, signatures and
# an end-to-end encryption system.
#
# Run the tests through:
# $ py.test-2.7 -v Lab01Tests.py

###########################
# Group Members: TODO
###########################


#####################################################
# TASK 1 -- Ensure petlib is installed on the System
#           and also pytest. Ensure the Lab Code can
#           be imported.

import petlib

#####################################################
# TASK 2 -- Symmetric encryption using AES-GCM
#           (Galois Counter Mode)
#
# Implement a encryption and decryption function
# that simply performs AES_GCM symmetric encryption
# and decryption using the functions in petlib.cipher.

from os import urandom
from petlib.cipher import Cipher
aes = Cipher("aes-128-gcm")
iv = urandom(16)
key = urandom(16)

def encrypt_message(K, message):
    """ Encrypt a message under a key K """

    plaintext = message.encode("utf8")

    ciphertext, tag = aes.quick_gcm_enc(K, iv, plaintext)

    return (iv, ciphertext, tag)

def decrypt_message(K, iv, ciphertext, tag):
    """ Decrypt a cipher text under a key K

        In case the decryption fails, throw an exception.
    """

    try:
        plain = aes.quick_gcm_dec(K, iv, ciphertext, tag)
    except Exception as e:
        raise e

    return plain.encode("utf8")

#####################################################
# TASK 3 -- Understand Elliptic Curve Arithmetic
#           - Test if a point is on a curve.
#           - Implement Point addition.
#           - Implement Point doubling.
#           - Implement Scalar multiplication (double & add).
#           - Implement Scalar multiplication (Montgomery ladder).
#
# MUST NOT USE ANY OF THE petlib.ec FUNCIONS. Only petlib.bn!

from petlib.bn import Bn


def is_point_on_curve(a, b, p, x, y):
    """
    Check that a point (x, y) is on the curve defined by a,b and prime p.
    Reminder: an Elliptic Curve on a prime field p is defined as:

              y^2 = x^3 + ax + b (mod p)
                  (Weierstrass form)

    Return True if point (x,y) is on curve, otherwise False.
    By convention a (None, None) point represents "infinity".
    """
    assert isinstance(a, Bn)
    assert isinstance(b, Bn)
    assert isinstance(p, Bn) and p > 0
    assert (isinstance(x, Bn) and isinstance(y, Bn)) \
           or (x == None and y == None)

    if x is None and y is None:
        return True

    lhs = (y * y) % p
    rhs = (x*x*x + a*x + b) % p
    on_curve = (lhs == rhs)

    return on_curve


def point_add(a, b, p, x0, y0, x1, y1):
    """Define the "addition" operation for 2 EC Points.

    Reminder: (xr, yr) = (xq, yq) + (xp, yp)
    is defined as:
        lam = (yq - yp) * (xq - xp)^-1 (mod p)
        xr  = lam^2 - xp - xq (mod p)
        yr  = lam * (xp - xr) - yp (mod p)

    Return the point resulting from the addition. Raises an Exception if the points are equal.
    """

    # ADD YOUR CODE BELOW
    xr, yr = None, None

    # check if points are equal, if so, raise Exception
    if x0 is x1 and y0 is y1:
        raise Exception("EC Points must not be equal") # the string has to be an exact match, spent way too long because of this, bloody hell

    #check if the points even exist on the Curve:
    if (is_point_on_curve(a, b, p, x0, y0) == False) or (is_point_on_curve(a, b, p, x1, y1) == False):
        return (None,None)


    #check if a point is infinity
    if (x0 is None and y0 is None):
        return (x1,y1)
    elif (x1 is None and y1 is None):
        return (x0,y0)
    elif x0 is x1:
        return (None,None)

    #calculate the point addition, if it fails, something is wrong with the formula
    try:
        lam = (y0.mod_sub(y1,p)).mod_mul((x0.mod_sub(x1,p)).mod_inverse(m=p),p)
        xr = lam.mod_mul(lam,p).mod_sub(x1,p).mod_sub(x0,p)
        yr = lam.mod_mul((x1.mod_sub(xr,p)),p).mod_sub(y1,p)
    except Exception as e:
        raise Exception("Point Addition formula failed")

    #return the beauties
    return xr, yr


def point_double(a, b, p, x, y):
    """Define "doubling" an EC point.
     A special case, when a point needs to be added to itself.

     Reminder:
        lam = (3 * xp ^ 2 + a) * (2 * yp) ^ -1 (mod p)
        xr  = lam ^ 2 - 2 * xp
        yr  = lam * (xp - xr) - yp (mod p)

    Returns the point representing the double of the input (x, y).
    """

    # ADD YOUR CODE BELOW
    xr, yr = None, None

    if (is_point_on_curve(a,b,p,x,y) == False):
        return (None,None)

    if (x is None) and (y is None):
        return (None,None)

    lam = (Bn(3).mod_mul(x.mod_pow(2,p),p).mod_add(a,p)).mod_mul(((Bn(2).mod_mul(y,p)).mod_inverse(p)),p)
    xr = (lam.mod_pow(2,p)).mod_sub((Bn(2).mod_mul(x,p)),p)
    yr = lam.mod_mul((x.mod_sub(xr,p)),p).mod_sub(y,p)

    return xr, yr

def point_scalar_multiplication_double_and_add(a, b, p, x, y, scalar):
    """
    Implement Point multiplication with a scalar:
        r * (x, y) = (x, y) + ... + (x, y)    (r times)

    Reminder of Double and Multiply algorithm: r * P
        Q = infinity
        for i = 0 to num_bits(P)-1
            if bit i of r == 1 then
                Q = Q + P
            P = 2 * P
        return Q

    """
    """
    ## Following algorithm was found from Wikipedia's page for 'Elliptic curve point multiplication'
    #the below algorithm is essentially the same as above but slightly easier to understand

    N <- P
    Q <- 0
    for i from 0 to m do
     if di = 1 then
        Q <- point_add(Q, N)
     N <- point_double(N)
     return Q
    """

    Q = (None, None)
    P = (x, y)

    for i in range(scalar.num_bits()):
        #pass ## ADD YOUR CODE HERE
        #check if ith bit in scalar is set, equal to 1
        if scalar.is_bit_set(i) == 1:
            Q = point_add(a,b,p,Q[0],Q[1],P[0],P[1]) #much better than re-making the function, saved a lot of time
        P = point_double(a,b,p,P[0],P[1])
    return Q


def point_scalar_multiplication_montgomerry_ladder(a, b, p, x, y, scalar):
    """
    Implement Point multiplication with a scalar:
        r * (x, y) = (x, y) + ... + (x, y)    (r times)

    Reminder of Double and Multiply algorithm: r * P
        R0 = infinity
        R1 = P
        for i in num_bits(P)-1 to zero:
            if di = 0:
                R1 = R0 + R1
                R0 = 2R0
            else
                R0 = R0 + R1
                R1 = 2 R1
        return R0

    """

    # Notation is Y = k * G. Y, G are EC points, and k is an integer
    # Int. exponentiation becomes EC scalar multiplication

    R0 = (None, None)
    R1 = (x, y)

    for i in reversed(range(0,scalar.num_bits())):
        #pass ## ADD YOUR CODE HERE
        #similar to previous function but slight differences in terms of implementation
        if scalar.is_bit_set(i) == 0: # bit equal to 0
            R1 = point_add(a,b,p,R0[0],R0[1],R1[0],R1[1])
            R0 = point_double(a,b,p,R0[0],R0[1])
        else:
            R0 = point_add(a,b,p,R0[0],R0[1],R1[0],R1[1])
            R1 = point_double(a,b,p,R1[0],R1[1])
    return R0


#####################################################
# TASK 4 -- Standard ECDSA signatures
#
#          - Implement a key / param generation
#          - Implement ECDSA signature using petlib.ecdsa
#          - Implement ECDSA signature verification
#            using petlib.ecdsa

from hashlib import sha256
# messages should be short. Use SHA256 to hash it first
from petlib.ec import EcGroup
from petlib.ecdsa import do_ecdsa_sign, do_ecdsa_verify

def ecdsa_key_gen():
    """ Returns an EC group, a random private key for signing
        and the corresponding public key for verification"""
    G = EcGroup()
    priv_sign = G.order().random()
    pub_verify = priv_sign * G.generator()
    return (G, priv_sign, pub_verify)


def ecdsa_sign(G, priv_sign, message):
    """ Sign the SHA256 digest of the message using ECDSA and return a signature """
    # requires a secret key and a short message, and returns a "signature"
    plaintext =  message.encode("utf8")
    ## YOUR CODE HERE
    # 'digest' or shorten the message using SHA256
    digest = sha256(plaintext).digest()
    # create a signature
    sig = do_ecdsa_sign(G, priv_sign, digest)

    return sig

def ecdsa_verify(G, pub_verify, message, sig):
    """ Verify the ECDSA signature on the message """
    # requires a public key, a short message and a signature. It returns True if the signature "checks" ie. is the result of sign with the correct key
    plaintext =  message.encode("utf8")

    ## YOUR CODE HERE
    # shorten the message by hashing it first using SHA256
    digest = sha256(plaintext).digest()
    try:
        # if verification returns true then great, if not, raise an exception
        res = do_ecdsa_verify(G, pub_verify, sig, digest)
    except Exception as e:
        raise Exception("Verification failed!")

    # if all is well then returns true, indicating verification is successful
    return res


#####################################################
# TASK 5 -- Diffie-Hellman Key Exchange and Derivation
#           - use Bob's public key to derive a shared key.
#           - Use Bob's public key to encrypt a message.
#           - Use Bob's private key to decrypt the message.
#
# NOTE:

"""
Petlib.bn, petlib.ec, petlib.cipher, and petlib.ecdsa

Use the library scalar multiplication

No need to encode messages into a binary format, just use Python tuples

What happens if no signatures are used?
Are you sure the designed scheme is resistant to a man in the middle?
What happens if either Alice or Bob are forced to reveal their secrets?

Signed fresh public keys (protects against coercion):
Sender can delete private key as soon as message is encrypted.
Receiver may delete secret as soon as message is received.
Signatures ensure protection against man in the middle attacks.
"""

def dh_get_key():
    """ Generate a DH key pair """
    G = EcGroup()
    priv_dec = G.order().random()
    pub_enc = priv_dec * G.generator()
    return (G, priv_dec, pub_enc)


def dh_encrypt(pub, message, aliceSig = None):
    """ Assume you know the public key of someone else (Bob),
    and wish to Encrypt a message for them.
        - Generate a fresh DH key for this message.
        - Derive a fresh shared key.
        - Use the shared key to AES_GCM encrypt the message.
        - Optionally: sign the message with Alice's key.

        - pub: public key of Bob the recepient
        - aliceSig: signature key of Alice the sender
    """

    ## YOUR CODE HERE
    #pass

    # Generate a fresh DH key for this message, like in tests file
    G,priv_dec,alicePub = dh_get_key()
    # Derive a fresh shared key
    sharedKey = (priv_dec*pub).export()
    sharedKey = sha256(sharedKey).digest()
    sharedKey = sharedKey[:16]
    # Use the shared key to AES_GCM encrypt the message, task 2 encrypt function
    aes = Cipher("aes-128-gcm")
    iv = urandom(16)
    plaintext = message.encode("utf8")
    ciphertext, tag = aes.quick_gcm_enc(sharedKey, iv, plaintext)

    ciphertext = (iv,ciphertext, tag, alicePub)

    return (ciphertext)


def dh_decrypt(priv, ciphertext, aliceVer = None):
    """ Decrypt a received message encrypted using your public key,
    of which the private key is provided. Optionally verify
    the message came from Alice using her verification key.

    - priv: receipient's (Bob) secret decryption key
    - aliceVer: a public verification key for a signature scheme
    """

    ## YOUR CODE HERE
    #pass
    aes = Cipher("aes-128-gcm")
    iv, ciphertexts, tag, alicePub = ciphertext

    sharedKey = (priv*alicePub).export()
    sharedKey = sha256(sharedKey).digest()
    sharedKey = sharedKey[:16]


    # try decrypting
    try:
        plaintext = aes.quick_gcm_dec(sharedKey, iv, ciphertexts, tag)
    except Exception as e:
        raise e


    return plaintext



## NOTE: populate those (or more) tests
#  ensure they run using the "py.test filename" command.
#  What is your test coverage? Where is it missing cases?
#  $ py.test-2.7 --cov-report html --cov Lab01Code Lab01Code.py

def test_encrypt():
    #basic encryption with no sign/verify mechanism
    message = "hello world"
    G, priv_dec, pub_enc = dh_get_key()
    ciphertext = dh_encrypt(pub_enc, message, None)
    iv, ciphertexts, tag, alicePub = ciphertext
    #checks
    ivTest = urandom(16)
    assert len(iv) is len(ivTest)
    assert len(tag) == 16
    assert alicePub != pub_enc


def test_decrypt():
    #basic decryption with no sign/verify mechanism
    message = "hello world"
    G, priv_dec, pub_enc = dh_get_key()
    ciphertext  = dh_encrypt(pub_enc, message, None)
    iv, ciphertexts, tag, alicePub = ciphertext
    plaintext = dh_decrypt(priv_dec, ciphertext, None)

    #checks
    assert plaintext == message


def test_fails():
    #test cases which fail for the functions above

    #using public key for private key parameter
    message = "hello world"
    G, priv_dec, pub_enc = dh_get_key()
    ciphertext = dh_encrypt(pub_enc, message, None)
    iv, ciphertexts, tag, alicePub = ciphertext
    plaintext = dh_decrypt(pub_enc, ciphertext, None)

    #checks
    assert plaintext == message



#####################################################
# TASK 6 -- Time EC scalar multiplication
#             Open Task.
#
#           - Time your implementations of scalar multiplication
#             (use time.clock() for measurements)for different
#              scalar sizes)
#           - Print reports on timing dependencies on secrets.
#           - Fix one implementation to not leak information.

def time_scalar_mul():
    pass
