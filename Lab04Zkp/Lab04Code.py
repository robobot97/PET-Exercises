#####################################################
# GA17 Privacy Enhancing Technologies -- Lab 04
#
# Zero Knowledge Proofs
#
# Run the tests through:
# $ py.test -v test_file_name.py

###########################
# Group Members: TODO
###########################

from petlib.ec import EcGroup
from petlib.bn import Bn

from hashlib import sha256
from binascii import hexlify

def setup():
    """ Generates the Cryptosystem Parameters. """
    G = EcGroup(nid=713)
    g = G.hash_to_point(b"g")
    hs = [G.hash_to_point(("h%s" % i).encode("utf8")) for i in range(4)]
    o = G.order()
    return (G, g, hs, o)

def keyGen(params):
   """ Generate a private / public key pair. """
   (G, g, hs, o) = params
   priv = o.random()
   pub = priv * g
   return (priv, pub)

def to_challenge(elements):
    """ Generates a Bn challenge by hashing a number of EC points """
    Cstring = b",".join([hexlify(x.export()) for x in elements])
    Chash =  sha256(Cstring).digest()
    return Bn.from_binary(Chash)

#####################################################
# TASK 1 -- Prove knowledge of a DH public key's
#           secret.

def proveKey(params, priv, pub):
    """ Uses the Schnorr non-interactive protocols produce a proof
        of knowledge of the secret priv such that pub = priv * g.

        Outputs: a proof (c, r)
                 c (a challenge)
                 r (the response)

        Private x
        1. random w; W = g^w
        2. Random c; in this case use: c = Hash(pub, W, m)
        3. r = (w - c * x) mod q
        4. Check: g^r * pub^c = W
    """
    (G, g, hs, o) = params

    ## YOUR CODE HERE:
    # Step 1a: generate random witness limited by the Group order
    w = o.random()
    # Step 1b: calculate g^w = W, accordingly to the formula
    W = g.pt_mul(w)

    # Step 2: generate a challenge as the Hash of the generator and W
    c = to_challenge([g, W])

    # Step 3: generate the response, according to the formula in the slides
    r = (w - c * priv) % o

    # Step 4: check that the proof can be verified
    assert((g.pt_mul(r) + pub.pt_mul(c)) == (W))

    # Step 5: send proof (challenge and response) to verifier
    return (c, r)

def verifyKey(params, pub, proof):
    """ Schnorr non-interactive proof verification of knowledge of a a secret.
        Returns a boolean indicating whether the verification was successful.
    """
    (G, g, hs, o) = params
    c, r = proof
    gw_prime  = c * pub + r * g
    return to_challenge([g, gw_prime]) == c

#####################################################
# TASK 2 -- Prove knowledge of a Discrete Log
#           representation.

def commit(params, secrets):
    """ Produces a commitment C = r * g + Sum xi * hi,
        where secrets is a list of xi of length 4.
        Returns the commitment (C) and the opening (r).
    """
    assert len(secrets) == 4
    (G, g, (h0, h1, h2, h3), o) = params
    x0, x1, x2, x3 = secrets
    r = o.random()
    C = x0 * h0 + x1 * h1 + x2 * h2 + x3 * h3 + r * g
    return (C, r)

def proveCommitment(params, C, r, secrets):
    """ Prove knowledge of the secrets within a commitment,
        as well as the opening of the commitment.

        Args: C (the commitment), r (the opening of the
                commitment), and secrets (a list of secrets).
        Returns: a challenge (c) and a list of responses.

        random ... wi...;
        W = Pi * gi^wi
        c = H(... gi..., C, W)
        ri = wi - c * v
            r1=v1-cx1(mod q) and r2=v2-cx2(mod q)
        Send (c, ...ri...)

        v == x; o == r

        Step 1: random w1, w2;
        Step 2: W = g^w1 * h*w2
        Step 3: c = H(g, h, C, W)
        Step 4: r1 = w1 - c * v
        Step 5: r2 = w2 - c * o
        Step 6: Send (c, r1, r2)
    """
    (G, g, (h0, h1, h2, h3), o) = params
    x0, x1, x2, x3 = secrets

    ## YOUR CODE HERE:

    # Step 1: generate 5 different random witnesses because there are 4 secrets + 1 commitment opening, limited by the Group order
    w0 = o.random()
    w1 = o.random()
    w2 = o.random()
    w3 = o.random()
    w4 = o.random()

    # Step 2a: calculate h^w for each unique h-w pair and sum these together
    hwSum = h0.pt_mul(w0) + h1.pt_mul(w1) + h2.pt_mul(w2) + h3.pt_mul(w3)
    # Step 2b: calculate witness W which should have the same shape as the commitment
        #Cw_prime = c * C + r0 * h0 + r1 * h1 + r2 * h2 + r3 * h3 + rr * g
    W = g.pt_mul(w4) + hwSum

    # Step 3: generate a challenge, hashing all generators of the group plus witness W
        #c = to_challenge([g, h0, h1, h2, h3, (Cw_prime)])
    c = to_challenge([g, h0, h1, h2, h3, W])

    # Step 4: generate responses for each of the 4 secrets, similar to method in task 1
    r0 = (w0 - c * x0) % o
    r1 = (w1 - c * x1) % o
    r2 = (w2 - c * x2) % o
    r3 = (w3 - c * x3) % o
    # Step 5: generate response for the commitment opening
    rr = (w4 - c * r) % o

    # Step 5.5: format all responses into a suitable output format
    responses = (r0, r1, r2, r3, rr)

    # Step 6: send the proof, commitment and all responses
    return (c, responses)

def verifyCommitments(params, C, proof):
    """ Verify a proof of knowledge of the commitment.
        Return a boolean denoting whether the verification succeeded. """
    (G, g, (h0, h1, h2, h3), o) = params
    c, responses = proof
    (r0, r1, r2, r3, rr) = responses

    Cw_prime = c * C + r0 * h0 + r1 * h1 + r2 * h2 + r3 * h3 + rr * g
    c_prime = to_challenge([g, h0, h1, h2, h3, Cw_prime])
    return c_prime == c

#####################################################
# TASK 3 -- Prove Equality of discrete logarithms.
#

def gen2Keys(params):
    """ Generate two related public keys K = x * g and L = x * h0. """
    (G, g, (h0, h1, h2, h3), o) = params
    x = o.random()

    K = x * g
    L = x * h0

    return (x, K, L)

def proveDLEquality(params, x, K, L):
    """ Generate a ZK proof that two public keys K, L have the same secret private key x,
        as well as knowledge of this private key. """
    (G, g, (h0, h1, h2, h3), o) = params
    w = o.random()
    Kw = w * g
    Lw = w * h0

    c = to_challenge([g, h0, Kw, Lw])

    r = (w - c * x) % o
    return (c, r)

def verifyDLEquality(params, K, L, proof):
    """ Return whether the verification of equality of two discrete logarithms succeeded.

    H(h, g, P1, P2, g^r * P1^c, h^r * P2^c) == c
    K = x * g = P1
    L = x * h0 = P2

    Essentially, just need to hash the relevant variables/info and compare that to commitment to verify
    ignore P1 and P2 from above hash formula because not used in the proveDLEquality function

    """
    (G, g, (h0, h1, h2, h3), o) = params
    c, r = proof

    ## YOUR CODE HERE:
    # Step 1: calculate g^r, first part of the equivalent of W1
    gr = g.pt_mul(r)
    # Step 2: calculate K^c, equivalent to P1^c
    Kc = K.pt_mul(c)
    # Step 3: calculate the equivalent of W1 in the proof algorithm
    W1Eq = gr + Kc

    # Step 4: calculate h^r
    hr = h0.pt_mul(r)
    # Step 5: calculate L^c, equivalent to P2^c
    Lc = L.pt_mul(c)
    # Step 6: calculate the equivalent of W2 in the proof algorithm
    W2Eq = hr + Lc

    # Step 7: hash the relevant info, variables calculated earlier, to calculate the actual value of the commitment
    calculatedValue = to_challenge([g, h0, W1Eq, W2Eq])

    # Step 8: compare the actual and verifying commitment values and return accordingly
    return  calculatedValue == c

#####################################################
# TASK 4 -- Prove correct encryption and knowledge of
#           a plaintext.

def encrypt(params, pub, m):
    """ Encrypt a message m under a public key pub.
        Returns both the randomness and the ciphertext.
    """
    (G, g, (h0, h1, h2, h3), o) = params
    k = o.random()
    return k, (k * g, k * pub + m * h0)

def proveEnc(params, pub, Ciphertext, k, m):
    """ Prove in ZK that the ciphertext is well formed
        and knowledge of the message encrypted as well.

        Return the proof: challenge and the responses.

        Looking for 2 responses, one for randomness and one for message

        a = k * g ; b =  k * pub + m * h0

        essentially carry out proof of knowledge on k and m, as well as proving DL representation of k using 'a' and 'b' of the ciphertext
    """
    (G, g, (h0, h1, h2, h3), o) = params
    a, b = Ciphertext

    ## YOUR CODE HERE:

    #  generate 2 random nonce variables, limited by the order of the Group
    wk = o.random()
    wm = o.random()

    # calculate pub^k equivalent, as in 'b' of the ciphertext, for proving DL representation of k
    pubk = pub.pt_mul(wk)
    # calculate g^k equivalent, for proving knowledge of k and for proving DL representation of k
    gk = g.pt_mul(wk)
    # calculate h^m equivalent, used for proving knowledge of m
    hm = h0.pt_mul(wm)

    # initialise a witness for g^k
    W1 = gk
    # initialise a witness for h^m and pub^k
    W2 = hm + pubk

    # hash all the generators (along with public key) and witnesses to create the challenge
    c = to_challenge([g, h0, pub, W1, W2])

    # generate a response to prove knowledge of k
    rk = (wk - c * k) % o
    # generate a response to prove knowledge of m
    rm = (wm - c * m) % o

    # return challenge and all responses
    return (c, (rk, rm))

def verifyEnc(params, pub, Ciphertext, proof):
    """ Verify the proof of correct encryption and knowledge of a ciphertext.

    Use verification function from task 3
    """
    (G, g, (h0, h1, h2, h3), o) = params
    a, b = Ciphertext
    (c, (rk, rm)) = proof

    ## YOUR CODE HERE:

    # calculate g^(response of k)
    grk = g.pt_mul(rk)
    # calculate a^c, used to test 'a' of ciphertext is correct
    ac = a.pt_mul(c)
    # calculate the witness equivalent of g^k from proof function
    W1Eq = grk + ac

    # calculate h^(response of m)
    hrm = h0.pt_mul(rm)
    # calculate pub^(response of k)
    pubrk = pub.pt_mul(rk)
    # calculate b^c, used to test 'b' of ciphertext is correct
    bc = b.pt_mul(c)
    # calculate the witness equivalent of h^m and pub^k from proof function
    W2Eq = hrm + pubrk + bc

    # hash the generators (along with public key) and the equivalent of the witnesses to create the calculated challenge value
    c_calculated = to_challenge([g, h0, pub, W1Eq, W2Eq])

    # return the comparison of the calculated and actual challenge values
    return c_calculated == c


#####################################################
# TASK 5 -- Prove a linear relation
#

def relation(params, x1):
    """ Returns a commitment C to x0 and x1, such that x0 = 10 x1 + 20,
        as well as x0, x1 and the commitment opening r.
    """
    (G, g, (h0, h1, h2, h3), o) = params
    r = o.random()

    x0 = (10 * x1 + 20)
    C = r * g + x1 * h1 + x0 * h0

    return C, x0, x1, r

def prove_x0eq10x1plus20(params, C, x0, x1, r):
    """ Prove C is a commitment to x0 and x1 and that x0 = 10 x1 + 20.

    C = g^r * h1^x1 * h0^x0
    The actual commitments are:
        Cx0 = g^x0 * h^o1
        Cx1 = g^x1 * h^o2
        x0 = (10 * x1 + 20)

    Substituing gives 2 commitments:
        Cx0 = g^(10 * x1 + 20) * h^o1 = g^(10*x1) * g^20 * h^o1 = (g^10)^x1 * g^20 * h^o1
        Cx1 = g^x1 * h^o2

    Use DL representation and Equality Proofs

    need to prove x1, r, and x0 = 10 * x1 + 20

    can ignore the 20 since it is a known value

    so need to prove x1, r, 10 * x1

    essentially proving knowledge of x1, r and 10x1
    """
    (G, g, (h0, h1, h2, h3), o) = params

    ## YOUR CODE HERE:

    # generate two random (nonce) values, one for x1 and one for r
    wx1 = o.random()
    wr = o.random()

    # calculate h^(10x1) equivalent, the relation to be tested between x0 and x1
    h10x1 = h0.pt_mul(10 * wx1)  # this is equivalent to ((h0.pt_mul(wx1)).pt_mul(10)) which equals h0^(10*x1)
    # calculate h^x1 equivalent, used for proving knowlegde of x1
    hx1 = h1.pt_mul(wx1)
    # calculate g^r equivalent, used for proving r (the commitement opening)
    gr = g.pt_mul(wr)

    # calculate witness using all previous previously calculated wtinesses
    W = gr + h10x1 + hx1

    # hash the generators and witness to create the challenge
    c = to_challenge([g, h0, h1, W])

    # generate response for x1
    rx1 = (wx1 - c * x1) % o
    # generate response for r
    rr = (wr - c * r) % o

    # combine all responses into one variable
    responses = (rx1, rr)

    # return the challenge and all responses
    return (c, responses)

def verify_x0eq10x1plus20(params, C, proof):
    """ Verify that proof of knowledge of C and x0 = 10 x1 + 20.

    The value of C changes to C - h^20 because we moved 20 to the left in the prove function

    """
    (G, g, (h0, h1, h2, h3), o) = params

    ## YOUR CODE HERE:

    # get and set the challenge and response variables from the prove function
    c, responses = proof
    # separate and set the responses accordingly
    rx1, rr = responses

    # update value of C, according to the substitution carried out in the prove function
    C = C - (20 * h0)
    # using the verify function from task 2 to calculate the equivalent of the witnesses
    # for x0 use the relation 10x1 to prove the relation holds
    Cw_prime = c * C + (10 * rx1) * h0 + rx1 * h1 + rr * g
    # hash the generators and witness equivalent to generate the calculated challenge
    c_prime = to_challenge([g, h0, h1, Cw_prime])

    # return the comparison between calculated and proof challenges, if match then relation holds and commitment is accurate
    return c_prime == c

#####################################################
# TASK 6 -- (OPTIONAL) Prove that a ciphertext is either 0 or 1


def binencrypt(params, pub, m):
    """ Encrypt a binary value m under public key pub """
    assert m in [0, 1]
    (G, g, (h0, h1, h2, h3), o) = params

    k = o.random()
    return k, (k * g, k * pub + m * h0)

def provebin(params, pub, Ciphertext, k, m):
    """ Prove a ciphertext is valid and encrypts a binary value either 0 or 1. """
    pass

def verifybin(params, pub, Ciphertext, proof):
    """ verify that proof that a cphertext is a binary value 0 or 1. """
    pass

def test_bin_correct():
    """ Test that a correct proof verifies """
    pass

def test_bin_incorrect():
    """ Prove that incorrect proofs fail. """
    pass

#####################################################
# TASK Q1 - Answer the following question:
#
# The interactive Schnorr protocol (See PETs Slide 8) offers
# "plausible deniability" when performed with an
# honest verifier. The transcript of the 3 step interactive
# protocol could be simulated without knowledge of the secret
# (see Slide 12). Therefore the verifier cannot use it to prove
# to a third party that the holder of secret took part in the
# protocol acting as the prover.
#
# Does "plausible deniability" hold against a dishonest verifier
# that  deviates from the Schnorr identification protocol? Justify
# your answer by describing what a dishonest verifier may do.

""" TODO: Your answer here.

For an honest verifier, the challenge sent to the prover should be random. However,
since a dishonest verifier can technically design a challenge 'c' which is not random
but instead has a relation with W = g^w, w being a random witness, which the dishonest verifier
receives from the prover, "plausible deniability" does not hold against a dishonest verifier.
More specifically, the dishnoest verifier could generate the challenge as a hash of W, hence
deviating from the Schnorr identification protocol, then sending this back to the prover.

"""

#####################################################
# TASK Q2 - Answer the following question:
#
# Consider the function "prove_something" below, that
# implements a zero-knowledge proof on commitments KX
# and KY to x and y respectively. Note that the prover
# only knows secret y. What statement is a verifier,
# given the output of this function, convinced of?
#
# Hint: Look at "test_prove_something" too.

""" TODO: Your answer here.

Since the prover builds a proof such that c1 + c2 = c (mod o), the verifier needs to
verify this holds. However, since only one of the secrets is provided to the proover
it can only have an appripriate response for y. Therefore, when it comes to the
verifier, it can be convinced that it will be able to verify y, but only y and not x.

"""

def prove_something(params, KX, KY, y):
    (G, g, _, o) = params

    # Simulate proof for KX
    # r = wx - cx => g^w = g^r * KX^c
    rx = o.random()
    c1 = o.random()
    W_KX = rx * g + c1 * KX

    # Build proof for KY
    wy = o.random()
    W_KY = wy * g
    c = to_challenge([g, KX, KY, W_KX, W_KY])

    # Build so that: c1 + c2 = c (mod o)
    c2 = (c - c1) % o
    ry = ( wy - c2 * y ) % o

    # return proof
    return (c1, c2, rx, ry)

import pytest

def test_prove_something():
    params = setup()
    (G, g, hs, o) = params

    # Commit to x and y
    x = o.random()
    y = o.random()
    KX = x*g
    KY = y*g

    # Pass only y
    (c1, c2, rx, ry) = prove_something(params, KX, KY, y)

    # Verify the proof
    W_KX = rx * g + c1 * KX
    W_KY = ry * g + c2 * KY
    c = to_challenge([g, KX, KY, W_KX, W_KY])
    assert c % o == (c1 + c2) % o
