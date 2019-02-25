#####################################################
# GA17 Privacy Enhancing Technologies -- Lab 03
#
# Basics of Privacy Friendly Computations through
#         Additive Homomorphic Encryption.
#
# Run the tests through:
# $ py.test -v test_file_name.py

#####################################################
# TASK 1 -- Setup, key derivation, log
#           Encryption and Decryption
#

###########################
# Group Members: TODO
###########################


from petlib.ec import EcGroup

def setup():
    """Generates the Cryptosystem Parameters."""
    G = EcGroup(nid=713)
    g = G.hash_to_point(b"g")
    h = G.hash_to_point(b"h")
    o = G.order()
    return (G, g, h, o)

def keyGen(params):
   """ Generate a private / public key pair """
   (G, g, h, o) = params

   # ADD CODE HERE
   """
   Public: g, h (and group parameters)
   Key generation: generate a random "x" (0 < x < order of the group);
   Private key is "x", public key is pk= g^x
   """

   # generate a random private using the Group order, ensuring value between 0 and Group order
   priv = o.random()
   # generate public key using a generator and the previously generated private key
   pub = priv * g

   return (priv, pub)

def encrypt(params, pub, m):
    """ Encrypt a message under the public key """
    if not -100 < m < 100:
        raise Exception("Message value to low or high.")

   # ADD CODE HERE
    """ Encryption of m with pk:random k; E(m; k) = (g^k, g^(xk)*h^m) """

    # initialise the necessary variables from the parameter 'params' tuple
    (G, g, h, o) = params

    # generate a random value k using the Group order, ensuring value between 0 and Group order
    k = o.random()
    # equivalent to g^k part of the encryption formula as stated in the lecture slides
    a = k * g
    # pub equals g^x, thus k * pub is equivalent to g^(xk); the overall calculation equates to the
    # second part of the encryption formula in the lecture slides
    b = (k * pub) + (m * h)
    # cipher is the combination of both a and b as described in the lecture
    c = (a, b)

    return c

def isCiphertext(params, ciphertext):
    """ Check a ciphertext """
    (G, g, h, o) = params
    ret = len(ciphertext) == 2
    a, b = ciphertext
    ret &= G.check_point(a)
    ret &= G.check_point(b)
    return ret

_logh = None
def logh(params, hm):
    """ Compute a discrete log, for small number only """
    global _logh
    (G, g, h, o) = params

    # Initialize the map of logh
    if _logh == None:
        _logh = {}
        for m in range (-1000, 1000):
            _logh[(m * h)] = m

    if hm not in _logh:
        raise Exception("No decryption found.")

    return _logh[hm]

def decrypt(params, priv, ciphertext):
    """ Decrypt a message using the private key """
    assert isCiphertext(params, ciphertext)
    a , b = ciphertext

   # ADD CODE HERE
    """ Decryption of (a,b) with x: m = logh(b*(a^x)^(-1))
        (= logh((g^(xk)h^m)/(g^(xk))))
    """

    # initialise the necessary variables from the parameter 'params' tuple
    (G, g, h, o) = params

    # following calculates the equivalent of g^(xk) as a = g^k
    ax = priv * a
    # invert the value of g^(xk) to allow the equivalent of division in the formula
    axInverse = (-1) * ax
    # essentially, decrypting the ciphertext to calculate the plaintext, as described in the lecture slides
    hm = b + axInverse

    return logh(params, hm)

#####################################################
# TASK 2 -- Define homomorphic addition and
#           multiplication with a public value
#

def add(params, pub, c1, c2):
    """ Given two ciphertexts compute the ciphertext of the
        sum of their plaintexts.
    """
    assert isCiphertext(params, c1)
    assert isCiphertext(params, c2)

   # ADD CODE HERE
    """
    Addition of E(m0;k0) = (a0, b0) and E(m1; k1) = (a1, b1)
    E(m0+m1; k0+k1) = (a0a1, b0b1)
        = (g^(k0)g^(k1), g^(xk0)h^(m0)g^(xk1)h^(m1)) = (g^(k0+k1), g^(x(k0+k1))h^(m0+m1))
    """

    # set the variables for part a and b of both ciphertexts
    a0, b0 = c1
    a1, b1 = c2
    # sum both parts a, equivalent to multiplying a0 and a1 in the formula in the slides
    a = a0 + a1
    # sum both parts b, equivalent to multiplying b0 and b1 in the formula in the slides
    b = b0 + b1
    # set the final ciphertext to be returned as the sums of the individual parts
    c3 = (a, b)

    return c3

def mul(params, pub, c1, alpha):
    """ Given a ciphertext compute the ciphertext of the
        product of the plaintext time alpha """
    assert isCiphertext(params, c1)

   # ADD CODE HERE
    """
    Multiplication of E(m0; k0) = (a0, b0) with a constant c:
    E(cm0; ck0) = ((a0)^c, (b0)^c)
    """

    # set the variables for part a and b of the ciphertext
    a0, b0 = c1
    # multiply part a by constant alpha, equivalent to a0^c in the formula in slides
    a = alpha * a0
    # multiply part b by constant alpha, equivalent to b0^c in the formula in slides
    b = alpha * b0
    # set the final ciphertext as the combination of the products of the multiplications above
    c3 = (a, b)

    return c3

#####################################################
# TASK 3 -- Define Group key derivation & Threshold
#           decryption. Assume an honest but curious
#           set of authorities.

def groupKey(params, pubKeys=[]):
    """ Generate a group public key from a list of public keys """
    (G, g, h, o) = params

   # ADD CODE HERE
    """
    Private keys: x1, ..., xn
    Public key: g^(x1+...+xn)

    need to do: g^(x1)*g^(x2)*g^(x3)*...*g^(xn)
        = pub1 * pub2 * pub3 * ... * pubn
    """

    # if there are any public keys present, then:
    if (len(pubKeys) > 0):
        # 'sum' equals the first public key
        sum = pubKeys[0]

        # if there are multiple public keys present, then:
        if (len(pubKeys) > 1):
            #for all remaining public keys not added:
            for i in range(1,len(pubKeys)):
                # add the public key to the existing value of the variable 'sum'
                sum += pubKeys[i]

        # final public key equals the final value of sum after reviewing all public keys in the list
        pub = sum
    else:
        # if there are no public keys in the list then return None, indicating no authorities
        return None

    return pub

def partialDecrypt(params, priv, ciphertext, final=False):
    """ Given a ciphertext and a private key, perform partial decryption.
        If final is True, then return the plaintext. """
    assert isCiphertext(params, ciphertext)

    # ADD CODE HERE
    """ Decryption of (a,b): m = b / a^x1 / a^x2 / ... / a^xn

    from task 1: b/ax:
        ax = priv * a
        axInverse = (-1) * ax
        hm = b + axInverse
    """

    # set the variables for part a and b of the ciphertext
    a1, b1 = ciphertext
    # following calculates the equivalent of g^(xk) as a1 = g^k
    a1x = priv * a1
    # invert the value of g^(xk) to allow the equivalent of division in the formula
    a1xInverse = (-1) * a1x
    # set the value of 'b1' as the addition of the existing value of 'b1' and inverted g^(xk)
    # equivalent to one iteration of the division operation in the formula in the slides
    b1 = b1 + a1xInverse

    if final:
        return logh(params, b1)
    else:
        return a1, b1

#####################################################
# TASK 4 -- Actively corrupt final authority, derives
#           a public key with a known private key.
#

def corruptPubKey(params, priv, OtherPubKeys=[]):
    """ Simulate the operation of a corrupt decryption authority.
        Given a set of public keys from other authorities return a
        public key for the corrupt authority that leads to a group
        public key corresponding to a private key known to the
        corrupt authority. """
    (G, g, h, o) = params

   # ADD CODE HERE
    """ Attack: A malicious party can simply ask the threshold decryption parties
    to decrypt a secret, not the output of the computation!
    (Trade name: a decryption oracle attack)

    in essence the overall corrupt public key provided should be able to negate all existing pub keys
    from other authorities and make the group public key equal to the actual public key of corrupt authority
    """

    # declare a variable to keep a sum of all the existing public keys, initialise its value to first public key in list
    sum = OtherPubKeys[0]
    # for all remaining keys from other authorities:
    for keys in OtherPubKeys[1:]:
        # increment the value of 'sum' by adding the key to the existing sum
        sum += keys
    # invert the total sum of all keys from other authorities to act as a counter negation when calculating the Group Key
    sum = (-1) * sum

    # calculate the actual public key associated to the (corrupt) authority, essentially g^x
    legitPublicKey = priv * g

    # return the final public key which is the addition of the inverted sum and the genuine public key
    pub = sum + legitPublicKey

    return pub

#####################################################
# TASK 5 -- Implement operations to support a simple
#           private poll.
#

def encode_vote(params, pub, vote):
    """ Given a vote 0 or 1 encode the vote as two
        ciphertexts representing the count of votes for
        zero and the votes for one."""
    assert vote in [0, 1]

   # ADD CODE HERE
   # initialise the necessary variables from the parameter 'params' tuple
    (G, g, h, o) = params

    # generate a random value k0 using the Group order, ensuring value between 0 and Group order
    k0 = o.random()
    # equivalent to g^k part of the encryption formula as stated in the lecture slides
    a0 = k0 * g
    # calculating the second part of the encryption formula, 'm' is set such that when vote is
    # for 0 the tally for 0 increases by one, and when vote is for 1 the tally for 0 stays the same
    b0 = (k0 * pub) + (((vote + 1) % 2) * h)
    # set the ciphertext representing votes for 0
    v0 = (a0, b0)

    # generate a random value k0 using the Group order, ensuring value between 0 and Group order
    k1 = o.random()
    # equivalent to g^k part of the encryption formula as stated in the lecture slides
    a1 = k1 * g
    # calculating the second part of the encryption formula, 'm' is set such that when vote is
    # for 0 the tally for 1 stays the same, and when vote is for 1 the tally for 1 increases by one
    b1 = (k1 * pub) + (vote * h)
    # set the ciphertext representing votes for 1
    v1 = (a1, b1)

    return (v0, v1)

def process_votes(params, pub, encrypted_votes):
    """ Given a list of encrypted votes tally them
        to sum votes for zeros and votes for ones. """
    assert isinstance(encrypted_votes, list)

   # ADD CODE HERE
    """ essentially for each pair/entry in the encrypted_votes list:
            take an entry
            for entry(0) add to tv0
            for entry(1) add to tv1
    """

    # declare variables to tally votes for ones and zeros and initialise their value as the first encrypted vote
    tv0, tv1 = encrypted_votes[0]

    # for the remaining encrypted votes in the list:
    for i in range(1,len(encrypted_votes)):
        # declare and set temporary variables as the next encrypted vote
        v0,v1 = encrypted_votes[i]

        # following additions are equivalent to the 'add' function implemented above
        # add together part a of the existing tally of votes for zeros and next vote's value for vote 0
        a0 = tv0[0] + v0[0]
        # add together part b of the existing tally of votes for zeros and next vote's value for vote 0
        b0 = tv0[1] + v0[1]
        # update the tally of votes for zero, hence tally increments or stays the same as appropriate
        tv0 = (a0, b0)

        # add together part a of the existing tally of votes for ones and next vote's value for vote 1
        a1 = tv1[0] + v1[0]
        # add together part b of the existing tally of votes for ones and next vote's value for vote 1
        b1 = tv1[1] + v1[1]
        # update the tally of votes for ones, hence tally increments or stays the same as appropriate
        tv1 = (a1, b1)

    return tv0, tv1

def simulate_poll(votes):
    """ Simulates the full process of encrypting votes,
        tallying them, and then decrypting the total. """

    # Generate parameters for the crypto-system
    params = setup()

    # Make keys for 3 authorities
    priv1, pub1 = keyGen(params)
    priv2, pub2 = keyGen(params)
    priv3, pub3 = keyGen(params)
    pub = groupKey(params, [pub1, pub2, pub3])

    # Simulate encrypting votes
    encrypted_votes = []
    for v in votes:
        encrypted_votes.append(encode_vote(params, pub, v))

    # Tally the votes
    total_v0, total_v1 = process_votes(params, pub, encrypted_votes)

    # Simulate threshold decryption
    privs = [priv1, priv2, priv3]
    for priv in privs[:-1]:
        total_v0 = partialDecrypt(params, priv, total_v0)
        total_v1 = partialDecrypt(params, priv, total_v1)

    total_v0 = partialDecrypt(params, privs[-1], total_v0, True)
    total_v1 = partialDecrypt(params, privs[-1], total_v1, True)

    # Return the plaintext values
    return total_v0, total_v1

###########################################################
# TASK Q1 -- Answer questions regarding your implementation
#
# Consider the following game between an adversary A and honest users H1 and H2:
# 1) H1 picks 3 plaintext integers Pa, Pb, Pc arbitrarily, and encrypts them to the public
#    key of H2 using the scheme you defined in TASK 1.
# 2) H1 provides the ciphertexts Ca, Cb and Cc to H2 who flips a fair coin b.
#    In case b=0 then H2 homomorphically computes C as the encryption of Pa plus Pb.
#    In case b=1 then H2 homomorphically computes C as the encryption of Pb plus Pc.
# 3) H2 provides the adversary A, with Ca, Cb, Cc and C.
#
# What is the advantage of the adversary in guessing b given your implementation of
# Homomorphic addition? What are the security implications of this?

""" Your Answer here

Assuming that adversary A is aware of the criteria of computing C, i.e. that when b=0, C = Pa+Pb
and when b=1, C = Pb+Pc and that the adversary can carry out the necessary homomorphic operations
to subtract the ciphertexts, we can conclude that since C = Ca + Cb or C = Cb + Cc, by carrying out
C - (Ca + Cb) and C - (Cb + Cc) and checking whether the results equals zero, the adversary can
determine the value of b.
If the result of C - (Ca + Cb) = 0 then b must be 0; if the result of C - (Cb + Cc) = 0 then b must be 1.
Note: If the adversary was to somehow guess b accurately, then they wouldn't need to carry out the
homomorphic calculations described above. This means saving resources and time.

The security implications depend on the capabilites of the adversary and the adversary's knowledge.
As mentioned, the attack is only possible if the adversary is aware of the criteria for computing C
and either able to guess the value of b accurately or carry out the homomorphic operations described above.
But if successful the implications are that the adversary A might be able to reverse engineer the
homomorphic computation carried out by H2 and identify the plaintexts used; thus greatly reducing the
reliability of the implementation.

"""

###########################################################
# TASK Q2 -- Answer questions regarding your implementation
#
# Given your implementation of the private poll in TASK 5, how
# would a malicious user implement encode_vote to (a) distrupt the
# poll so that it yields no result, or (b) manipulate the poll so
# that it yields an arbitrary result. Can those malicious actions
# be detected given your implementation?

""" Your Answer here

(a) A malicious user could implement the encode_vote such that they would set the default value
to a 0 when encoding votes for both v0 and v1 such that the tally of votes for 0 and tally
of votes for 1 are both equal to zero. This would result in a completely pointless result as it would mean that
neither 0 or 1 was voted for even though there were votes casted and the only possible options were 0 and 1. The
code statements needed to alter for this would be to change b0 and b1, as follows:
    b0 = (k0 * pub) + (0 * h)
    b1 = (k1 * pub) + (0 * h)

(b) A malicious user could easily implement the encode_vote function such that it would result in an
inaccurate and arbitrary result. One such possible implementation is to always increase the tally of one of the vote options
despite the actual vote, such that if the malicious user wants to favour votes for 0 they could set the following statements for b0 and b1:
    b0 = (k0 * pub) + (1 * h)
    b1 = (k1 * pub) + (0 * h)
This will mean that despite the actual vote the tally of votes for 1 will be zero and the tally of votes for 0 will be maximum.
Alternatively, for a completely random and arbitrary result the malicious user could implement a random number generator between 0 and 1
and use this to calculate the values of b0 and b1, instead of the actual votes.

None of the malicious actions mentioned above can be detected by the implementation of the actual encode_vote
function above, because there are no checks to verify whether the sum of the tally for both votes for 0 and votes for 1
equal the total number of votes. Additionally, there is no way to ascertain the tally until after the decryption occurs.
Furthermore, there is no checks for a bias in the implementation, which could determine whether the tally has been
tampered with. Finally, testing for whether the tally has been done on a random basis or on the actual votes
is not implemented.

"""
