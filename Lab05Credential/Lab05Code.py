#####################################################
# GA17 Privacy Enhancing Technologies -- Lab 05
#
# Selective Disclosure (Anonymous) Credentials
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

#####################################################
# Background, setup, key derivation and utility
# functions.
#

def credential_setup():
    """ Generates the parameters of the algebraic MAC scheme"""
    G = EcGroup()
    g = G.hash_to_point(b"g")
    h = G.hash_to_point(b"h")
    o = G.order()

    params = (G, g, h, o)
    return params

def credential_KeyGenIssuer(params):
    """ Generates keys and parameters for the credential issuer for 1 attribute"""
    _, g, h, o = params

    # Generate x0, x1 as the keys to the algebraic MAC scheme
    x0, x1 = o.random(), o.random()
    sk = [x0, x1]
    iparams = x1 * h

    # Generate a pedersen commitment Cx0 to x0 with opening x0_bar
    x0_bar = o.random()
    Cx0 = x0 * g + x0_bar * h

    return (Cx0, iparams), (sk, x0_bar)

def credential_KeyGenUser(params):
    """ Generates keys and parameters for credential user """
    G, g, h, o = params
    priv = o.random()
    pub = priv * g # This is just an EC El-Gamal key
    return (priv, pub)

## This is our old friend "to_challenge" from Lab04 on Zero Knowledge

def to_challenge(elements):
    """ Generates a Bn challenge by hashing a number of EC points """
    Cstring = b",".join([hexlify(x.export()) for x in elements])
    Chash =  sha256(Cstring).digest()
    return Bn.from_binary(Chash)

#####################################################
# TASK 1 -- User Encrypts a secret value v and sends
#           and sends it to the issuer. This v will
#           become the single attribute of the user.
#           Prove in ZK that the user knows v and the
#           private key of pub.

## IMPORTANT NOTE: The reference scheme for all the
# techniques in this exercise are in section
# "4.2 Keyed-verification credentials from MAC_GGM"
# pages 8-9 of https://eprint.iacr.org/2013/516.pdf

def credential_EncryptUserSecret(params, pub, priv):
    """ Encrypt a user defined random secret v under the public key of the user.
        Prove knowledge of the secret v, the private key "priv" and correctness of
        the encryption """
    G, g, h, o = params
    v = o.random()

    ## Encrypt v using Benaloh with randomness k
    k = o.random()
    ciphertext = k * g, k * pub + v * g
    a, b = ciphertext

    ## Prove knowledge of the encrypted v and priv in ZK
    #  NIZK{(v, k, priv): a = k * g and
    #                     b = k * pub + v * g and
    #                     pub = priv * g}

    ## TODO
    """
    Similar to task 4 of Lab04, prove knowledge of k, v, and priv
    """
    # generate random witnesses for each term to be proved
    wk = o.random()
    wv = o.random()
    wpriv = o.random()

    # calculate generators to power of the witnesses, to generate 'W' witnesses
    gk = g.pt_mul(wk)
    pubk = pub.pt_mul(wk)
    gv = g.pt_mul(wv)
    gpriv = g.pt_mul(wpriv)

    # define each 'W' witness for each of the terms to be proved, based on the equations to prove above
    Wk = gk
    Wv = pubk + gv
    Wpriv = gpriv

    # create the challenge
    c = to_challenge([g, pub, a, b, Wk, Wv, Wpriv])

    # create the necessary responses
    rk = (wk - c * k) % o
    rv = (wv - c * v) % o
    rpriv = (wpriv - c * priv) % o


    # Return the fresh v, the encryption of v and the proof.
    proof = (c, rk, rv, rpriv)
    return v, ciphertext, proof


def credential_VerifyUserSecret(params, pub, ciphertext, proof):
    """ Verify the ciphertext is a correct encryption and the
        proof of knowledge of the secret key "priv" """
    G, g, h, o = params

    ## The cipher text and its proof of correctness
    a, b = ciphertext
    (c, rk, rv, rpriv) = proof

    # Verify knowledge of the encrypted k, v and priv
    Wap = c * a + rk * g
    Wbp = c * b + rk * pub + rv * g
    Wpubp = c * pub + rpriv * g

    cp = to_challenge([g, pub, a, b, Wap, Wbp, Wpubp])
    return cp == c


#####################################################
# TASK 2 -- The issuer issues an
#           algebraic MAC on v, along with a ZK proof
#           that the MAC is correctly formed. The user
#           decrypts and verifies the MAC.

## IMPRTANT NOTE: Study the section "Issuance" p.8
#  of https://eprint.iacr.org/2013/516.pdf

def credential_Issuing(params, pub, ciphertext, issuer_params):
    """ A function used by the credential issuer to provide a MAC
        on a secret (encrypted) attribute v """

    G, g, h, o = params

    ## The public and private parameters of the issuer
    (Cx0, iparams), (sk, x0_bar) = issuer_params
    X1 = iparams
    x0, x1 = sk

    # The ciphertext of the encrypted attribute v
    a, b = ciphertext

    # 1) Create a "u" as u = b*g
    # 2) Create a X1b as X1b == b * X1 == (b * x1) * h
    #     and x1b = (b * x1) mod o

    # TODO 1 & 2

    # create a random beta ,'b' in above equations is actually referred to as beta later on so b above == beta
    beta = o.random();
    # create 'u' from task 1
    u = g.pt_mul(beta)

    # calculate X1b from task 2 above, in both ways defined
    X1_beta = X1.pt_mul(beta)
    h_x1_beta = h.pt_mul(beta * x1)
    # check if both calculation methods are equal
    assert(X1_beta == h_x1_beta)

    # define X1b and x1b for task task 2 above
    X1b = X1_beta
    x1b = (beta * x1) % o


    # 3) The encrypted MAC is u, and an encrypted u_prime defined as
    #    E( (b*x0) * g + (x1 * b * v) * g ) + E(0; r_prime)

    # TODO 3

    # generate random "r'"
    r_prime = o.random()

    # calculate new_a, used for the ciphertext
    # calculate g^r'
    r_prime_g = g.pt_mul(r_prime)
    # calculate a^x1b
    x1b_a = a.pt_mul(x1b)
    # calculate the sum to form new_a
    new_a = r_prime_g + x1b_a

    # calculate new_b, used for the second part of the ciphertext
    # calculate pub^r'
    r_prime_pub = pub.pt_mul(r_prime)
    # calculate b^x1b
    x1b_b = b.pt_mul(x1b)
    # calculate u^x0
    x0_u = u.pt_mul(x0)
    # calculate sum to form new_b
    new_b = r_prime_pub + x1b_b + x0_u

    # define ciphertext using new a and b values
    ciphertext = new_a, new_b

    ## A large ZK proof that:
    #  NIZK{(x1, beta, x1b, r_prime, x0, x0_bar)
    #       X1  = x1 * h
    #       X1b = beta * X1
    #       X1b = x1b * h
    #       u   = beta * g
    #       new_a = r_prime * g + x1b * a
    #       new_b = r_prime * pub + x1b * b + x0 * u
    #       Cx0 = x0 * g + x0_bar * h }

    ## TODO proof
    # generate random witnesses for each term to be proved
    w_x1 = o.random()
    w_beta = o.random()
    w_x1b = o.random()
    w_r_prime = o.random()
    w_x0 = o.random()
    w_x0_bar = o.random()

    # calculate all calculatios to generate the 'W' witnesses for each term
    h_x1 = h.pt_mul(w_x1)
    X1_beta = X1.pt_mul(w_beta)
    h_x1b = h.pt_mul(w_x1b)
    g_beta = g.pt_mul(w_beta)
    ga_new_a = g.pt_mul(w_r_prime) + a.pt_mul(w_x1b)
    pubbu_new_b = pub.pt_mul(w_r_prime) + b.pt_mul(w_x1b) + u.pt_mul(w_x0)
    gh_Cx0 = g.pt_mul(w_x0) + h.pt_mul(w_x0_bar)

    # generate the challenge for the proof
    c = to_challenge([g, h, pub, a, b, X1, X1b, new_a, new_b, Cx0, h_x1, X1_beta, h_x1b, g_beta, ga_new_a, pubbu_new_b, gh_Cx0])

    # generate responses for each term to be proved
    r_x1 = (w_x1 - c * x1) % o
    r_beta = (w_beta - c * beta) % o
    r_x1b = (w_x1b - c * x1b) % o
    r_r_prime = (w_r_prime - c * r_prime) % o
    r_x0 = (w_x0 - c * x0) % o
    r_x0_bar = (w_x0_bar - c * x0_bar) % o

    # combine all responses into one group
    rs = (r_x1, r_beta, r_x1b, r_r_prime, r_x0, r_x0_bar)

    proof = (c, rs, X1b) # Where rs are multiple responses

    return u, ciphertext, proof

def credential_Verify_Issuing(params, issuer_pub_params, pub, u, Enc_v, Enc_u_prime, proof):
    """ User verifies that the proof associated with the issuance
        of the credential is valid. """

    G, g, h, o = params

    ## The public parameters of the issuer.
    (Cx0, iparams) = issuer_pub_params
    X1 = iparams

    ## The ciphertext of the encrypted attribute v and the encrypted u_prime
    a, b = Enc_v
    new_a, new_b = Enc_u_prime

    ## The proof of correctness
    (c, rs, X1b) = proof

    c_prime = to_challenge([g, h, pub, a, b, X1, X1b, new_a, new_b, Cx0,
                    c * X1 + rs[0] * h,
                    c * X1b + rs[1] * X1,
                    c * X1b + rs[2] * h,
                    c * u + rs[1] * g,
                    c * new_a + rs[3] * g + rs[2] * a,
                    c * new_b + rs[3] * pub + rs[2] * b + rs[4] * u,
                    c * Cx0 + rs[4] * g + rs[5] * h
                    ])

    return c_prime == c

def credential_Decrypt(params, priv, u, Enc_u_prime):
    """ Decrypt the second part of the credential u_prime """

    G, g, h, o = params
    new_a, new_b = Enc_u_prime
    u_prime = new_b - priv * new_a
    return (u, u_prime)

#####################################################
# TASK 3 -- The user re-blinds the MAC and proves
#           its possession without revealing the secret
#           attribute.

## IMPORTANT NOTE: Study the section "Credential presentation"
#  p.9 of https://eprint.iacr.org/2013/516.pdf

def credential_show(params, issuer_pub_params, u, u_prime, v):
    """ The user blinds the credential (u, u_prime) and then
        proves its correct possession."""

    G, g, h, o = params

    ## The public parameters of the credential issuer
    (Cx0, iparams) = issuer_pub_params
    X1 = iparams

    # 1) First blind the credential (u, u_prime)
    #    using (alpha * u, alpha * u_prime) for a
    #    random alpha.

    # TODO 1

    # generate random variable alpha
    alpha = o.random()
    # blind u using alpha
    u = u.pt_mul(alpha)
    # blind u' using alpha
    u_prime = u_prime.pt_mul(alpha)

    # 2) Implement the "Show" protocol (p.9) for a single attribute v.
    #    Cv is a commitment to v and Cup is C_{u'} in the paper.

    # TODO 2

    # follow the protocol in the paper

    # generate two random variables, r and z1
    r = o.random()
    z1 = o.random()

    # calulate u^v to calculate Cv (commitment)
    u_v = u.pt_mul(v)
    # calculate h^z1 to calculate Cv (commitment)
    h_z1 = h.pt_mul(z1)
    # calculate Cv, commitment to v
    Cv = u_v + h_z1

    # calculate g^r to calculate Cup (C_{u'})
    g_r = g.pt_mul(r)
    # calculate Cup, (C_{u'})
    Cup = u_prime + g_r

    # generate group to return, tag
    tag = (u, Cv, Cup)

    # Proof or knowledge of the statement
    #
    # NIZK{(r, z1,v):
    #           Cv = v *u + z1 * h and
    #           V  = r * (-g) + z1 * X1 }

    ## TODO proof

    # proof is similar to previous task

    w_r = o.random()
    w_z1 = o.random()
    w_v = o.random()

    u_v = u.pt_mul(w_v)
    h_z1 = h.pt_mul(w_z1)
    gi_r = (-g).pt_mul(w_r)
    X1_z1 = X1.pt_mul(w_z1)

    # generate 'W' of both the Cv and Cup
    W_Cv = u_v + h_z1
    W_V = gi_r + X1_z1
    # generate challenge
    c = to_challenge([u, h, g, X1, Cv, Cup, Cx0, W_Cv, W_V])

    # generate all responses
    rr = (w_r - c * r) % o
    rz1 =  (w_z1 - c * z1) % o
    rv = (w_v - c * v) % o

    # combine the challenge and responses to create proof
    proof = (c, rr, rz1, rv)
    return tag, proof

def credential_show_verify(params, issuer_params, tag, proof):
    """ Take a blinded tag and a proof of correct credential showing and verify it """

    G, g, h, o = params

    ## Public and private issuer parameters
    (Cx0, iparams), (sk, x0_bar) = issuer_params
    x0, x1 = sk
    X1 = iparams

    # Verify proof of correct credential showing
    (c, rr, rz1, rv) = proof
    (u, Cv, Cup) = tag

    ## TODO

    # follow the protocol in paper

    u_x0 = u.pt_mul(x0)
    Cv_x1 = Cv.pt_mul(x1)
    V = (u_x0 + Cv_x1) - Cup

    Cv_c = Cv.pt_mul(c)
    u_rv = u.pt_mul(rv)
    h_rz1 = h.pt_mul(rz1)
    # generate 'W' witness of Cv
    W_Cv = Cv_c + u_rv + h_rz1

    V_c = V.pt_mul(c)
    gi_rr = (-g).pt_mul(rr)
    X1_rz1 = X1.pt_mul(rz1)
    # generate 'W' witness of V
    W_V = V_c + gi_rr + X1_rz1

    # create challenge
    c_prime = to_challenge([u, h, g, X1, Cv, Cup, Cx0, W_Cv, W_V])

    # check two challenges to determine verification
    return c == c_prime

#####################################################
# TASK 4 -- Modify the standard Show / ShowVerify process
#           to link the credential show to a long term
#           pseudonym for a service. The pseudonyms should
#           be unlikable between services.

def credential_show_pseudonym(params, issuer_pub_params, u, u_prime, v, service_name):
    """ From a credential (u, u_prime) generate a pseudonym H(service_name)^v
        and prove you hold a valid credential with attribute v """

    G, g, h, o = params

    ## Public issuer parameters
    (Cx0, iparams) = issuer_pub_params
    X1 = iparams

    ## A stable pseudonym associated with the service
    N = G.hash_to_point(service_name)
    pseudonym = v * N

    ## TODO (use code from above and modify as necessary!)

    # same as last task but added another relation to prove which is pseudonym = v * N

    # below section is exactly the same as before
    alpha = o.random()
    u = u.pt_mul(alpha)
    u_prime = u_prime.pt_mul(alpha)


    r = o.random()
    z1 = o.random()

    u_v = u.pt_mul(v)
    h_z1 = h.pt_mul(z1)
    Cv = u_v + h_z1

    g_r = g.pt_mul(r)
    Cup = u_prime + g_r

    tag = (u, Cv, Cup)

    # Proof
    # NIZK{(r, z1,v):
    #           Cv = v * u + z1 * h and
    #           V  = r * (-g) + z1 * X1 and
    #           pseudonym = v * N = ps}

    # same proof as task 3 with some additions
    w_r = o.random()
    w_z1 = o.random()
    w_v = o.random()

    u_v = u.pt_mul(w_v)
    h_z1 = h.pt_mul(w_z1)
    gi_r = (-g).pt_mul(w_r)
    # create a new calculation for the relation/verification of the pseudonym
    X1_z1 = X1.pt_mul(w_z1)

    W_Cv = u_v + h_z1
    W_V = gi_r + X1_z1
    # generate 'W' witness for the pseudonym
    W_ps = N.pt_mul(w_v)

    # included witness of pseudonym in the generation of the challenge and N attribute
    c = to_challenge([u, h, g, X1, N, Cv, Cup, Cx0, W_Cv, W_V, W_ps])

    # responses remains same because v does not change
    rr = (w_r - c * r) % o
    rz1 =  (w_z1 - c * z1) % o
    rv = (w_v - c * v) % o

    proof = (c, rr, rz1, rv)

    return pseudonym, tag, proof

def credential_show_verify_pseudonym(params, issuer_params, pseudonym, tag, proof, service_name):
    """ Verify a pseudonym H(service_name)^v is generated by the holder of the
        a valid credential with attribute v """

    G, g, h, o = params

    ## The public and private issuer parameters
    (Cx0, iparams), (sk, x0_bar) = issuer_params
    x0, x1 = sk
    X1 = iparams

    ## The EC point corresponding to the service
    N = G.hash_to_point(service_name)

    ## Verify the correct Show protocol and the correctness of the pseudonym

    # TODO (use code from above and modify as necessary!)

    # similar as task 3
    (c, rr, rz1, rv) = proof
    (u, Cv, Cup) = tag

    u_x0 = u.pt_mul(x0)
    Cv_x1 = Cv.pt_mul(x1)
    V = (u_x0 + Cv_x1) - Cup

    Cv_c = Cv.pt_mul(c)
    u_rv = u.pt_mul(rv)
    h_rz1 = h.pt_mul(rz1)
    W_Cv = Cv_c + u_rv + h_rz1

    V_c = V.pt_mul(c)
    gi_rr = (-g).pt_mul(rr)
    X1_rz1 = X1.pt_mul(rz1)
    W_V = V_c + gi_rr + X1_rz1

    # calculate the reverse witness of the pseudonym
    ps_c = pseudonym.pt_mul(c)
    N_rv = N.pt_mul(rv)
    W_ps = ps_c + N_rv

    # generate the verification challenge with the pseudonym witness and N attribute
    c_prime = to_challenge([u, h, g, X1, N, Cv, Cup, Cx0, W_Cv, W_V, W_ps])

    # check if both challenges match and verification true
    return c == c_prime

#####################################################
# TASK Q1 -- Answer the following question:
#
# How could you use a credential scheme, such as the one you
# implemented above to implement an electronic cash scheme
# ensuring both integrity (no-double spending) and privacy.
# What would the credential represent, and what statements
# would need to be shown to a verifier.

""" Your answer here.

The scheme could be used to implement an online transaction system where a centralised authority, also the issuer of credentials,
acts as a bank, for many customers, being assigned credentials, and many e-commerce websites, acting as verifiers.
Here, if a customer Alice wants to add some amount of money to their e-wallet they would contact the issuer (central bank)
and give them a hash representation of the value of money she wants to add and a random unique number. This hash will be stored
by the bank which will then issue it into Alice's e-wallet after creating a MAC of the hash value and proving that it is valid.
Additionally, the bank will send Alice back a credential. This credential will be the MAC generated earlier and the proof of validity.
Next, Alice will generate a stable pseudonym for her e-wallet account using the method implemented in the task 4 and send this to the bank,
which then stores this pseudonym. Note: a different pseudonym will be used for each transaction of money into Alice's e-wallet.

Now, say Alice wants to spend the money she just added into her e-wallet for an online retailer supporting this scheme. She will send the pseudonym,
a MAC she rebuilds, and a Zero-Knowledge proof of validity of the credential to the online retailer. The retailer (verifier) will contact the issuing bank
and send the proof to ensure the transaction is verified. If verified, the bank will then transfer the money from Alice's e-wallet into the
retailer's e-wallet and delete the pseudonym for Alice which corresponds to the original money transaction Alice added into her e-wallet.

To ensure privacy, pseduonyms will have to be different for each time Alice adds money to her e-wallet; also credentials will be unique. To ensure integrity (no-double spending),
the bank deletes the pseudonym of a transaction which has been transferred from Alice's account to another account, such that, the same transaction
will not be verified (upon a request to spend) and thus cannot be spent again.

"""
