#####################################################
# GA17 Privacy Enhancing Technologies -- Lab 02
#
# Basics of Mix networks and Traffic Analysis
#
# Run the tests through:
# $ py.test -v test_file_name.py

#####################################################
# TASK 1 -- Ensure petlib is installed on the System
#           and also pytest. Ensure the Lab Code can
#           be imported.

###########################
# Group Members: TODO
###########################


from collections import namedtuple
from hashlib import sha512
from struct import pack, unpack
from binascii import hexlify

def aes_ctr_enc_dec(key, iv, input):
    """ A helper function that implements AES Counter (CTR) Mode encryption and decryption.
    Expects a key (16 byte), and IV (16 bytes) and an input plaintext / ciphertext.

    If it is not obvious convince yourself that CTR encryption and decryption are in
    fact the same operations.
    """

    aes = Cipher("AES-128-CTR")

    enc = aes.enc(key, iv)
    output = enc.update(input)
    output += enc.finalize()

    return output

#####################################################
# TASK 2 -- Build a simple 1-hop mix client.
#
#


## This is the type of messages destined for the one-hop mix
OneHopMixMessage = namedtuple('OneHopMixMessage', ['ec_public_key',
                                                   'hmac',
                                                   'address',
                                                   'message'])

from petlib.ec import EcGroup
from petlib.hmac import Hmac, secure_compare
from petlib.cipher import Cipher

def mix_server_one_hop(private_key, message_list):
    """ Implements the decoding for a simple one-hop mix.

        Each message is decoded in turn:
        - A shared key is derived from the message public key and the mix private_key.
        - the hmac is checked against all encrypted parts of the message
        - the address and message are decrypted, decoded and returned

    """
    G = EcGroup()

    out_queue = []

    # Process all messages
    for msg in message_list:

        ## Check elements and lengths
        if not G.check_point(msg.ec_public_key) or \
               not len(msg.hmac) == 20 or \
               not len(msg.address) == 258 or \
               not len(msg.message) == 1002:
           raise Exception("Malformed input message")

        ## First get a shared key
        shared_element = private_key * msg.ec_public_key
        key_material = sha512(shared_element.export()).digest()

        # Use different parts of the shared key for different operations
        hmac_key = key_material[:16]
        address_key = key_material[16:32]
        message_key = key_material[32:48]

        ## Check the HMAC
        h = Hmac(b"sha512", hmac_key)
        h.update(msg.address)
        h.update(msg.message)
        expected_mac = h.digest()

        if not secure_compare(msg.hmac, expected_mac[:20]):
            raise Exception("HMAC check failure")

        ## Decrypt the address and the message
        iv = b"\x00"*16

        address_plaintext = aes_ctr_enc_dec(address_key, iv, msg.address)
        message_plaintext = aes_ctr_enc_dec(message_key, iv, msg.message)

        # Decode the address and message
        address_len, address_full = unpack("!H256s", address_plaintext)
        message_len, message_full = unpack("!H1000s", message_plaintext)

        output = (address_full[:address_len], message_full[:message_len])
        out_queue += [output]

    return sorted(out_queue)


def mix_client_one_hop(public_key, address, message):
    """
    Encode a message to travel through a single mix with a set public key.
    The maximum size of the final address and the message are 256 bytes and 1000 bytes respectively.
    Returns an 'OneHopMixMessage' with four parts: a public key, an hmac (20 bytes),
    an address ciphertext (256 + 2 bytes) and a message ciphertext (1002 bytes).
    """

    G = EcGroup()
    assert G.check_point(public_key)
    assert isinstance(address, bytes) and len(address) <= 256
    assert isinstance(message, bytes) and len(message) <= 1000

    # Encode the address and message
    # Use those as the payload for encryption
    address_plaintext = pack("!H256s", len(address), address)
    message_plaintext = pack("!H1000s", len(message), message)

    ## Generate a fresh public key
    private_key = G.order().random()
    client_public_key  = private_key * G.generator()

    ## ADD CODE HERE
    ##take parameters and encode message, such that the mix will output a tuple of (address, message) to be routed to its final destination.
    #essentially reverse the decoder function above

    #derive a shared key
    shared_element = private_key*public_key
    key_material = sha512(shared_element.export()).digest()

    #use the correct part of the key for the HMAC and encrypting the address and message
    hmac_key = key_material[:16]
    address_key = key_material[16:32]
    message_key = key_material[32:48]

    #generate an IV of 16 zeros.
    iv = b"\x00"*16

    #encrypt the address and message
    address_cipher = aes_ctr_enc_dec(address_key, iv, address_plaintext)
    message_cipher = aes_ctr_enc_dec(message_key, iv, message_plaintext)

    #create the HMAC
    h = Hmac(b"sha512", hmac_key)
    h.update(address_cipher)
    h.update(message_cipher)
    expected_mac = h.digest()
    expected_mac = expected_mac[:20]


    return OneHopMixMessage(client_public_key, expected_mac, address_cipher, message_cipher)



#####################################################
# TASK 3 -- Build a n-hop mix client.
#           Mixes are in a fixed cascade.
#

from petlib.ec import Bn

# This is the type of messages destined for the n-hop mix
NHopMixMessage = namedtuple('NHopMixMessage', ['ec_public_key',
                                                   'hmacs',
                                                   'address',
                                                   'message'])


def mix_server_n_hop(private_key, message_list, final=False):
    """ Decodes a NHopMixMessage message and outputs either messages destined
    to the next mix or a list of tuples (address, message) (if final=True) to be
    sent to their final recipients.

    Broadly speaking the mix will process each message in turn:
        - it derives a shared key (using its private_key),
        - checks the first hmac,
        - decrypts all other parts,
        - either forwards or decodes the message.
    """

    G = EcGroup()

    out_queue = []

    # Process all messages
    for msg in message_list:

        ## Check elements and lengths
        if not G.check_point(msg.ec_public_key) or \
               not isinstance(msg.hmacs, list) or \
               not len(msg.hmacs[0]) == 20 or \
               not len(msg.address) == 258 or \
               not len(msg.message) == 1002:
           raise Exception("Malformed input message")

        ## First get a shared key
        shared_element = private_key * msg.ec_public_key
        key_material = sha512(shared_element.export()).digest()

        # Use different parts of the shared key for different operations
        hmac_key = key_material[:16]
        address_key = key_material[16:32]
        message_key = key_material[32:48]

        # Extract a blinding factor for the public_key
        blinding_factor = Bn.from_binary(key_material[48:])
        new_ec_public_key = blinding_factor * msg.ec_public_key

        ## Check the HMAC
        h = Hmac(b"sha512", hmac_key)

        for other_mac in msg.hmacs[1:]:
            h.update(other_mac)

        h.update(msg.address)
        h.update(msg.message)

        expected_mac = h.digest()

        if not secure_compare(msg.hmacs[0], expected_mac[:20]):
            raise Exception("HMAC check failure")

        ## Decrypt the hmacs, address and the message
        aes = Cipher("AES-128-CTR")

        # Decrypt hmacs
        new_hmacs = []
        for i, other_mac in enumerate(msg.hmacs[1:]):
            # Ensure the IV is different for each hmac
            iv = pack("H14s", i, b"\x00"*14)

            hmac_plaintext = aes_ctr_enc_dec(hmac_key, iv, other_mac)
            hmac_plaintext = hmac_plaintext[:20]
            new_hmacs += [hmac_plaintext]

        # Decrypt address & message
        iv = b"\x00"*16

        address_plaintext = aes_ctr_enc_dec(address_key, iv, msg.address)
        message_plaintext = aes_ctr_enc_dec(message_key, iv, msg.message)

        if final:
            # Decode the address and message
            address_len, address_full = unpack("!H256s", address_plaintext)
            message_len, message_full = unpack("!H1000s", message_plaintext)

            out_msg = (address_full[:address_len], message_full[:message_len])
            out_queue += [out_msg]
        else:
            # Pass the new mix message to the next mix
            out_msg = NHopMixMessage(new_ec_public_key, new_hmacs, address_plaintext, message_plaintext)
            out_queue += [out_msg]

    return out_queue


def mix_client_n_hop(public_keys, address, message):
    """
    Encode a message to travel through a sequence of mixes with a sequence public keys.
    The maximum size of the final address and the message are 256 bytes and 1000 bytes respectively.
    Returns an 'NHopMixMessage' with four parts: a public key, a list of hmacs (20 bytes each),
    an address ciphertext (256 + 2 bytes) and a message ciphertext (1002 bytes).

    """
    G = EcGroup()
    # assert G.check_point(public_key)
    assert isinstance(address, bytes) and len(address) <= 256
    assert isinstance(message, bytes) and len(message) <= 1000

    # Encode the address and message
    # use those encoded values as the payload you encrypt!
    address_plaintext = pack("!H256s", len(address), address)
    message_plaintext = pack("!H1000s", len(message), message)

    ## Generate a fresh public key
    private_key = G.order().random()
    client_public_key  = private_key * G.generator()

    ## ADD CODE HERE
    #similar to task 2 but more steps involved and conditional statements

    #generate blinded public keys list, but only blind entries after the first key
    public_keys_blinded = [public_keys[0]]
    for i in range(1,len(public_keys)-1):
        shared_element = private_key * public_keys_blinded[len(public_keys_blinded)-1]
        key_material = sha512(shared_element.export()).digest()

        hmac_key = key_material[:16]
        address_key = key_material[16:32]
        message_key = key_material[32:48]
        #generate a blinding factor to create unlinkability between public keys
        blinding_factor = Bn.from_binary(key_material[48:])
        #blind the public key
        new_ec_public_key = blinding_factor * public_keys[i]
        #store the blinded public key into the list
        public_keys_blinded.append(new_ec_public_key)


    #when encrypting, the blinded public keys usage should start from the the last entry, working to the first entry to ensure correct order while decrypting
    #reverse the order of the blinded public keys
    reversed_public_keys_blinded = list(reversed(public_keys_blinded))
    hmacs = []
    #initialise the address and message ciphertext variables for the interations later
    address_cipher = 0
    message_cipher = 0

    # using each element in the list, i.e. each key:
    for i, public_key_rb in enumerate(reversed_public_keys_blinded):
        #generate shared key
        shared_element = private_key * public_key_rb
        key_material = sha512(shared_element.export()).digest()

        hmac_key = key_material[:16]
        address_key = key_material[16:32]
        message_key = key_material[32:48]

        iv = b"\x00"*16
        #if not first round then keep iterating over the ciphertexts, else use plaintext to create the ciphertexts
        if (address_cipher is not 0 and message_cipher is not 0):
            address_cipher = aes_ctr_enc_dec(address_key, iv, address_cipher)
            message_cipher = aes_ctr_enc_dec(message_key, iv, message_cipher)
        else:
            address_cipher = aes_ctr_enc_dec(address_key, iv, address_plaintext)
            message_cipher = aes_ctr_enc_dec(message_key, iv, message_plaintext)

        #aes = Cipher("AES-128-CTR")
        #create the HMAC
        h = Hmac(b"sha512", hmac_key)
        new_hmacs = []
        #for each HMAC in the final list:
        for j, other_mac in enumerate(hmacs):
            # Ensure the IV is different for each HMAC
            iv = pack("H14s", i, b"\x00"*14)
            #encrypt the HMAC
            hmac_plaintext = aes_ctr_enc_dec(hmac_key, iv, other_mac)
            #append the encrypted HMAC to the HMAC created above
            h.update(hmac_plaintext)
        #append the address and message ciphertexts to the HMAC
        h.update(address_cipher)
        h.update(message_cipher)
        #format the HMAC to make sure it can be processed by the decoding function properly
        expected_mac = h.digest()
        expected_mac = expected_mac[:20]
        #insert the formatted HMAC into the final list of HMACS
        hmacs.insert(0,expected_mac)

    return NHopMixMessage(client_public_key, hmacs, address_cipher, message_cipher)



#####################################################
# TASK 4 -- Statistical Disclosure Attack
#           Given a set of anonymized traces
#           the objective is to output an ordered list
#           of likely `friends` of a target user.

import random

def generate_trace(number_of_users, threshold_size, number_of_rounds, targets_friends):
    """ Generate a simulated trace of traffic. """
    target = 0
    others = range(1, number_of_users)
    all_users = range(number_of_users)

    trace = []
    ## Generate traces in which Alice (user 0) is not sending
    for _ in range(number_of_rounds // 2):
        senders = sorted(random.sample( others, threshold_size))
        receivers = sorted(random.sample( all_users, threshold_size))

        trace += [(senders, receivers)]

    ## Generate traces in which Alice (user 0) is sending
    for _ in range(number_of_rounds // 2):
        senders = sorted([0] + random.sample( others, threshold_size-1))
        # Alice sends to a friend
        friend = random.choice(targets_friends)
        receivers = sorted([friend] + random.sample( all_users, threshold_size-1))

        trace += [(senders, receivers)]

    random.shuffle(trace)
    return trace


from collections import Counter

def analyze_trace(trace, target_number_of_friends, target=0):
    """
    Given a trace of traffic, and a given number of friends,
    return the list of receiver identifiers that are the most likely
    friends of the target.
    """

    ## ADD CODE HERE
    """
    print("no.rounds:", len(trace))
    print("no:", target_number_of_friends)
    print("target:", target)
    print("trace1",trace[1])
    print("trace10",trace[1][0])
    print("trace101",trace[1][0][1])
    print("no.senders",len(trace[1][0][:]))
    """
    #create a counter object using Python's built-in functions
    countlist = Counter()
    #for each round of communication:
    for i in range(0,len(trace)):
        #if the target sender id is present in the senders list then:
        if (target in trace[i][0][:]):
            #count the occurance of each unique receiver id and concatenate into an overall id-frequency object list
            countlist += Counter(trace[i][1][:])

    #print("clist:", countlist)

    #print("mostcommon:", countlist.most_common(target_number_of_friends))
    #print("mostcommon:", (countlist.most_common(target_number_of_friends)[0][0]))

    #initialise empty list
    friends = []
    #until you obtain the same number of receivers as the number of friends the target has:
    for i in range(0, target_number_of_friends):
        #keep appending the most common (highest frequency) receiver id in a descending order from most to least likely 'friend'
        friends.append((countlist.most_common(target_number_of_friends)[i][0]))
    #print("friends list:", friends)
    #return list of most likely friends the target has been sending messages to
    return friends

## TASK Q1 (Question 1): The mix packet format you worked on uses AES-CTR with an IV set to all zeros.
#                        Explain whether this is a security concern and justify your answer.

""" TODO: Your answer HERE
AES-CTR uses IV-Counter pairs which are encrypted and then used with the plaintext to create cyphertext.
The IV is essentially suppposed to be a nonce. Hence, it should be an unpredicatable, one-time value.
Therefore, an IV set to all zeros in real-life would pose a significant security concern, especially if it is not uniquely and randomly generated for each block.
For exmaple, comprimising a full-disk encryption mechanism. However, in this case, because the encryption key is generated each time a message is encrypted an IV
with all zeros is not a security concern. Additionally, since each message has its own seemingly random shared key the security of the encryption is fine.
Although, in general, IV should always be altered and random.
"""


## TASK Q2 (Question 2): What assumptions does your implementation of the Statistical Disclosure Attack
#                        makes about the distribution of traffic from non-target senders to receivers? Is
#                        the correctness of the result returned dependent on this background distribution?

""" TODO: Your answer HERE
The assumptions made while implementing the Statistical Disclosure attack about the distribution of traffic from non-target senders
to receivers are as follows:
    o Non-target senders are not going to be sending messages to the target's friends/receivers, such that any messaged received by the target's friends'
    are always from the target. This could affect the correctness of the result returned, because, a receiver frequently receiving messages will be deemed the target's friend,
    even if, for example, the receiver was just receiving heavy traffic from a non-target sender.
    o Additionally, it is assumed that the frequency of messages received by non-targets' friends/receivers is lower than the frequency of messages received
    by the target's friends/receivers. This means that the target senders' friends are those with the highest frequency. This can greatly affect the correctness of the results,
    because it is likely that the target sender will send fewer and more compact messages to their friends in order to avoid generating too much attention. Hence, skewing
    the results received.
    o Furthermore, it is assumed that there is no or very little latency, since we assume that the senders only interact with the receivers in the same round, and vice versa.
    Since, real systems tend to have unexpected latency issues and there is also a possibility of mixing mechanisms, it is possible that the messages sent by the target sender
    actually reach the receiver some rounds later, maybe even in a round where the target sender is not listed in the senders list. Thus, potentially, missing a target's actual receivers
    and returning an incorrect list of most likely friends.
    o We also assume that the receivers are genuine end users and not a redirecting service such as a VPN. Again, affecting the correctness, as the actual targets friends
    are likely still hidden.
"""
