"""
This is a toy implementation of the Pedersen Hash function used to 
illustrate several of its vulnerabilities when the requirements on the
encoding function are not followed properly.

It accompanies the blog post "Breaking Pedersen Hashes in Practice" 
hosted on NCC Group's Research Platform at
https://research.nccgroup.com/2023/03/22/breaking-pedersen-hashes-in-practice/
"""

# First we pick an elliptic curve with prime order:
F = GF(127)
E = EllipticCurve(F, [F(1), F(42)])
assert E.order().is_prime()
print(f"{E} with order {E.order()}")
# Elliptic Curve defined by y^2 = x^3 + x + 42 over Finite Field of size 127 with order 139

# We pick two generators. As the curve has prime order, all non-identity points
# are generators
G1 = E(1, 60)
G2 = E(2, 59)

GENERATORS = [G1, G2]


def IdentityEncode(lebs):
    """
    Encodes a binary string (assumed to be in little-endian bit order)
    to an integer
    """
    return int(lebs[::-1], 2)


def EncodeMessage(msg, encode_function):
    """
    Helper function which encodes a message given a variable
    encode function
    """
    return [encode_function(x) for x in msg]


def GenericPedersenHash(generators, encoded_chunks):
    """
    Helper function for computing the Pedersen hash of a message

    The hash is computed as a linear combination of of the generators with
    (already encoded) chunks used as scalar multiples
    """
    assert len(generators) == len(encoded_chunks), "Incompatible lengths"

    res = E(0)
    for chunk, generator in zip(encoded_chunks, generators):
        res += chunk * generator
    return res


def PedersenHash(message, encode_function=IdentityEncode, generators=GENERATORS):
    """
    Computes the Pedersen hash of a message

    Input: a message
    Output: the Pedersen Hash of the message

    Optional:
        encode_function: the encoding function to break a message into integers
        generators: elements G ∈ E which generate E
    """
    encoded_message = EncodeMessage(message, encode_function)
    return GenericPedersenHash(generators, encoded_message)


def ZcashEncode(bin_value):
    r"""
    Zcash's Encoding function ⟨⋅⟩: encodes `bin_value`, a binary value in
    little-endian bit order to an element in the range
    {︀−(𝑟 − 1)/2 .. (𝑟 − 1)/2}︀∖{0}, with r the subgroup order
    """

    def enc(b):
        """
        Zcash's 3-bit signed encoding function
        """
        return (1 - 2 * int(b[2])) * (1 + int(b[0]) + 2 * int(b[1]))

    assert len(bin_value) % 3 == 0

    res = 0
    for j, a in enumerate(range(0, len(bin_value), 3)):
        bchunk = bin_value[a : a + 3]
        res += enc(bchunk) * (2 ** (4 * j))
    return res


def ZcashPedersenHash(message, generators=GENERATORS):
    """
    Wrapper function around `PedersenHash`
    """
    return PedersenHash(message, encode_function=ZcashEncode, generators=generators)

# ============================ #
#   Example of Pedersen Hash   #
# ============================ #

message = ["010101", "000111"]  # M = [42, 56]
H = PedersenHash(message)
print(f"Hash of {message} = {H}")
# Hash of  ['010101', '000111']  =  (3 : 31 : 1)

# We check that the Pedersen hash of the message is equivalent to computing
# the linear combination of the generator points and the integers representations
# of the message chunks
assert H == 42 * G1 + 56 * G2

# Since the subgroup order is 139, adding this quantity (or multiples of it)
# to the scalar factors of the linear combination computation performed by
# the Pedersen hash function results in the same hash output, as can be seen below.

H2 = (42 + 139) * G1 + (56 + 2 * 139) * G2
assert H == H2

colliding_message = ["10101101", "011100101"]

# Ensures encoding colliding_message results in the integers
# used explicitly above 
assert EncodeMessage(colliding_message, IdentityEncode) == [42 + 139, 56 + 2 * 139]

H3 = PedersenHash(colliding_message)
assert H == H3

# ========================================== #
# Vulnerability 1 - Non-unique x-coordinate  #
# ========================================== #

H = ZcashPedersenHash(message)
print(f"Zcash's Hash of {message} = {H}")
# Zcash's Hash of  ['010101', '000111']  =  (83 : 83 : 1)

colliding_message = ["011100", "001110"]
H2 = ZcashPedersenHash(colliding_message)

assert H[0] == H2[0]
assert message != colliding_message

# ======================================= #
#   Vulnerability 2 - Related Generators  #
# ======================================= #

# We know the discrete logarithm of G2 with respect to G1
assert 35 * G1 == G2

message = ["010101", "000111"]  # M = [42, 56]
encoded_message = EncodeMessage(message, ZcashEncode)
print(f"Encoded Message: {encoded_message}")
# Encoded Message:  [-29, -63]

H = ZcashPedersenHash(message)
assert 129 * G1 == H

# We need to find a message M' = M1' || M2' such that
# <M1'> + 35*<M2'> =  (-29 -35*63 ) = 129 mod 139
H2 = GenericPedersenHash(GENERATORS, [17, 31])
assert H == H2

H3 = ZcashPedersenHash(["000000", "001100"])
assert H == H3

# ======================================== #
# Vulnerability 3 - Variable-length Input  #
# ======================================== #

message = ["010101", "111000"]
colliding_message = [message[0] + "000", message[1][:3]]
print(f"Colliding Message: {colliding_message}")
# Colliding Message:  ['010101000', '111']

assert PedersenHash(colliding_message) == PedersenHash(message)
