import os
from math import sqrt, ceil
import hashlib
from Crypto.Util.number import getStrongPrime, isPrime
from typing import Tuple, Callable
from .keys import Keys, kLen

def shaf(msg: bytes) -> bytes:
    """
    Definition of a hash function. In this case, sha1.
    """
    hash_f = hashlib.sha1()
    hash_f.update(msg)
    return hash_f.digest()

def mgf1(seed: bytes, mlen: int, f_hash: Callable = shaf) -> bytes:
    """
    MGF1 mask generation function using SHA (any hash function can be used)
    https://en.wikipedia.org/wiki/Mask_generation_function
    Iteratively apply a hash function together with an incrementing counter value.
    Seed: binary string
    mlen: intended length of the mask
    """
    # t is an empty byte (octet) string
    t = b''
    # Get length of bytes of the hash function.
    hlen = len(f_hash(b''))
    for counter in range(0, ceil(mlen / hlen)):
        # i2bs = primitive i2osp
        _c = MathHelpers.i2bs(counter, 4)
        t += f_hash(seed + _c)
    return t[:mlen]

# Based on: https://gist.github.com/ppoffice/e10e0a418d5dafdd5efe9495e962d3d2
class pyRSA:
    def generate(bits: int = 1024):
        """
        Generates public and private key according with the RSA algorithm.
        """
        p = getStrongPrime(bits)
        q = getStrongPrime(bits)
        while p == q:
            q = getStrongPrime(bits)
        e = 0x10001
        return pyRSA.keys(p, q, e)

    def keys(p: int, q: int, e: int = 0x10001) -> Keys:
        """
        Create RSA public (exponent e and modulos n) and private keys (exponent d and modulos n)
        """
        # Check the provided numbers
        # Choose two primes
        assert isPrime(p) and isPrime(q)
        assert p != q
        # Getting modulos n
        n = p * q
        # Calculate Phi (Totient)
        phi = (p - 1) * (q - 1)
        # Verify the numbers are co-primes
        assert MathHelpers.euclid(phi, e) == 1
        # Compute the congruence relation
        d = MathHelpers.mmi(e, phi)
        return Keys(e = e, d = d, n = n)

    def encrypt(msg: bytes, key: Tuple[int, int]) -> bytes:
        """
        RSA encryption (does not force to be pub or priv key).
        Does not add padding.
        m ^ d = c (mod n)
        """
        d, n = key
        k = kLen(key) # Number of bytes of the key
        cipher = pow(MathHelpers.b2ip(msg), d, n)
        # Convert integer to bytes
        return MathHelpers.i2bs(cipher, k)

    def encrypt_oaep(msg: bytes, key: Tuple[int, int], f_hash: Callable = shaf) -> bytes:
        """
        RSA encryption of an array of bytes after an OAEP padding.
        """
        hlen = len(f_hash(b''))
        k = kLen(key)
        assert len(msg) <= k - hlen - 2
        return pyRSA.encrypt(OAEP.encode(msg, k), key)

    def decrypt(cipher: int, key: Tuple[int, int]) -> bytes:
        """
        RSA decryption (does not force to be pub or priv key).
        Does not remove padding.
        c ^ e = (m ^ e) ^ d = m (mod n)
        """
        e, n = key
        k = kLen(key)
        msg = pow(MathHelpers.b2ip(cipher), e, n)
        return MathHelpers.i2bs(msg, k)

    def decrypt_oaep(cipher: bytes, key: Tuple[int, int], f_hash: Callable = shaf) -> bytes:
        """
        RSA decryption of a cipher and then remove OAEP padding.
        """
        k = kLen(key)
        hlen = len(f_hash(b'')) # SHA-1 hash length
        assert len(cipher) == k
        assert k >= 2 * hlen + 2
        return OAEP.decode(pyRSA.decrypt(cipher, key), k)


class OAEP:
    # Based on EME-OAEP https://www.inf.pucrs.br/~calazans/graduate/TPVLSI_I/RSA-oaep_spec.pdf
    def encode(msg: bytes, k: int, label: bytes = b'',
                    f_hash: Callable = shaf, f_mgf: Callable = mgf1) -> bytes:
        """
        Add OAEP padding.
        https://programmersought.com/article/80435453648/
        k = length of the key
        label = optional addional label for the message
        """
        mlen = len(msg)        # length of the message
        lhash = f_hash(label)  # hash a empty byte string
        hlen = len(lhash)      # get length of the hash function
        ps = b'\x00' * (k - mlen - 2 * hlen - 2)
        db = lhash + ps + b'\x01' + msg
        seed = os.urandom(hlen) # Generation of a random byte string
        db_mask = f_mgf(seed, k - hlen - 1, f_hash) # get a mask
        masked_db = MathHelpers.xor(db, db_mask) # First xor
        seed_mask = f_mgf(masked_db, hlen, f_hash) # get a new mask
        masked_seed = MathHelpers.xor(seed, seed_mask) # Second xor
        return b'\x00' + masked_seed + masked_db # Merge

    def decode(cipher: bytes, k: int, label: bytes = b'',
                    f_hash: Callable = shaf, f_mgf: Callable = mgf1) -> bytes:
        """
        Undo OAEP padding.
        https://programmersought.com/article/80435453648/
        k = length of the key
        label = optional addional label for the message
        """
        clen = len(cipher)
        lhash = f_hash(label)
        hlen = len(lhash)
        # Decompose the encoded message
        _, masked_seed, masked_db = cipher[:1], cipher[1:1 + hlen], cipher[1 + hlen:]
        seed_mask = f_mgf(masked_db, hlen, f_hash)
        seed = MathHelpers.xor(masked_seed, seed_mask)
        db_mask = f_mgf(seed, k - hlen - 1, f_hash)
        db = MathHelpers.xor(masked_db, db_mask)
        _lhash = db[:hlen]
        assert lhash == _lhash, "Problem with keys! Don't match."
        indx = hlen
        # Decomposition of possible empty hex
        while indx < len(db):
            if db[indx] == 0:
                indx += 1
                continue
            elif db[indx] == 1:
                indx += 1
                break
            else:
                raise Exception("Decryption error! Y non zero.")
        msg = db[indx:]
        return msg


class MathHelpers:
    def euclid(a: int, b: int) -> int:
        """
        Calculate GCD of two integers based on the Euclid's Algorithm
        https://en.wikipedia.org/wiki/Euclidean_algorithm#:~:text=In%20mathematics%2C%20the%20Euclidean%20algorithm,them%20both%20without%20a%20remainder.
        """
        while b != 0:
            a, b = b, a % b
        return a

    def xeuclid(a: int, b: int) -> Tuple[int, int, int]:
        """
        Calculate Euclid's Extended Algorithm to calculate integers x and y
        that satisfies a * x + b * y = euclid(a, b).
        Return x, y and GCD
        """
        if b == 0:
            return 1, 0, a
        else:
            x, y, gcd = MathHelpers.xeuclid(b, a % b)
            return y, x - (a // b) * y, gcd

    def mmi(a: int, m: int) -> int:
        """
        Calculate the Modular Multiplicate Inverse. Uses he Euclids Extended Alg.
        https://cp-algorithms.com/algebra/module-inverse.html#:~:text=Practice%20Problems-,Definition,inverse%20does%20not%20always%20exist.

        """
        x, y, gcd = MathHelpers.xeuclid(a, m)
        if gcd != 1:
            # Inverse does not exist
            raise Exception("Modular Inverse does not exist.")
        else:
            return x % m

    def b2ip(num: bytes) -> int:
        """
        Converts bytes to a non-negative integer.
        """
        return int.from_bytes(num, byteorder = 'big')

    def i2bs(num: int, xlen: int) -> bytes:
        """
        Converts a non-negative integer to a string of bytes with specific length.
        """
        return num.to_bytes(xlen, byteorder = 'big')

    def xor(data: bytes, mask: bytes) -> bytes:
        """
        Operation XOR on bytes.
        """
        masked = b''
        ldata, lmask = len(data), len(mask)
        # Loop through all the byes
        for indx in range(ldata):
            # Do this while inside data and mask
            if indx < ldata and indx < lmask:
                masked += (data[indx] ^ mask[indx]).to_bytes(1, byteorder = 'big')
            # Just add the data if the mask was not sufficient
            else:
                masked += data[indx].to_bytes(1, byteorder='big')
        return masked
