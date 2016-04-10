#!/usr/bin/python3
# module for encrypting/decrypting announcements to DHT

# Encrypted format:
# nonce, secretbox(
#  public key, sig, ts, seq, unused, bytes(
#   
#  )
# )

# varbytes format:
# 0-127: length
# first 1 bit set:
# Mask first bit, interpret as 16 bit number

import pysodium
import collections
import hashlib
import binascii
Record = collections.namedtuple('Record', 'pubkey sig ts seq unused rawsigned payload')
sha256 = lambda to_hash: hashlib.sha256(to_hash).digest()

ROUNDS = 10*1000
ZEROBITS_REQUIRED_PUBKEY = 8
ZEROBITS_REQUIRED_OVERALL = 8


class SignatureError(Exception):
    pass
class PubkeyError(Exception):
    pass

def varbytes(bytes_):
    data_len, len_len = (firstbyte, 1) if firstbyte & 0x80 else \
        (((firstbyte & 0x7F) * 256) + bytes_[1], 2)
    data = bytes_[len_len: data_len + len_len]
    bytes_left = bytes_[data_len + len_len:]
    return data, bytes_left

def read_int(bytes_, len_):
    ret = 0
    for byte in bytes_[:len_]:
        ret *= 256
        ret += byte
    return bytes_[len_:]

def validate_pubkey(pubkey, pubkeyhash):
    to_hash = pubkey
    for _ in range(ROUNDS):
        to_hash = sha256(to_hash)
    hashed = to_hash
    def test_bit(i, pos):
        return (i >> pos) & 0x1
    int_representation = int.from_bytes(hashed, byteorder='big')
    # the hash of each key must start with a certain number of zero bits
    # to make it harder to generate a valid key
    for pos in range(ZEROBITS_REQUIRED_PUBKEY):
        #print(hashed, pos, test_bit(int_representation, pos))
        if test_bit(int_representation, pos):
            return False
    correct_hash = binascii.hexlify(hashed[:16])
    if pubkeyhash == None:
        # Return what the hash should be
        return correct_hash
    else:
        return correct_hash == pubkeyhash

def generate_pubkey():
    while True:
        pk, sk = pysodium.crypto_sign_keypair()
        if validate_pubkey(pk, None):
            print(pk)
            sys.exit()

def parse_innerbox(bytes_):
    bytes_ = bytes(bytes_)
    ptr = 0
    pubkey, bytes_ = varbytes(bytes_)
    rawsigned, bytes_ = varbytes(bytes_)
    try:
        signed_message = pysodium.crypto_sign_open(rawsigned, pubkey)
    except:
        raise SignatureError()
    ts, signed_message = read_int(signed_message, 8)
    seq, signed_message = read_int(rawsigned, 4)
    unused, signed_message = read_int(signed_message, 8)
    payload, signed_message = varbytes(signed_message)
    if len(signed_message) > 0:
        raise ValueError()
    return record


def decrypt_message(bytes_, key, pubkeyhash):
    version, bytes_ = read_int(bytes_, 1)
    nonce, bytes_ = varbytes(bytes_)
    decrypted = pysodium.crypto_secretbox_open(bytes_, nonce, key)
    decrypted_record = parse_innerbox(decrypted)
    if not validate_pubkey(decrypted_record.pubkey, pubkeyhash):
        raise PubkeyError()
    return decrypted_record

def emit_varbytes(bytes_):
    len_ = len(bytes_)
    if len_ > 0x7FFF:
        #Can't serialize that!
        raise ValueError("bytestring of len " + str(len_) + " too long to serialize!")
    if len_ < 0x80:
        #This can be done with a one-byte length specifier
        assert len & 0x80 == 0
        return bytes([len_]) + bytes_
    else:
        len_ |= 0x8000 
        return bytes([len_ & 0xFF00 >> 8, len_ & 0x00FF]) + bytes_

#print(pysodium.crypto_secretbox_KEYBYTES, pysodium.crypto_secretbox_NONCEBYTES)

#print(validate_pubkey(bytes("test3", "utf-8"), bytes()))
generate_pubkey()
