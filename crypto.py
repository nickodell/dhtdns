#!/usr/bin/python3
# module for encrypting/decrypting announcements to DHT


import pysodium
import collections
import hashlib
import binascii
import struct
import copy
import time
import cProfile

import seq
import serial

#inclusive range
irange = lambda a, b: range(a, b + 1)
Record = collections.namedtuple('Record', 'pubkey inner_ver rawsig ts seq payload')
Identity = collections.namedtuple('Identity', 'pk sk enc handle')

outer_pack = struct.Struct('!bpp') #version, IV, encrypted block
mid_pack = struct.Struct('!pp') #pubkey, signature/message block
inner_pack = struct.Struct('!bqIQp') #inner_ver, ts, seq, unused, payload

ux = binascii.unhexlify
hx = lambda x: binascii.hexlify(x).decode('ascii')

ROUNDS = 10*1000
ZEROBITS_REQUIRED_PUBKEY = 4
ZEROBITS_REQUIRED_OVERALL = 4


class SignatureError(Exception):
    pass
class PubkeyError(Exception):
    pass

def sha256(m):
    return hashlib.sha256(m).digest()

def slow_hash(m, rounds=ROUNDS):
    for _ in range(rounds):
        m = sha256(m)
    return m

def check_zerobits(hash, zerobits):
    def test_bit(i, pos):
        return (i >> pos) & 0x1
    int_representation = int.from_bytes(hash, byteorder='big')
    for pos in range(zerobits):
        if test_bit(int_representation, pos):
            return False
    return True

def hash_pubkey(pubkey):
    hashed = slow_hash(pubkey, ROUNDS)
    # the hash of each key must start with a certain number of zero bits
    # to make it harder to generate a valid key
    if not check_zerobits(hashed, ZEROBITS_REQUIRED_PUBKEY):
        return False
    hashed = hx(hashed[:16])
    return hashed

def validate_pubkey(pubkey, pubkeyhash):
    return hash_pubkey(pubkey) == pubkeyhash

def generate_identity():
    pk, sk, handle = None, None, None
    while True:
        pk, sk = pysodium.crypto_sign_keypair()
        if hash_pubkey(pk):
            break
    while True:
        enc = pysodium.randombytes(16)
        try:
            handle = hash_pubkey(pk) + hx(enc)
            expand_handle(handle)
        except:
            continue
        break
    return Identity(pk=pk, sk=sk, \
                    enc=enc, handle=handle)

def parse_innerbox(bytes_):
    pubkey, rawsigned = mid_pack.unpack(bytes_)
    try:
        signed_message = pysodium.crypto_sign_open(rawsigned, pubkey)
    except:
        raise SignatureError()
    inner_ver, ts, seq, signed_message, payload = \
        inner_pack.unpack(signed_message)
    record = Record(pubkey=pubkey, \
                    inner_ver=inner_ver, \
                    ts=ts, \
                    seq=seq, \
                    rawsig=rawsigned, \
                    payload=payload)
    return record


def decrypt_message(bytes_, key, pubkeyhash):
    version, nonce, encrypted = outer_pack.unpack(bytes_)
    decrypted = pysodium.crypto_secretbox_open(encrypted, nonce, key)
    decrypted_record = parse_innerbox(decrypted)
    if not validate_pubkey(decrypted_record.pubkey, pubkeyhash):
        raise PubkeyError()
    if version != decrypted_record.inner_ver:
        # The version on the outside doesn't match the version that the other
        # end signed!
        raise SignatureError()
    return decrypted_record

def expand_handle(handle):
    bin = ux(handle)
    if len(handle) != 64 or len(bin) != 32:
        raise ValueError("lookup address too long or short")
    if not check_zerobits(slow_hash(bin, ROUNDS), ZEROBITS_REQUIRED_OVERALL):
        raise ValueError("typo in lookup address")
    pubkeyhash = hx(bin[:16])
    encryption_key = slow_hash(bin[16:], ROUNDS)
    return pubkeyhash, encryption_key

def generate_hash160s(pubkeyhash):
    # go backward and forward 12 hours to accommodate inacurate clocks
    hash160s = set()
    for offset_hours in irange(-12, 12):
        # changes at midnight UTC
        offset_days = offset_hours / 24
        days_since_epoch = time.time()/(24*3600)
        days_since_epoch += offset_days
        days_since_epoch = int(math.floor(days_since_epoch))
        to_hash = pubkeyhash + "-" + str(days_since_epoch)
        hash160 = slow_hash(to_hash, ROUNDS)[:20]
        hash160s.add(hash160)
    return list(hash160s)

def generate_innerbox(pk, sk, payload, version):
    ts = int(time.time()*1000)
    seq_ = seq.assign_seq()
    unused = 0
    to_sign = inner_pack.pack(version, ts, seq_, unused, payload)
    print(to_sign, payload)
    signed = pysodium.crypto_sign(to_sign, sk)
    return mid_pack.pack(pk, signed)

def encrypt_message(identity, payload):
    version = 1
    nonce = pysodium.randombytes(pysodium.crypto_secretbox_NONCEBYTES)
    pubkeyhash, encryption_key = expand_handle(identity.handle)
    if not validate_pubkey(identity.pk, pubkeyhash):
        raise PubkeyError()
    decrypted = generate_innerbox(identity.pk, identity.sk, payload, version)
    encrypted = pysodium.crypto_secretbox(decrypted, nonce, encryption_key)
    return outer_pack.pack(version, nonce, encrypted)

if __name__ == '__main__':
    #print(pysodium.crypto_secretbox_KEYBYTES, pysodium.crypto_secretbox_NONCEBYTES)
    #print(validate_pubkey(bytes("test3", "utf-8"), bytes()))
    #serial.save_identity('key.json', generate_identity())
    print(encrypt_message(generate_identity(), 'test1'.encode('ascii')))
    #cProfile.run('generate_identity()')
