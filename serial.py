#!/usr/bin/env python3
import collections
import json
import binascii


hx = lambda x: binascii.hexlify(x).decode('ascii')
ux = binascii.unhexlify
hex_fields = ['pk', 'sk', 'enc']
Identity = collections.namedtuple('Identity', 'pk sk enc handle')

def load_identities(filename):
    with open(filename, 'r') as f:
        data = json.loads(f.read())
    def process_ident(ident):
        for field in ident:
            if field in hex_fields:
                ident[field] = ux(ident[field])
        return Identity(**ident) 
    return list(map(process_ident, data))

def load_identity(filename, handle):
    data = load_identities(filename)
    data = filter(lambda ident: ident.handle == handle, data)
    data = list(data)
    if len(data) < 1:
        raise ValueError("Handle '%s' not found in file '%s'" % \
            (handle, filename))
    if len(data) > 1:
        raise ValueError("Duplicate handle in file '%s'" % \
            (filename))
    return data[0]

def save_identities(filename, identities):
    def process_ident(ident):
        d = ident._asdict()
        for field in d:
            if field in hex_fields:
                d[field] = hx(d[field])
        return d
    serialized = list(map(process_ident, identities))
    with open(filename, 'w+') as f:
        f.write(json.dumps(serialized, indent=4))

def save_identity(filename, identity):
    idents = load_identities(filename)
    print(idents)
    for ident in idents:
        if ident.handle == identity.handle:
            return
    idents.append(identity)
    save_identities(filename, idents)

if __name__ == '__main__':
    print(load_identity('key.json', 'uiop'))
    save_identity('key2.json', load_identity('key.json', 'uiop'))
