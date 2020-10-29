#!/usr/bin/sage
# vim: syntax=python

import sys
import json
import binascii

try:
    from sagelib.oprf import KeyGen, SetupBaseServer, SetupBaseClient, SetupVerifiableServer, SetupVerifiableClient, oprf_ciphersuites, _as_bytes
except ImportError as e:
    sys.exit("Error loading preprocessed sage files. Try running `make setup && make clean pyfiles`. Full error: " + e)

def to_hex(octet_string):
    if isinstance(octet_string, str):
        return "".join("{:02x}".format(ord(c)) for c in octet_string)
    assert isinstance(octet_string, bytes)
    return "0x" + "".join("{:02x}".format(c) for c in octet_string)

class Protocol(object):
    def __init__(self):
        self.inputs = map(lambda h : _as_bytes(bytearray.fromhex(h).decode()), ['00', '01', '02'])

    def run_vector(self, vector):
        raise Exception("Not implemented")

    def run(self, client, server, info):
        assert(client.suite.group == server.suite.group)
        group = client.suite.group

        vectors = []
        for x in self.inputs:
            r, R, P = client.blind(x)
            T = server.evaluate(R)
            Z = client.unblind(T, r, R)
            y = client.finalize(x, Z, info.encode("utf-8"))

            assert(server.verify_finalize(x, info.encode("utf-8"), y))

            vector = {}
            vector["Input"] = {
                "ClientInput": to_hex(x)
            }
            if (group.name == "ristretto255"):
                vector["Blind"] = {
                    "Token": hex(r),
                    "BlindedElement": binascii.hexlify(R.encode()),
                }
            else:
                vector["Blind"] = {
                    "Token": hex(r),
                    "BlindedElement": to_hex(group.serialize(R)),
                }
            if (group.name == "ristretto255"):
               vector["Evaluation"] = {
                   "EvaluatedElement": binascii.hexlify(T.evaluated_element.encode()),
               }
            else:
               vector["Evaluation"] = {
                   "EvaluatedElement": to_hex(group.serialize(T.evaluated_element)),
               }
            if T.proof != None:
                vector["Evaluation"]["proof"] = {
                    "c": hex(T.proof[0]),
                    "s": hex(T.proof[1]),
                }
            if (group.name == "ristretto255"):
               vector["Unblind"] = {
                   "IssuedToken": binascii.hexlify(Z.encode())
               }
            else:
               vector["Unblind"] = {
                   "IssuedToken": to_hex(group.serialize(Z))
               }

            vector["ClientOutput"] = to_hex(y)
            vectors.append(vector)

        vector = {}
        vector["skS"] = hex(server.skS)
        vector["info"] = info
        vector["suite"] = client.suite.name
        vector["vectors"] = vectors

        return vector

def main(path="vectors"):
    vectors = {}

    for suite in oprf_ciphersuites:
        skS, _ = KeyGen(suite)
        server = SetupBaseServer(suite, skS)
        client = SetupBaseClient(suite)
        protocol = Protocol()
        vectors["Base" + suite.name] = protocol.run(client, server, "test information")

    for suite in oprf_ciphersuites:
        skS, pkS = KeyGen(suite)
        server, pkS = SetupVerifiableServer(suite, skS, pkS)
        client = SetupVerifiableClient(suite, pkS)
        protocol = Protocol()
        vectors["Verifiable" + suite.name] = protocol.run(client, server, "test information")

    with open(path + "/allVectors.json", 'wt') as f:
        json.dump(vectors, f, sort_keys=True, indent=2)
        f.write("\n")

if __name__ == "__main__":
    main()
