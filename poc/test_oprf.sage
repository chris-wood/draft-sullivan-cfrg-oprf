#!/usr/bin/sage
# vim: syntax=python

import sys
import json
import binascii

try:
    from sagelib.oprf \
    import DeriveKeyPair, SetupBaseServer, SetupBaseClient, SetupVerifiableServer, \
           SetupVerifiableClient, oprf_ciphersuites, _as_bytes, MODE_BASE,  \
           MODE_VERIFIABLE, \
           ciphersuite_ristretto255_sha512, \
           ciphersuite_decaf448_shake256, \
           ciphersuite_p256_sha256, \
           ciphersuite_p384_sha512, \
           ciphersuite_p521_sha512
except ImportError as e:
    sys.exit("Error loading preprocessed sage files. Try running `make setup && make clean pyfiles`. Full error: " + e)

def to_hex_string(octet_string):
    if isinstance(octet_string, str):
        return "".join("{:02x}".format(ord(c)) for c in octet_string)
    assert isinstance(octet_string, (bytes, bytearray))
    return "".join("{:02x}".format(c) for c in octet_string)

def to_hex(octet_string):
    if isinstance(octet_string, list):
        return ",".join([to_hex_string(x) for x in octet_string])
    return to_hex_string(octet_string)

test_suites = [
    ciphersuite_ristretto255_sha512,
    ciphersuite_decaf448_shake256,
    ciphersuite_p256_sha256,
    ciphersuite_p384_sha512,
    ciphersuite_p521_sha512
]

class Protocol(object):
    def __init__(self, suite, mode):
        self.inputs = [b'\x00', b'\x5A'*17]
        self.suite = suite
        self.mode = mode

        self.seed = b'\xA3' * suite.group.scalar_byte_length()
        skS, pkS = DeriveKeyPair(self.mode, self.suite, self.seed)
        if mode == MODE_BASE:
            self.server = SetupBaseServer(suite, skS)
            self.client = SetupBaseClient(suite)
        elif mode == MODE_VERIFIABLE:
            self.server = SetupVerifiableServer(suite, skS, pkS)
            self.client = SetupVerifiableClient(suite, pkS)
        else:
            raise Exception("bad mode")

    def run(self):
        group = self.client.suite.group
        client = self.client
        server = self.server

        def create_test_vector_for_input(x):
            blind, blinded_element = client.blind(x)
            evaluated_element, proof, proof_randomness = server.evaluate(blinded_element)
            output = client.finalize(x, blind, evaluated_element, blinded_element, proof)

            assert(server.verify_finalize(x, output))

            vector = {}
            vector["Blind"] = to_hex(group.serialize_scalar(blind))
            vector["BlindedElement"] = to_hex(blinded_element)
            vector["EvaluationElement"] = to_hex(evaluated_element)

            if self.mode == MODE_VERIFIABLE:
                vector["EvaluationProof"] = {
                    "c": to_hex(group.serialize_scalar(proof[0])),
                    "s": to_hex(group.serialize_scalar(proof[1])),
                    "r": to_hex(group.serialize_scalar(proof_randomness)),
                }

            vector["Input"] = to_hex(x)
            vector["Output"] = to_hex(output)
            vector["Batch"] = int(1)

            return vector

        def create_batched_test_vector_for_inputs(xs):
            blinds = []
            blinded_elements = []
            for x in xs:
                blind, blinded_element = client.blind(x)
                blinds.append(blind)
                blinded_elements.append(blinded_element)

            evaluated_elements, proof, proof_randomness = server.evaluate_batch(blinded_elements)

            outputs = client.finalize_batch(xs, blinds, evaluated_elements, blinded_elements, proof)
            for i, output in enumerate(outputs):
                assert(server.verify_finalize(xs[i], output)) 

            vector = {}
            vector["Blind"] = ",".join([to_hex(group.serialize_scalar(blind)) for blind in blinds])
            vector["BlindedElement"] = to_hex(blinded_elements)
            vector["EvaluationElement"] = to_hex(evaluated_elements)

            if self.mode == MODE_VERIFIABLE:
                vector["EvaluationProof"] = {
                    "c": to_hex(group.serialize_scalar(proof[0])),
                    "s": to_hex(group.serialize_scalar(proof[1])),
                    "r": to_hex(group.serialize_scalar(proof_randomness)),
                }

            vector["Input"] = to_hex(xs)
            vector["Output"] = to_hex(outputs)
            vector["Batch"] = int(len(xs))

            return vector

        vectors = [create_test_vector_for_input(x) for x in self.inputs]
        if self.mode == MODE_VERIFIABLE:
            vectors.append(create_batched_test_vector_for_inputs(self.inputs))

        vecSuite = {}
        vecSuite["suiteName"] = self.suite.name
        vecSuite["suiteID"] = int(self.suite.identifier)
        vecSuite["mode"] = int(self.mode)
        vecSuite["hash"] = self.suite.H().name.upper()
        vecSuite["seed"] = to_hex(self.seed)
        vecSuite["skSm"] = to_hex(group.serialize_scalar(server.skS))
        vecSuite["groupDST"] = to_hex(client.group_domain_separation_tag())
        if self.mode == MODE_VERIFIABLE:
            vecSuite["pkSm"] = to_hex(group.serialize(server.pkS))
        vecSuite["vectors"] = vectors

        return vecSuite

def wrap_write(fh, arg, *args):
    line_length = 68
    string = " ".join( [arg] + list(args))
    for hunk in (string[0+i:line_length+i] for i in range(0, len(string), line_length)):
        if hunk and len(hunk.strip()) > 0:
            fh.write(hunk + "\n")

def write_blob(fh, name, blob):
    wrap_write(fh, name + ' = ' + to_hex(blob))

def write_value(fh, name, value):
    wrap_write(fh, name + ' = ' + value)

def write_base_vector(fh, vector):
    fh.write("~~~\n")
    write_value(fh, "seed", vector["seed"])
    write_value(fh, "skSm", vector["skSm"])
    fh.write("~~~\n")
    fh.write("\n")
    for i, v in enumerate(vector["vectors"]):
        fh.write("#### Test Vector " + str(i+1) + ", Batch Size " + str(v["Batch"]) + "\n")
        fh.write("\n")
        fh.write("~~~\n")
        write_value(fh, "Input", v["Input"])
        write_value(fh, "Blind", v["Blind"])
        write_value(fh, "BlindedElement", v["BlindedElement"])
        write_value(fh, "EvaluationElement", v["EvaluationElement"])
        write_value(fh, "Output", v["Output"])
        fh.write("~~~\n")
        fh.write("\n")

def write_verifiable_vector(fh, vector):
    fh.write("~~~\n")
    write_value(fh, "seed", vector["seed"])
    write_value(fh, "skSm", vector["skSm"])
    write_value(fh, "pkSm", vector["pkSm"])
    fh.write("~~~\n")
    fh.write("\n")
    for i, v in enumerate(vector["vectors"]):
        fh.write("#### Test Vector " + str(i+1) + ", Batch Size " + str(v["Batch"]) + "\n")
        fh.write("\n")
        fh.write("~~~\n")
        write_value(fh, "Input", v["Input"])
        write_value(fh, "Blind", v["Blind"])
        write_value(fh, "BlindedElement", v["BlindedElement"])
        write_value(fh, "EvaluationElement", v["EvaluationElement"])
        write_value(fh, "EvaluationProofC", v["EvaluationProof"]["c"])
        write_value(fh, "EvaluationProofS", v["EvaluationProof"]["s"])
        write_value(fh, "Output", v["Output"])
        fh.write("~~~\n")
        fh.write("\n")

def main(path="vectors"):
    allVectors = {}
    for suite_id in test_suites:
        suite = oprf_ciphersuites[suite_id]
        suiteVectors = {}
        for mode in [MODE_BASE, MODE_VERIFIABLE]:
            protocol = Protocol(suite, mode)
            suiteVectors[str(mode)] = protocol.run()
        allVectors[suite.name] = suiteVectors

    flatVectors = []
    for suite in allVectors:
        for mode in allVectors[suite]:
            flatVectors.append(allVectors[suite][mode])
    with open(path + "/allVectors.json", 'wt') as f:
        json.dump(flatVectors, f, sort_keys=True, indent=2)
        f.write("\n")

    with open(path + "/allVectors.txt", 'wt') as f:
        for suite in allVectors:
            f.write("## " + suite + "\n")
            f.write("\n")
            for mode in allVectors[suite]:
                if mode == str(MODE_BASE):
                    f.write("### Base Mode\n")
                    f.write("\n")
                    write_base_vector(f, allVectors[suite][mode])
                else:
                    f.write("### Verifiable Mode\n")
                    f.write("\n")
                    write_verifiable_vector(f, allVectors[suite][mode])

if __name__ == "__main__":
    main()
