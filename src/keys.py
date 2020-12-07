from typing import Tuple
import base64

class Keys():
    def __init__(self, e, d, n):
        self.e = e
        self.d = d
        self.n = n

    def save_pubKey(self, name: str):
        template = '-----BEGIN RSA PUBLIC KEY-----\n{}\n-----END RSA PUBLIC KEY-----\n'
        keys = "e: {}\nn: {}\n".format(hex(self.e), hex(self.n))
        k_bytes = keys.encode('ascii')
        base64_bytes = base64.b64encode(k_bytes)
        base64_keys = base64_bytes.decode('ascii')
        with open("{}_pk.pem".format(name), "w") as pk_file:
            pk_file.write(template.format(base64_keys))

    def save_secKey(self, name: str):
        template = '-----BEGIN RSA PRIVATE KEY-----\n{}\n-----END RSA PRIVATE KEY-----\n'
        keys = "d: {}\nn: {}\n".format(hex(self.d), hex(self.n))
        k_bytes = keys.encode('ascii')
        base64_bytes = base64.b64encode(k_bytes)
        base64_keys = base64_bytes.decode('ascii')
        with open("{}_sk.pem".format(name), "w") as sk_file:
            sk_file.write(template.format(base64_keys))

def load_pubKey(file_name: str) -> Tuple[int, int]:
    e, n = 0, 0
    with open(file_name, "r") as pk_file:
        content = pk_file.read()
        base64_keys = content.split("\n")[1]
        base64_bytes = base64_keys.encode('ascii')
        keys_bytes = base64.b64decode(base64_bytes)
        keys_l = keys_bytes.decode('ascii').split("\n")
        for line in keys_l:
            if line.startswith("e: "):
                e = int(line.strip().replace("e: ", ""), 0)
            elif line.startswith("n: "):
                n = int(line.strip().replace("n: ", ""), 0)
    return (e, n)

def load_secKey(file_name: str) -> Tuple[int, int]:
    d, n = 0, 0
    with open(file_name, "r") as sk_file:
        content = sk_file.read()
        base64_keys = content.split("\n")[1]
        base64_bytes = base64_keys.encode('ascii')
        keys_bytes = base64.b64decode(base64_bytes)
        keys_l = keys_bytes.decode('ascii').split("\n")
        for line in keys_l:
            if line.startswith("d: "):
                d = int(line.strip().replace("d: ", ""), 0)
            elif line.startswith("n: "):
                n = int(line.strip().replace("n: ", ""), 0)
    return (d, n)

def kLen(key: Tuple[int, int]) -> int:
    """
    Returns the number of bytes of the key n.
    """
    return key[1].bit_length() // 8
