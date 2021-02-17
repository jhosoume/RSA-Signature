# Digital Signature Using RSA-OAEP and SHA-3

A CLI for creating RSA keys, signatures and verification. 

---
## Commands
* genKeys
```console
./pyssl genKeys my_keys -s 1024
```

Generates public and secret keys. The argument defines the name of the genarated files cointaining the keys in the PEM format. The `pk` in the name means public key, whereas `sk` meas secret key. The option `-s` allows modificaton on the number of bits of the keys.

* sign 
```console
./pyssl  sign  tests/T1/msg_sent.txt  key_sk.pem -o signature.sha3
```
Generates a signature for a file based on the secret key. The first argument is the file to be signed and the second argument is the secret key (defines `d` and `n` values). The option `-o` defines the name of the output file (signature file).

* verify
```console
./ pyssl  verify  tests/T1/msg_rec.txt  signature.sha3  key_pk.pem
``` 
Verifies if the file and signature are valids. In other words, checks if the file was not modified and if it belongs to the intended sender. The first argument is the file with the message, the second argument is the signatured of the file and the third and last argument is the public key of the sender. The output of this command is a message indicating if the signature is valid.

---
## Installation

Recommended installation:
* Creating Python Env
```console
python3 -m venv rsa_sig
```

* Use the Python Env
```console
source rsa_sig/bin/activate
```

*  Get Required Packages
```console
pip install -r requirements.txt
```

* Run
```console
./pyssl
```

* To run a sample test
```console
./run_t1.sh
```
