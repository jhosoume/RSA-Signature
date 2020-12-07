./pyssl genKeys
./pyssl genKeys wr
./pyssl sign tests/T1/msg_sent.txt key_sk.pem
./pyssl verify tests/T1/msg_rec.txt signature.sha3 key_pk.pem
./pyssl verify tests/T1/msg_rec_wrong.txt signature.sha3 key_pk.pem
./pyssl verify tests/T1/msg_rec.txt signature.sha3 wr_pk.pem
