from Crypto.Hash import keccak

from secp256k1prp import PrivateKey


# Needed to be modified to read passphrase from key.pem
class Key(PrivateKey):
    # class variable
    _privateKey = 0
    _publicKey = 0

    # private / public key 생성
    def keyPairGenerate(self):
        # https://github.com/ludbb/secp256k1-py
        passphrase = input('Enter your passphrase for private key : ')
        keccak_hash = keccak.new(digest_bits=256)
        keccak_hash.update(passphrase.encode('ascii'))
        passphrase = keccak_hash.hexdigest()
        self.__class__._privateKey = PrivateKey(bytes(bytearray.fromhex(passphrase)), raw=True)
        self.__class__._publicKey = self.__class__._privateKey.pubkey

        return self.__class__._privateKey

    def generate_sign(self, msg):
        return self.ecdsa_sign(msg, raw=False)

    def verify(self, sig, key, msg):
        pass
        # sig_des = PrivateKey().ecdsa_deserialize(input.unlock)
        # Search rawBlock and transaction pool that match with input.txid and input.index
        # verify = vout.lock.ecdsa_verify(bytes(bytearray.fromhex(txOutid)),sig_des)
        #publickey


    def publickey(self):
        return self.__class__._publicKey

    def privatekey(self):
        return self.__class__._privateKey
