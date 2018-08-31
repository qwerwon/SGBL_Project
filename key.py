from Crypto.Hash import keccak

from secp256k1prp import PrivateKey


# Needed to be modified to read passphrase from key.pem
class Key(PrivateKey):
    # class variable
    _privateKey = 0
    _publicKey = 0

    def keyPairGenerate(self):
        # private / public key 생성
        # https://github.com/ludbb/secp256k1-py
        passphrase = input('Enter your passphrase for private key : ')
        keccak_hash = keccak.new(digest_bits=256)
        keccak_hash.update(passphrase.encode('ascii'))
        passphrase = keccak_hash.hexdigest()
        self.__class__._privateKey = PrivateKey(bytes(bytearray.fromhex(passphrase)), raw=True)
        self.__class__._publicKey = self.__class__._privateKey.pubkey

        return self.__class__._privateKey

    def publickey(self):
        return self.__class__._publicKey

    def privatekey(self):
        return self.__class__._privateKey
