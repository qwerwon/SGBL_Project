from Crypto.Hash import keccak
import hashlib
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
        #256bit로 digest해야 한답니다 == 256bit로 맞춰야 된답니다.
        return self.ecdsa_sign(msg, raw=False, digest=hashlib.sha256)

    def verify(self, sig, key, msg):
        """

        :param sig: Signature object of package secp256k1prp
        :param key: secp256klrpr.PublicKey
        :param msg: string
        :return:
        """
        #자료형: msg: string
        #자료형: key: secp256klrpr.PublicKey
        #자료형: sig: _cffi_backend.CDataOwn  <??type으로 찾은거라...객체인듯요>
        #sig를 key를 이용해 해제 한후 msg와 같은지 확인한다.
        #msg는 str로 받아서 ascii로 encode합니다
        msg = msg.encode('ascii')

        #임시로 객체를 생성하고, pubkey를 파라미터의 key로 받는다.
        tmp = PrivateKey()
        tmp.pubkey = key

        vrf = tmp.pubkey.ecdsa_verify(msg,sig,raw = False , digest=hashlib.sha256)

        #검증 결과가 참이면 true를 return 한다. 거짓이면 false
        return vrf

    def publickey(self):
        return self.__class__._publicKey

    def privatekey(self):
        return self.__class__._privateKey
