import plyvel

class UTXO(object):
    def __init__(self, txOutid, index, address, amount):
        self.txOutid = txOutid                  # bytes : key
        self.index = index                      # int
        self.address = address                  # bytes => PublicKey(pub, raw=True)로 디코딩
        self.amount = amount                    # float


class UTXOset(object):
    # class variables
    _UTXOset = 0
    _myUTXOset = 0
    def initialize(self):
        self.__class__. _UTXOset = plyvel.DB('/db/UTXOset/', create_if_missing=True)
        self.__class__. _myUTXOset = plyvel.DB('/db/myUTXOset/', create_if_missing=True)

    #def append(self, arg...):

    #def search(self, arg...):

    def utxoSet(self):
        return self.__class__._UTXOset

    def myutxoSet(self):
        return self.__class__._myUTXOset
