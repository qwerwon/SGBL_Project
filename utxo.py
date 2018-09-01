import plyvel

class UTXO(object):
    def __init__(self, txOutid, index, address, amount):
        self.txOutid = txOutid                  # bytes : key
        self.index = index                      # int
        self.address = address                  # string => bytes => PublicKey(pub, raw=True)로 디코딩
        self.amount = amount                    # float

# input / output
class Vin:
    def __init__(self, tx_id, index, unlock):
        self.tx_id = tx_id                      # string
        self.index = index                      # int
        self.unlock = unlock                    # bytes => Privatekey.ecdsa_deserialize(unlock)로 디코딩
class Vout:
    def __init__(self, value, lock):
        self.value = value                      # float
        self.lock = lock                        # bytes => PublicKey(pub, raw=True)로 디코딩

'''
Vout.lock => UTXO.address
(bytes => string)
sig_str = base64.b64encode(sig_bytes).decode('utf-8')

UTXO.address => Vout.lock
(string => bytes)
sig_bytes = base64.b64decode(sig_str)
'''

class UTXOset(object):
    # class variables
    _UTXOset = 0
    _myUTXOset = 0

    @classmethod
    def initialize(cls):
        cls. _UTXOset = plyvel.DB('./db/UTXOset/', create_if_missing=True)
        cls. _myUTXOset = plyvel.DB('./db/myUTXOset/', create_if_missing=True)

    #def append(self, arg...):

    #def search(self, arg...):
    
    

    def utxoSet(self):
        return self.__class__._UTXOset

    def myutxoSet(self):
        return self.__class__._myUTXOset
    



    def Insert_UTXO(self,txOutid,index,address,amount):
        utxo={'txOutid':str(txOutid),'index': str(index),'address':str(address),'amount': str(amount)}
        utxo_en=json.dumps(utxo)
        UTXOset._UTXOset.put(txOutid.encode(),utxo_en.encode())
    
    def Pop_UTXO(self,txOutid):
        UTXOset._UTXOset.delete(txOutid.encode(),sync=True)




    def Insert_myUTXO(self,txOutid,index,address,amount):
        myutxo={'txOutid':str(txOutid),'index': str(index),'address':str(address),'amount': str(amount)}
        myutxo_en=json.dumps(utxo)
        UTXOset._myUTXOset.put(txOutid.encode,myutxo_en.encode())
    def Pop_myUTXO(self,txOutid):
        UTXOset._myUTXOset.delete(txOutid.encode(),sync=True)


        
        
