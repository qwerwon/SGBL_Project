import base64
import json

import plyvel


class UTXO(object):

    def __init__(self, txOutid, index, address, amount):
        # Key = txOutid(in byte) + index.to_bytes(1, byteorder="little")
        self.txOutid = txOutid                  # string
        self.index = index                      # int
        self.address = address                  # string => bytes => PublicKey(pub, raw=True)로 디코딩
        self.amount = amount                    # float

'''
Vout.lock => UTXO.address
(bytes => string)
sig_str = base64.b64encode(sig_bytes).decode('utf-8')

UTXO.address => Vout.lock
(string => bytes)
sig_bytes = base64.b64decode(sig_str)
'''

# UTXOset Class
class UTXOset(object):
    # class variables
    _UTXOset = 0
    _myUTXOset = 0

    @classmethod
    def initialize(cls):
        cls. _UTXOset = plyvel.DB('./db/UTXOset/', create_if_missing=True)
        cls. _myUTXOset = plyvel.DB('./db/myUTXOset/', create_if_missing=True)

    @classmethod
    def Insert_UTXO(cls, txOutid, index, address, amount):
        """
        Key of DB       : txOutid + index.to_bytes(1, byteorder="little")

        Args:
            txOutid     : bytes
            index       : int
            address     : string
            amount      : int
        """

        key = txOutid + index.to_bytes(1, byteorder="little")
        txOutid_str = base64.b64encode(txOutid).decode('utf-8')
        utxo={'txOutid':txOutid_str, 'index': index, 'address': address, 'amount': amount}
        utxo_en=json.dumps(utxo)
        cls._UTXOset.put(key, utxo_en.encode())

    @classmethod
    def Pop_UTXO(cls, txOutid, index):
        """
         Key of DB       : txOutid + index.to_bytes(1, byteorder="little")

        Args:
            txOutid     : bytes
            index       : int
        """

        key = txOutid + index.to_bytes(1, byteorder="little")
        cls._UTXOset.delete(key, sync=True)

    @classmethod
    def get_UTXO(cls, txOutid, index):
        """

        :param txOutid  : byte
        :param index    : int
        :return         : False or UTXO
        """
        key = txOutid + index.to_bytes(1, byteorder="little")

        result = cls._UTXOset.get(key, default=None)

        if result is None:
            return False

        else:
            data_json = json.loads(result)
            return UTXO(txOutid, index, data_json['address'], data_json['amount'])

    @classmethod
    def Insert_myUTXO(cls, txOutid, index, address, amount):
        """
        Key of DB       : txOutid + index.to_bytes(1, byteorder="little")

        Args:
            txOutid     : bytes
            index       : int
            address     : string
            amount      : int
        """

        key = txOutid + index.to_bytes(1, byteorder="little")
        txOutid_str = base64.b64encode(txOutid).decode('utf-8')
        myutxo={'txOutid':txOutid_str, 'index': index, 'address': address, 'amount': amount}
        myutxo_en=json.dumps(myutxo)
        cls._myUTXOset.put(key, myutxo_en.encode())

    @classmethod
    def Pop_myUTXO(cls, txOutid, index):
        """
        Key of DB       : txOutid + index.to_bytes(1, byteorder="little")

        Args:
            txOutid     : bytes
            index       : int
        """

        key = txOutid + index.to_bytes(1, byteorder="little")
        cls._myUTXOset.delete(key, sync=True)

    @classmethod
    def get_myUTXO(cls, txOutid, index):
        """

        :param txOutid  : bytes
        :param index    : int
        :return         : UTXO
        """
        key = txOutid + index.to_bytes(1, byteorder="little")

        result = cls._myUTXOset.get(key, default=None)

        if result is None:
            return False
        else:
            data_json = json.loads(result)
            return UTXO(txOutid, index, data_json['address'], data_json['amount'])
