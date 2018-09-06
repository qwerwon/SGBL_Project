import json
import base64

import plyvel


# Vin class
class Vin(object):
    def __init__(self, tx_id, index, unlock):
        self.tx_id = tx_id                      # string
        self.index = index                      # int
        self.unlock = unlock                    # bytes => Privatekey.ecdsa_deserialize(unlock)로 디코딩

    def to_dict(self):
        return {'tx_id': self.tx_id, 'index': self.index, 'unlock': base64.b64encode(self.unlock).decode('utf-8')}

    def from_dict(self, data_json):
        return Vin(data_json["tx_id"], data_json["index"], base64.b64decode(data_json["unlock"]))


# Vout class
class Vout(object):
    def __init__(self, value, lock):
        self.value = value                      # float
        self.lock = lock                        # bytes => PublicKey(pub, raw=True)로 디코딩

    def to_dict(self):
        return {'value': self.value, 'lock': base64.b64encode(self.lock).decode('utf-8')}

    def from_dict(self, data_json):
        return Vout(data_json["value"], base64.b64decode(data_json["lock"]))


# Transaction class
class Transaction(object):

    # class variables
    _MemoryPool = 0

    # init
    def __init__(self, tx_id, in_num, vin, out_num, vout):
        # Key = tx_id
        self.tx_id = tx_id          # bytes
        self.in_num = in_num        # int
        self.vin = vin              # list[Vin]
        self.out_num = out_num      # int
        self.vout = vout            # list[Vout]

    # Make db for store pending transaction
    @classmethod
    def initialize(cls):
        """
        Open and initialize Database of MemoryPool

        """

        cls._MemoryPool = plyvel.DB('./db/MemoryPool', create_if_missing=True)

    # Insert transaction to DB
    @classmethod
    def Insert_MemoryPool(cls, tx_id, in_counter, vin, out_counter, vout):
        """
        Insert Transaction into MemoryPool DB as
            key         : tx_id(bytes)
            value       : {'tx_id': string, 'in_num': int, 'vin': [Vin().to_dict], 'out_num': int,
                           'vout': [Vout().to_dict]}

        Args:
            tx_id       : bytes
            in_num      : int
            vin         : list[Vin()]
            out_num     : int
            vout        : list[Vout()]
        """

        tx_data = Transaction(tx_id, in_counter, vin, out_counter, vout).to_dict()
        tx_data_en = json.dumps(tx_data).encode()

        cls._MemoryPool.put(tx_id, tx_data_en)

    # Pop transaction from DB
    @classmethod
    def Pop_MemoryPool(cls, tx_id):
        """
        Delete Transaction from MemoryPool DB
            key         : txOutid(bytes) + index(bytes)

        Args:
            tx_id       : bytes(key of db)
        """

        cls._MemoryPool.delete(tx_id, sync=True)

    @classmethod
    def get_MemoryPool(cls, tx_id):
        """
        Fetch Transaction from MemoryPool DB
            key         : tx_id(bytes)

        Args:
            tx_id       : bytes(key of db)

        return:
            Transaction object or False
        """

        result = Transaction._MemoryPool.get(tx_id, default=None)

        if result is None:
            return False
        else:
            data_json = json.loads(result)
            return Transaction(b'0', 0, [], 0, []).from_dict(data_json)

    def to_dict(self):
        return {'tx_id': base64.b64encode(self.tx_id).decode('utf-8'), 'in_num': self.in_num,
                'vin': [item.to_dict() for item in self.vin], 'out_num': self.out_num, 'vout': [item.to_dict() for item in self.vout]}

    def from_dict(self, data_json):
        return Transaction(base64.b64decode(data_json["tx_id"]), data_json["in_num"],
                           [Vin(0, 0, 0).from_dict(item) for item in data_json["vin"]], data_json["out_num"],
                           [Vout(0, 0).from_dict(item) for item in data_json["vout"]])
