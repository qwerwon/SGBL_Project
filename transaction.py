import json

import plyvel

# vin class
########################################################################################################################
class Vin:
    def __init__(self, tx_id, index, unlock):
        self.tx_id = tx_id                      # string
        self.index = index                      # int
        self.unlock = unlock                    # bytes => Privatekey.ecdsa_deserialize(unlock)로 디코딩


# Vout class
########################################################################################################################
class Vout:
    def __init__(self, value, lock):
        self.value = value                      # float
        self.lock = lock                        # bytes => PublicKey(pub, raw=True)로 디코딩


# Transaction class
########################################################################################################################
class Transaction(object):

    # class variables
    _MemoryPool = 0

    # init
    ####################################################################################################################
    def __init__(self, tx_id, in_num, vin, out_num, vout):
        # Key = tx_id
        self.tx_id = tx_id          # bytes
        self.in_num = in_num        # int
        self.vin = vin              # list[Vin]
        self.out_num = out_num      # int
        self.vout = vout            # list[Vout]

    # Make db for store pending transaction
    ####################################################################################################################
    @classmethod
    def initialize(cls):
        cls._MemoryPool = plyvel.DB('./db/MemoryPool', create_if_missing=True)


    # Insert transaction to DB
    ####################################################################################################################
    @classmethod
    def Insert_MemoryPool(cls, tx_id, in_counter, vin, out_counter, vout):
        """
        Args:
            tx_id       : bytes(key of db)
            in_counter  : int
            vin         : list[Vin]
            out_counter : int
            vout        : list[Vout]
        """

        newVin = []
        newVout = []

        # Convert vin and vout for store
        ################################################################################################################
        for vin_el in vin:
            newVin.append(json.dumps(vin_el.__dict__))

        for vout_el in vout:
            newVout.append(json.dumps(vout_el.__dict__))

        mempool = {"in_num": in_counter,
                   "vin": json.dumps(newVin),
                   "out_num": out_counter,
                   "vout": json.dumps(newVout)}

        mempool_en = json.dumps(mempool)

        cls._MemooryPool.put(tx_id, mempool_en.encode())

    # Pop transaction from DB
    ####################################################################################################################
    @classmethod
    def Pop_MemoryPool(cls, tx_id):
        """
        Args:
            tx_id       : bytes(key of db)
        """

        cls._MemoryPool.delete(tx_id, sync=True)
