import json
import plyvel


class MemoryPool(object):
    # class variables
    _MemoryPool = 0

    @classmethod
    def initialize(cls):
        cls._MemoryPool = plyvel.DB('./db/MemoryPool/', create_if_missing=True)

    @classmethod
    def Insert_MemoryPool(cls, tx_id, in_counter, vin, out_counter, vout):
        newVin = []
        newVout = []

        for vin_el in vin:
            newVin.append(json.dumps(vin_el.__dict__))
        for vout_el in vout:
            newVout.append(json.dumps(vout_el.__dict__))
        mempool = {"in_num": in_counter, "vin": json.dumps(newVin), "out_num": out_counter, "vout": json.dumps(newVout)}
        mempool_en = json.dumps(mempool)
        cls._MemooryPool.put(tx_id, mempool_en.encode())

    @classmethod
    def Pop_MemoryPool(cls, tx_id):
        cls._MemoryPool.delete(tx_id, sync=True)