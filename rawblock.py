import json

import plyvel

from block import Block


class RawBlock(object):
    _raw_block = 0

    @classmethod
    def initialize(cls):
        blk_height = 0
        try:
            cls._raw_block = plyvel.DB('./db/RawBlock', create_if_missing=True, error_if_exists=False)

        except:
            cls._raw_block = plyvel.DB('./db/RawBlock', create_if_missing=True)
            for key, value in cls._raw_block:
                blk_height += 1

            if blk_height >= 10:
                blk_start = blk_height - 10
            else:
                blk_start = 0

            return (blk_start, blk_height)

        else:
            return (0, 0)

    @classmethod
    def Insert_RawBlock(cls, index, block_hash, previous_block, merkle_root, difficulty, timestamp, nonce, tx_set):
        # Error_here
        newtx_set = []
        for tx in tx_set:
            newtx_set.append(json.dumps(tx.__dict__))
        block_data = {"index": index, "block_hash": block_hash, "previous_block": previous_block,
                      "merkle_root": merkle_root, "difficulty": difficulty, "timestamp": timestamp,
                      "nonce": nonce, "tx_set": json.dumps(newtx_set)}
        block_data_en = json.dumps(block_data)
        cls._raw_block.put(str(index).encode(), block_data_en.encode())

    @classmethod
    def Pop_RawBlock(cls, index):
        cls._raw_block.delete(str(index).encode())
        # Require some operations handling _BlockHeight and _Blockchain


    @classmethod
    def search_RawBlock(cls, index):
        result = RawBlock._raw_block.get(str(index).encode(), default=None)
        if result is None:
            return False
        else:
            block_data = json.loads(RawBlock._raw_block.get(str(index).encode(), default=None))
            tmptx_set = json.loads(block_data["tx_set"])
            tx_set = []
            for i in range(0, len(tmptx_set)):
                tx_set.append(tmptx_set[i])

            return Block(index, block_data["block_hash"], block_data["previous_block"], block_data["merkle_root"],
                         block_data["difficulty"], block_data["timestamp"], block_data["nonce"], tx_set)
