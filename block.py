import json
import time
import base64

import plyvel

from transaction import Transaction, Vin, Vout
from utxo import UTXO, UTXOset

class Block(object):
    # class variables
    _BlockChain = []
    _BlockHeight = 0
    _raw_block = 0

    def __init__(self, block_index, block_hash, previous_block, merkle_root, difficulty, timestamp, nonce, tx_set):
        # Key = str(index).encode()
        self.block_index = block_index          # int
        self.block_hash = block_hash            # string
        self.previous_block = previous_block    # string
        self.merkle_root = merkle_root          # string
        self.difficulty = difficulty            # int
        self.timestamp = timestamp              # int
        self.nonce = nonce                      # int
        self.tx_set = tx_set                    # list[Transaction]

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

            cls._BlockHeight = blk_height
            for i in range(blk_start, blk_height):
                tmp_block = cls.search_RawBlock(i)
                if tmp_block is False:
                    print('Block initialize faile')
                    return False

                cls.insert_blockchain(i, tmp_block.block_hash, tmp_block.previous_block, tmp_block.merkle_root,
                                      tmp_block.difficulty, tmp_block.timestamp, tmp_block.nonce, tmp_block.tx_set)

        else:
            difficulty = 0x0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
            cls.insert_blockchain(0, '0', '0', '0', difficulty, int(time.time()), 0, [])

    @classmethod
    def Insert_RawBlock(cls, index, block_hash, previous_block, merkle_root, difficulty, timestamp, nonce, tx_set):
        """
        Key of DB       : str(index).encode()

        Args:
            index           : int
            block_hash      : string
            previous_block  : string
            merkle_root     : string
            difficulty      : int
            timestamp       : int
            nonce           : int
            tx_set          : list[Transaction()]
        """

        newtx_set = []
        for tx in tx_set:
            newtx = Transaction(0, 0, 0, 0, 0)
            newtx.tx_id = base64.b64encode(tx.tx_id).decode('utf-8')
            newtx.in_num = tx.in_num
            newvin = []
            for vin in tx.vin:
                newvin.append(json.dumps(Vin(0, 0).__dict__))
            newtx.out_num = tx.out_num
            newvout = []
            for vout in tx.vout:
                newvout.append(json.dumps(Vout(0, 0).__dict__))
            newtx.vin = newvin
            newtx.vout = newvout
            newtx_set.append(json.dumps(newtx.__dict__))
        block_data = {"index": index, "block_hash": block_hash, "previous_block": previous_block,
                      "merkle_root": merkle_root, "difficulty": difficulty, "timestamp": timestamp,
                      "nonce": nonce, "tx_set": json.dumps(newtx_set)}
        block_data_en = json.dumps(block_data)
        cls._raw_block.put(str(index).encode(), block_data_en.encode())

    @classmethod
    def Pop_RawBlock(cls, index):
        """
        Key of DB       : str(index).encode()

        Args:
            index           : int
        """

        cls._raw_block.delete(str(index).encode())
        # Require some operations handling _BlockHeight and _Blockchain

    @classmethod
    def search_RawBlock(cls, index):
        """
        Key of DB       : str(index).encode()

        Args:
            index           : int

        Returns:
            Block()
        """

        result = cls._raw_block.get(str(index).encode(), default=None)
        if result is None:
            return False
        else:
            block_data = json.loads(cls._raw_block.get(str(index).encode(), default=None))
            tmptx_set = json.loads(block_data["tx_set"])
            tx_set = []
            for i in range(0, len(tmptx_set)):
                tx_set.append(tmptx_set[i])

            return Block(index, block_data["block_hash"], block_data["previous_block"], block_data["merkle_root"],
                         block_data["difficulty"], block_data["timestamp"], block_data["nonce"], tx_set)

    @classmethod
    def insert_blockchain(cls, index, block_hash, previous_block, merkle_root, difficulty, timestamp, nonce, tx_set):
        """
        Key of DB       : str(index).encode()

        Args:
            index           : int
            block_hash      : string
            previous_block  : string
            merkle_root     : string
            difficulty      : int
            timestamp       : int
            nonce           : int
            tx_set          : list[Transaction()]
        """

        cls._BlockChain.append(Block(index, block_hash, previous_block, merkle_root, difficulty, timestamp, nonce, tx_set))
        cls._BlockHeight += 1
        if cls._BlockHeight > 10:
            del cls._BlockChain[0]

