import base64
import json
import time

import plyvel

from transaction import Transaction, Vin, Vout

class Block(object):
    # Class variables
    _BlockChain = []
    _BlockHeight = 0
    _raw_block = 0

    # Block class init
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


    # Get Block Info from db
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

                cls.insert_blockchain(i,
                                      tmp_block.block_hash,
                                      tmp_block.previous_block,
                                      tmp_block.merkle_root,
                                      tmp_block.difficulty,
                                      tmp_block.timestamp,
                                      tmp_block.nonce,
                                      tmp_block.tx_set)

        else:
            difficulty = 0x0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
            cls.insert_blockchain(0, '0', '0', '0', difficulty, int(time.time()), 0, [])

    # Insert Block to db
    @classmethod
    def Insert_RawBlock(cls, block_index, block_hash, previous_block, merkle_root, difficulty, timestamp, nonce, tx_set):
        """
        Key of DB       : str(index).encode()

        Args:
            block_index     : int
            block_hash      : string
            previous_block  : string
            merkle_root     : string
            difficulty      : int
            timestamp       : int
            nonce           : int
            tx_set          : list[Transaction()]
        """

        blk_data = Block(block_index, block_hash, previous_block, merkle_root, difficulty, timestamp, nonce, tx_set).to_dict()
        block_data_en = json.dumps(blk_data).encode()
        cls._raw_block.put(str(block_index).encode(), block_data_en)

    # Pop block from DB
    @classmethod
    def Pop_RawBlock(cls, index):
        """
        Key of DB       : str(index).encode()

        Args:
            index           : int
        """

        cls._raw_block.delete(str(index).encode())
        # Require some operations handling _BlockHeight and _Blockchain

    # Search block from DB
    @classmethod
    def get_RawBlock(cls, index):
        """
        Key of DB       : str(index).encode()

        Args:
            index           : int

        Returns:
            Block()
        """

        result = Block._raw_block.get(str(index).encode(), default=None)

        if result is None:
            return False
        else:
            data_json = json.loads(result)
            return Block(0, '0', '0', '0', 0, 0, 0, []).from_dict(data_json)

    # Insert block into blockchain
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

        cls._BlockChain.append(
            Block(index,
                  block_hash,
                  previous_block,
                  merkle_root,
                  difficulty,
                  timestamp,
                  nonce,
                  tx_set))

        cls._BlockHeight += 1

        if cls._BlockHeight > 10:
            del cls._BlockChain[0]

    def to_dict(self):
        return {'block_index': self.block_index, 'block_hash': self.block_hash, 'previous_block': self.previous_block,
                'merkle_root': self.merkle_root, 'difficulty': self.difficulty, 'timestamp': self.timestamp,
                'nonce': self.nonce, 'tx_set': [item.to_dict() for item in self.tx_set]}

    def from_dict(self, data_json):
        return Block(data_json["block_index"], data_json["block_hash"], data_json["previous_block"],
                     data_json["merkle_root"], data_json["difficulty"], data_json["timestamp"],
                     data_json["nonce"], [Transaction(0, 0, 0, 0, 0).from_dict(item) for item in data_json["tx_set"]])

