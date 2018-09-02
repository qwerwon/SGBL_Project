import json
import time

from block import Block
from merkleroot import create_merkle_root
from rawblock import RawBlock
from transaction import Transaction


class Blockchain(object):
    # class variables
    _BlockChain = []
    _BlockHeight = 0

    @classmethod
    def initialize(cls):
        (block_start, block_height) = RawBlock.initialize()
        if block_height == 0:
            Blockchain.getGenesisblock()
            cls._BlockHeight = 1

        else:
            for i in range(block_start, block_height):
                cls._BlockChain.append(RawBlock.search_RawBlock(i))
            cls._BlockHeight = block_height

    @classmethod
    def getGenesisblock(cls):
        difficulty = 0x0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
        cur_time = int(time.time())
        RawBlock.Insert_RawBlock(0, '0', '0', '0', difficulty, cur_time, 0, [])
        cls._BlockChain.append(Block(0, '0', '0', '0', difficulty, cur_time, 0, []))
        cls._BlockHeight = 1

    @classmethod
    def add_block(cls, index, block_hash, previous_block, merkle_root, difficulty, timestamp, nonce, tx_set):
        RawBlock.Insert_RawBlock(index, block_hash, previous_block, merkle_root, difficulty, timestamp, nonce, tx_set)
        cls._BlockChain.append(Block(index, block_hash, previous_block, merkle_root, difficulty, timestamp, nonce, tx_set))
        cls._BlockHeight += 1
        if cls._BlockHeight > 10:
            del cls._BlockChain[0]


    # Method that calculates the vout's values
    def Calculate_block_vouts(self, tx_id, index):
        # if there is no key-value data in db
        if RawBlock._raw_block.get(str(index).encode(),default=None) is None:
            return 0

        #if there is key-value data in db
        else:
            total_val=0
            tmpbl_Data=json.loads(RawBlock._raw_block.get(str(index).encode()),default=None)
            tmptx_set=json.loads(tmpbl_Data["tx_set"])
            for i in range(0,len(tmptx_set)):
                tmptx_set_el=json.loads(tmptx_set[i])
                if tmptx_set_el.tx_id == tx_id:
                    tmptx_vout=tmptx_set_el.vout
                    break
            for i in range(0,len(tmptx_vout)):
                total_val += tmptx_vout.value
            return total_val

    def getLatestBlock(self):
        if Blockchain._BlockHeight > 10:
            return Blockchain._BlockChain[9]
        else:
            return Blockchain._BlockChain[Blockchain._BlockHeight-1]

    def get_difficulty(self, index, prev_diff):
        if index > 6:
            if index > 9:
                elapsed = Blockchain._BlockChain[9].timestamp - Blockchain._BlockChain[3].timestamp
            else:
                elapsed = Blockchain._BlockChain[index-1].timestamp - Blockchain._BlockChain[index-6].timestamp
            return int(elapsed/50*prev_diff)
        else:
            return 0x0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff

    def set_candidateblock(self):
        # warning for poinint class var
        block_index = Blockchain._BlockHeight
        prev_block = self.getLatestBlock()
        previous_block = prev_block.block_hash

        tx_set = []
        total_fee = 12.5

        # get tx_set from MemPool greedy
        # calculate total commission of tx_set(total_fee)
        # Transaction priority required

        coinbase = Transaction(b'0', 0, [], 0, []).generate_coinbase(total_fee)
        tx_set.insert(0, coinbase)

        merkle_root = create_merkle_root(tx_set)
        difficulty = Blockchain().get_difficulty(Blockchain._BlockHeight, prev_block.difficulty)

        return Block(block_index, '0', previous_block, merkle_root, difficulty, 0, 0, tx_set)

    #Require block fork management methods

