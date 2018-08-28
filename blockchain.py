import time
import json
from block import Block
import os.path
import plyvel

class Blockchain(object):
    # class variables
    _BlockChain = []
    _RawBlock = 0
    _BlockHeight = 0

    @classmethod
    def initialize(cls):
        #Should be revised
        cls._RawBlock = plyvel.DB('./db/RawBlock/', create_if_missing=True)
        #if(os.path.isdir('./db/RawBlock')==False):
        cls.getGenesisblock()
        cls._BlockHeight = 0
        #else:
            #Read from DB and update Blockchain._BlockChain
        #    pass

    @classmethod
    def addBlock(cls, newBlock):
        Blockchain._BlockChain.append(newBlock)
        cls._BlockHeight += 1


    @classmethod
    def getGenesisblock(cls):
        cls._BlockChain.append(Block(0, 0, 0, 0, 0, 0, 0, []))
        block_data = {"block_hash": "0", "previous_block": "0", "merkle_root": "0", "difficulty": 0,
                      "timestamp": time.time(), "nonce": 0, "tx_set": []}
        block_data_en = json.dumps(block_data)
        #Blockchain._RawBlock.put(bytes([0]), block_data_en)


    #Should be modified

    @classmethod
    def getLatestBlock(cls):
        return cls._BlockChain[0]

    def blockchain(self):
        return self.__class__._BlockChain

    def rawblock(self):
        return self.__class__._RawBlock

    def blockheight(self):
        return self.__class__._BlockHeight

    #Require block fork management methods

