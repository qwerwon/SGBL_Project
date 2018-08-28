import time
import json
from block import Block
import os.path
import plyvel

class Blockchain(object):
    # class variables
    _BlockChain = 0
    _RawBlock = 0
    _BlockHeight = 0
    def initialize(self):
        #Should be revised
        self.__class__._RawBlock = plyvel.DB('./db/RawBlock', create_if_missing=True)
        if(os.path.isdir('./db/RawBlock')==False):
            self.getGenesisblock()
        else:
            #Read from DB and update Blockchain._BlockChain
            pass

    def addBlock(self, newBlock):
        Blockchain._BlockChain.appen(newBlock)

    def getGenesisblock(self):
        self.__class__._BlockChain.append(Block(0, 0, 0, 0, 0, 0, 0, []))
        block_data = {"block_index": 0, "block_hash": "0", "previous_block": "0", "merkle_root": "0", "difficulty": 0,
                      "timestamp": time.time(), "nonce": 0, "tx_set": []}
        block_data_en = json.dumps(block_data)

    def blockchain(self):
        return self.__class__._BlockChain

    def rawblock(self):
        return self.__class__._RawBlock

    def blockheight(self):
        return self.__class__._BlockHeight

    #Require block fork management methods

