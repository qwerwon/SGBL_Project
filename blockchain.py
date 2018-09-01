import json
import time

import plyvel

from block import Block


class Blockchain(object):
    # class variables
    _BlockChain = []
    _RawBlock = 0
    _BlockHeight = 0

    @classmethod
    def initialize(cls):
        _tmpBlockheight=0
        try:
            cls._RawBlock = plyvel.DB('./db/RawBlock/', create_if_missing=True,error_if_exists=False)
        except:
            
            cls._RawBlock = plyvel.DB('./db/RawBlock/', create_if_missing=True)
            for key, value in _RawBlock:
                _tmpBlockheight+=1
           
            if _tmpBlockheight >= 10:
                _tmpblockstart =_tmpBlockheight-10
            else:
                _tmpblockstart = 0

            for i in range(_tmpblockstart,_tmpBlockheight):
                _BlockChain.append(json.loads(_RawBlock.get(str(i).encode())))
            
            cls._BlockHeight = _tmpBlockheight 

        else:
            Blockchain.getGenesisblock()
            cls._BlockHeight = 1


            #update in _blockchain memory --10!! 


        # else:
            # Read from DB and update Blockchain._BlockChain
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
        # Blockchain._RawBlock.put(bytes([0]), block_data_en)


    # Should be modified

    @classmethod
    def getLatestBlock(cls):
        return cls._BlockChain[0]

    def blockchain(self):
        return self.__class__._BlockChain

    def rawblock(self):
        return self.__class__._RawBlock

    def blockheight(self):
        return self.__class__._BlockHeight
   
    def insert_RawBlock(self,index,block_hash,previous_block,merkle_root,difficulty,timestamp,nonce,tx_set):
        block_data={"index": str(index) , "block_hash": str(block_hash),"previous_block":str(previous_block),"merkle_root": str(merkle_root),"difficulty":str(difficulty),"timestamp":str(timestamp),"nonce":str(nonce),"tx_set":json.dumps(tx_set.__dict__)}
        block_data_en=json.dumps(block_data)
        Blockchain._RawBlock.put(str(index).encode(),block_data_en.encode())
    
    def Pop_RawBlock(self,index):
        
        Blockchain.RawBlock.delete(str(index).encode())

    
    #Method that calculates the vout's values
    def Calculate_block(self,tx_id,index):

        # if there is no key-value data in db
        if _RawBlock.get(str(index).encode(),default=None) is None:
            return 0
        #if there is key-value data in db
        else:
            total_val=0
            tmpbl_Data=json.loads(_RawBlock.get(str(index).encode()),default=None)
            tmptx_set=json.loads(tmpbl_Data["tx_set"])
            for i in range(0,len(tmptx_set)):
                tmptx_set_el=json.loads(tmptx_set[i])
                if tmptx_set_el.tx_id == tx_id:
                    tmptx_vout=tmptx_set_el.vout
                    break
            for i in range(0,len(tmptx_vout)):
                total_val += tmptx_vout.value
            return total_val


                





    #Require block fork management methods

