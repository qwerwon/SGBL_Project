import time
from time import sleep

from Crypto.Hash import keccak

from block import Block
from blockchain import Blockchain
from key import Key
from transaction import Transaction
from utxo import UTXOset


class Mining(object):
    # class variables
    _MiningFlag = False

    def mineStart(self):
        publicKey = Key._publicKey
        publicKey_ser = publicKey.serialize(compressed=False)

        if(self._MiningFlag):
            return True

        self.flagup()

        target_diff = Blockchain().get_difficulty(Blockchain._BlockHeight, Blockchain().getLatestBlock().difficulty)
        while(Mining._MiningFlag):

            candidate_block = Blockchain().set_candidateblock()
            blockData = str(candidate_block.previous_block) + str(candidate_block.merkle_root) + \
                        str(candidate_block.difficulty)
            (targetNonce, time) = Mining.proofofwork(blockData, candidate_block.difficulty)

            if targetNonce == False:
                print('Failed to get golden nonce')
                continue
            else:
                keccak_hash = keccak.new(digest_bits=256)
                blockData = blockData + str(targetNonce)
                keccak_hash.update(blockData.encode('ascii'))
                candidate_block.block_hash = keccak_hash.hexdigest()
                Blockchain.add_block(candidate_block.block_index, candidate_block.block_hash, candidate_block.previous_block,
                                         candidate_block.merkle_root, candidate_block.difficulty, targetNonce, time,
                                         candidate_block.tx_set)
                print('successfully mined new block#' + str(Blockchain._BlockHeight))

            # Delete from MemoryPool
            for tx in Block._CandidateBlock.tx_set:
               Transaction.Pop_MemoryPool(tx.tx_id)

            # Add to UTXOsets and myUTXOsets(for coinbase transaction only)
            coinbase = candidate_block.tx_set[0]
            UTXOset.Insert_UTXO(coinbase.tx_id, 0, coinbase.vout[0].lock, coinbase.vout[0].value)
            UTXOset.Insert_myUTXO(coinbase.tx_id, 0, coinbase.vout[0].lock, coinbase.vout[0].value)

            # Wait for log(will be removed)
            sleep(3.0)

    @classmethod
    def proofofwork(cls, blockData, targetValue):
        nonce = 0
        start = int(time.time())
        while(Mining._MiningFlag):
            keccak_hash = keccak.new(digest_bits=256)
            current_time = time.time()
            SumString = blockData + str(nonce) + str(current_time)
            elaped_time = int(current_time - start)

            keccak_hash.update(SumString.encode(('ascii')))
            if int('0x' + keccak_hash.hexdigest(), 0) < targetValue:
                print('target nonce :' + str(nonce))
                print('elapsed time: '+ str(elaped_time))

                return (nonce,current_time)
            nonce += 1

        return (False,0)


    @classmethod
    def flagup(cls):
        cls._MiningFlag = True

    @classmethod
    def flagdown(cls):
        cls._MiningFlag = False

    @classmethod
    def miningflag(cls):
        return cls._MiningFlag

    #Method that caculates the vout's values of currenctBlock
    def Calculate_curBlock(cls):
        pass
        #total_val=0
        #for tx in tx_set:
        #    tx_vout=tx.vout
        #    for i in range(0,len(tx_vout)):
        #        total_val+=tx_vout.value
