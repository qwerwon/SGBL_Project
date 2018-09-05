import base64
import time

from Crypto.Hash import keccak

from blkutils import get_difficulty, getLatestBlock, get_candidateblock, Block_Validation
from block import Block
from key import Key
from transaction import Transaction
from utxo import UTXOset


# Class for Mining
class Mining(object):

    # class variables
    _MiningFlag = False

    # Function for mining start
    @classmethod
    def mineStart(cls):

        publicKey = Key._publicKey
        publicKey_ser = publicKey.serialize(compressed=False)

        if(cls._MiningFlag):
            return True

        cls.flagup()

        # Mining start
        while Mining._MiningFlag:

            previous_block = getLatestBlock()
            target_diff = get_difficulty(Block._BlockHeight,
                                         getLatestBlock().difficulty)

            print('target difficulty :', target_diff)

            candidate_block = get_candidateblock()
            #print(candidate_block.block_index, candidate_block.block_hash, candidate_block.previous_block, candidate_block.merkle_root,
            #      candidate_block.difficulty)

            blockData = str(candidate_block.previous_block) + \
                        str(candidate_block.merkle_root) + \
                        str(target_diff)

            (targetNonce, time) = Mining.proofofwork(blockData, target_diff)

            if targetNonce == False:
                print('Failed to get golden nonce')
                continue
            else:
                keccak_hash = keccak.new(digest_bits=256)
                blockData = blockData + str(targetNonce)
                keccak_hash.update(blockData.encode('ascii'))

                candidate_block.block_hash = keccak_hash.hexdigest()
                candidate_block.difficulty = target_diff
                candidate_block.nonce = targetNonce
                candidate_block.timestamp = time

                # Add to RawBlock and _Blockchain
                Block.Insert_RawBlock(candidate_block.block_index,
                                      candidate_block.block_hash,
                                      candidate_block.previous_block,
                                      candidate_block.merkle_root,
                                      candidate_block.difficulty,
                                      candidate_block.timestamp,
                                      candidate_block.nonce,
                                      candidate_block.tx_set)

                Block.insert_blockchain(candidate_block.block_index,
                                        candidate_block.block_hash,
                                        candidate_block.previous_block,
                                        candidate_block.merkle_root,
                                        candidate_block.difficulty,
                                        candidate_block.timestamp,
                                        candidate_block.nonce,
                                        candidate_block.tx_set)

                print('successfully mined new block#' + str(Block._BlockHeight))
                if candidate_block.block_index != 0:
                    is_valid_flag = Block_Validation(candidate_block.block_index,
                                        candidate_block.block_hash,
                                        candidate_block.previous_block,
                                        candidate_block.merkle_root,
                                        candidate_block.difficulty,
                                        candidate_block.timestamp,
                                        candidate_block.nonce,
                                        candidate_block.tx_set,
                                        previous_block.difficulty)
                    if is_valid_flag == True :
                        print("True")
                    if is_valid_flag == False :
                        print("False")

            # Add to UTXOsets and myUTXOsets(for coinbase transaction only)
            coinbase = candidate_block.tx_set[0]
            coinbase_data = coinbase.vout[0]
            coinbase_tx_id = coinbase.tx_id

            UTXOset.Insert_UTXO(coinbase_tx_id,
                                0,
                                coinbase_data.lock,
                                coinbase_data.value)

            UTXOset.Insert_myUTXO(coinbase_tx_id,
                                  0,
                                  coinbase_data.lock,
                                  coinbase_data.value)

            # Delete from MemoryPool
            for tx in candidate_block.tx_set:
               Transaction.Pop_MemoryPool(base64.b64decode(tx.tx_id))



    # Proof of work
    """
    parameter: blockData, targetValue
    return: nonce, current_time
    """

    @classmethod
    def proofofwork(cls, blockData, targetValue):

        nonce = 0
        start = int(time.time())

        while(Mining._MiningFlag):

            keccak_hash = keccak.new(digest_bits=256)
            current_time = int(time.time())

            SumString = blockData + str(nonce) + str(current_time)
            elaped_time = int(current_time - start)

            keccak_hash.update(SumString.encode(('ascii')))

            if int('0x' + keccak_hash.hexdigest(), 0) < targetValue:
                print('target nonce :' + str(nonce))
                print('elapsed time: '+ str(elaped_time))

                return (nonce, current_time)

            nonce += 1

        return (False,0)

    # Flag value management
    @classmethod
    def flagup(cls):
        cls._MiningFlag = True

    @classmethod
    def flagdown(cls):
        cls._MiningFlag = False

    @classmethod
    def miningflag(cls):
        return cls._MiningFlag

