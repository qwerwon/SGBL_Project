import base64
import time

from Crypto.Hash import keccak

from blkutils import getLatestBlock, get_candidateblock
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

            candidate_block = get_candidateblock()

            blockData = str(candidate_block.previous_block) + \
                        str(candidate_block.merkle_root) + \
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

            # Update UTXOsets and myUTXOsets
            for tx in candidate_block.tx_set:
                # Delete UTXO
                for vin in tx.vin:
                    """
                        type(vin.tx_id)     : string
                        type(UTXO.txOutid)  : bytes
                        string to bytes conversion required
                        tx_id_byte = base64.b64decode(vin.tx_id)
                    """
                    tx_id_byte = base64.b64decode(vin.tx_id)
                    result = UTXOset.get_myUTXO(tx_id_byte, vin.index)
                    UTXOset.Pop_UTXO(tx_id_byte, vin.index)

                    if result != False:
                        UTXOset.Pop_myUTXO(tx_id_byte, vin.index)

                # Add UTXO
                index = 0
                for vout in tx.vout:
                    """
                        type(vout.lock)     : bytes
                        type(UTXO.address)  : string
                        bytes to string conversion required
                        address = base64.b64encode(vout.lock).decode('utf-8')
                    """
                    address = base64.b64encode(vout.lock).decode('utf-8')
                    UTXOset.Insert_UTXO(tx.tx_id, index, address, vout.value)
                    if vout.lock == publicKey_ser:
                        UTXOset.Insert_myUTXO(tx.tx_id, index, address, vout.value)
                    index += 1

            # Delete from MemoryPool
            for tx in candidate_block.tx_set:
                Transaction.Pop_MemoryPool(tx.tx_id)

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

