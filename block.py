from Crypto.Hash import keccak
import time

Blockchain = []
class Block(object):
    #class variables
    _CandidataBlock = 0
    def __init__(self, block_index, block_hash, previous_block, merkle_root, difficulty, timestamp, nonce, tx_set):
        self.block_index = block_index          # int
        self.block_hash = block_hash            # string
        self.previous_block = previous_block    # string
        self.merkle_root = merkle_root          # string
        self.difficluty = difficulty            # int
        self.timestamp = timestamp              # float
        self.nonce = nonce                      # int
        self.tx_set = tx_set                    # list[Transaction]

    def isValid(self):

        #Check if block_hash is valid
        SumString = str(self.previous_block) + str(self.merkle_root) + str(self.difficluty) + str(self.nonce)
        keccak_hash = keccak.new(digest_bits=256)
        keccak_hash.update(SumString.encode('ascii'))
        if (keccak_hash.hexdigest() != self.block_hash):
            return False

        #Check if difficulty is valid(난이도 계산식과 일치하는지 확인, 미구현)

        #Check if block_hash is less than difficulty
        if(int('0x' + self.block_hash, 0) >= self.difficluty):
            return False

        #Check if is generated within 2-hours
        if(self.timestamp + 72000 < time.time()):
            return False

        #Check if block height is right(Orphan block, 미구현)

        #Check if all transactions in tx_set are valid(미구현, Transaction.isvalid() 호출하면 끗)

    def candidateblock(self):
        return self.__class__._CandidataBlock