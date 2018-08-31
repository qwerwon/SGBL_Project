
from Crypto.Hash import keccak
import time


#Blockchain = []


class Block(object):
    # class variables
    _CandidateBlock = 0
    # 아직 난이도는 고정값 사용, 지난 6개의 블록을 생성하는데 걸린 시간으로 다시 계산해야 함
    # 이유는 모르겠지만 자꾸 keccak_hash(256bit)이 512bit으로 나온다
    difficulty = 0x0fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff  # int

    def __init__(self, block_index, block_hash, previous_block, merkle_root, difficulty, timestamp, nonce, tx_set):
        self.block_index = block_index  # int
        self.block_hash = block_hash  # string
        self.previous_block = previous_block  # string
        self.merkle_root = merkle_root  # string
        self.difficulty = difficulty
        self.timestamp = timestamp  # float
        self.nonce = nonce  # int
        self.tx_set = tx_set  # list[Transaction]
        self.blockData = str(self.previous_block) + str(self.merkle_root) + str(self.difficulty)


    def isValid(self):

        # Check if block_hash is valid
        SumString = str(self.previous_block) + str(self.merkle_root) + str(self.difficluty) + str(self.nonce)
        keccak_hash = keccak.new(digest_bits=256)
        keccak_hash.update(SumString.encode('ascii'))
        if (keccak_hash.hexdigest() != self.block_hash):
            return False

        # Check if difficulty is valid(난이도 계산식과 일치하는지 확인, 미구현)

        # Check if block_hash is less than difficulty
        if (int('0x' + self.block_hash, 0) >= self.difficluty):
            return False

        # Check if is generated within 2-hours
        if (self.timestamp + 72000 < time.time()):
            return False

        # Check if block height is right(Orphan block, 미구현)

        # Check if all transactions in tx_set are valid(미구현, Transaction.isvalid() 호출하면 끗)

    @classmethod
    def candidateblock(cls,targetnonce,tx_set,merkle_root):

        # warning for poinint class var
        from blockchain import Blockchain
        block_index = Blockchain._BlockHeight
        previous_block = Blockchain.getLatestBlock().block_hash
        tx_set = tx_set

        blockData = str(previous_block) + str(merkle_root) + str(cls.difficulty)

        keccak_hash = keccak.new(digest_bits=256)
        blockData = blockData + str(targetnonce)
        keccak_hash.update(blockData.encode('ascii'))
        block_hash = keccak_hash.hexdigest()
        timestamp = time.time()

        cls.CandidateBlock =  Block(block_index, block_hash,previous_block, merkle_root, cls.difficulty, timestamp, targetnonce, tx_set)

        return cls._CandidateBlock

    @classmethod
    def create_merkle_root(self,tx_set):
        self.tx_set = tx_set
        # Merkle root 생성
        # 일단 tree를 만들지 않고, 모든 transaction의 hash를 다시 hash한 값을 merkle root로 간단하게 만듦, 수정 요망
        keccak_hash = keccak.new(digest_bits=256)
        for tx in self.tx_set:
            keccak_hash.update(tx.tx_id)
        merkle_root = keccak_hash.hexdigest()

        return merkle_root

