from Crypto.Hash import keccak
import time
from time import sleep
from block import Block
import command

class Mining(Block):
    #class variables
    _MiningFlag = False
    def mineStart(self):
        MiningFlag = Mining.miningflag()
        CandidateBlock = Block.candidateblock()
        publicKey = Key.publickey()
        publicKey_ser = publicKey.serialize(compressed=False)

        while(MiningFlag):


    def mineStop(self):

    def miningflag(self):
        return self.__class__._MiningFlag




tx_tmp=[]


#Block class의 method로 바꿔야 함(수정 요망)
def mining(): #내용 추가
    global miningFlag, privateKey, publicKey
    publicKey_ser = publicKey.serialize(compressed=False)
    while(miningFlag):
        block_index = len(Blockchain)
        previous_block = Blockchain[-1].block_hash
        tx_set = []

        #아직 난이도는 고정값 사용, 지난 6개의 블록을 생성하는데 걸린 시간으로 다시 계산해야 함
        #이유는 모르겠지만 자꾸 keccak_hash(256bit)이 512bit으로 나온다
        difficulty = 0x0fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff

        #transaction의 priority는 아직 구현 못함
        #Block에 들어가는 transactino의 최대 크기는 아직 3개로 고정, 수정해야 함

        #DB의 memoryPool에서 가져와야 함
        #tx_set = memoryPool[:3]
        for i in range(0,len(tx_tmp)):
            tx_set[i]=memoryPool.get(tx_tmp[i].encode())
        #수수료 계산(모든 input의 value - 모든 output의 value)
        #input의 value 구하기 위해서는 UTXOset을 검색해야함(추후에 추가 예졍)
        #for tx in tx_set:

        #고정된 블록 보상인 12.5BTC만 일단 지급

        #coinbase transaction 생성
        in_num = 0
        vin = []
        out_num = 1
        vout = [Vout(12.5, publicKey_ser)]
        SumString = str(in_num) + str(vin) + str(out_num) + str(vout)
        keccak_hash = keccak.new(digest_bits=256)
        keccak_hash.update(SumString.encode('ascii'))
        tx_id = keccak_hash.hexdigest()

        #coinbase transaction
        tx_set.insert(0, Transaction(tx_id, in_num, vin, out_num, vout))


        #Merkle root 생성
        #일단 tree를 만들지 않고, 모든 transaction의 hash를 다시 hash한 값을 merkle root로 간단하게 만듦, 수정 요망
        keccak_hash = keccak.new(digest_bits=256)
        for tx in tx_set:
            keccak_hash.update(tx.tx_id.encode('ascii'))
        merkle_root = keccak_hash.hexdigest()

        blockData = str(previous_block) + str(merkle_root) + str(difficulty)

        #PoW 호출
        targetNonce = proofOfWork(blockData, difficulty)

        if(targetNonce == False):
            print('Failed to get golden nonce')
            continue

        #채굴에 성공하면, 해당 블록에 포함되는transaction과 utxo를 memoryPool과 UTXOset에서 제거한다
        for i in range(0,len(tx_set)-1):
            memoryPool.delete(tx_tmp[i].encode())
        memoryPool.delete(coinbase_txid.encode())
        for i in range(0,len(tx_tmp)):
            tx_tmp.pop()
        #del UTXOset[]
        #del myUTXOset[]

        keccak_hash = keccak.new(digest_bits=256)
        blockData = blockData + str(targetNonce)
        keccak_hash.update(blockData.encode('ascii'))
        block_hash = keccak_hash.hexdigest()
        timestamp = time.time()

        Blockchain.append(Block(block_index, block_hash, previous_block, merkle_root, difficulty, timestamp, targetNonce, tx_set))
        print('successfully mined new block#'+ str(len(Blockchain)))

        #로그 확인을 위해서 3초 기다림
        sleep(3.0)

#수정 요망, 이상하게 코딩함
def proofOfWork(blockData, targetValue):
    global miningFlag
    nonce = 0
    while(miningFlag):
        keccak_hash = keccak.new(digest_bits=256)
        SumString = blockData + str(nonce)
        keccak_hash.update(SumString.encode(('ascii')))
        if(int('0x' + keccak_hash.hexdigest(), 0) < targetValue):
            print('target nonce :'+ str(nonce))
            return nonce
        nonce+=1

    return False

#genesis block 생성, 추후 수정 필요
#파일에서 genesis block을 읽어오는 방향으로 수정(e.g /block/genesis.json)


miningFlag = False
cmd = ""

#임시로 genesis block 생성
#추후 삭제