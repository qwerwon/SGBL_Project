#pip install Flask
from flask import Flask

#pip install ecdsa
from ecdsa import SigningKey, VerifyingKey, SECP256k1

#pip install pycryptodome
from Crypto.Hash import keccak

import binascii
import threading
import time
from time import sleep

#Block
# Blockchain : 가장 최근의 10개 블록 리스트
Blockchain = []
class Block:
    def __init__(self, block_index, block_hash, previous_block, merkle_root, difficulty, timestamp, nonce, tx_set):
        self.block_index = block_index
        self.block_hash = block_hash
        self.previous_block = previous_block
        self.merkle_root = merkle_root
        self.difficluty = difficulty
        self.timestamp = timestamp
        self.nonce = nonce
        self.tx_set = tx_set

    def isValid(self):

        #Check if block_hash is valid
        SumString = ""
        SumString = SumString + str(self.previous_block) + str(self.merkle_root) + str(self.difficluty) + str(self.nonce)
        keccak_hash = keccak.new(digest_bits=256)
        keccak_hash.update(SumString.encode('ascii'))
        if (str(keccak_hash) != self.block_hash):
            return False

        #Check if difficulty is valid(난이도 계산식과 일치하는지 확인, 미구현)

        #Check if block_hash is less than difficulty
        if(int(self.block_hash) >= self.difficluty):
            return False

        #Check if is generated within 2-hours
        if(self.timestamp + 72000 < time.time()):
            return False

        #Check if block height is right(Orphan block, 미구현)

#input / output
class Vin:
    def __init__(self, tx_id, index, unlock):
        self.tx_id = tx_id
        self.index = index
        self.unlock = unlock
class Vout:
    def __init__(self, value, lock):
        self.value = value
        self.lock = lock

#Transaction
# memoryPool : 아직 블록에 포함되지 않은 트랜잭션 리스트
memoryPool = []
# orphanPool : input중에 부모 output이 존재하지않는 트랜잭션 리스트
orphanPool = []
class Transaction:
    def __init__(self, tx_id, in_num, vin, out_num, vout):
        self.tx_id = tx_id
        self.in_num = in_num
        self.vin = vin
        self.out_num = out_num
        self.vout = vout
        memoryPool.append(self)

    #CLI로부터 transaction 생성 명령을 받았을 때(받는 사람, 보내는 양, 수수료 입력)
    def generate(self, receiver, amount, commission):
        global publicKey, privateKey
        #DB로부터 myUTXOset 가져와야 함
        sum = 0
        tx_id = ""
        in_counter = 0
        out_counter = 0
        vin = []
        vout = []
        tmpUTXO = []
        SumString = ""

        #Gathering from myUTXOset
        for output in myUTXOset :
            if(output.lock != publicKey):
                #myUTXOset과 DB로부터 output 제거해야함
                continue
            tmpUTXO.append(output)
            if(sum > amount+commission):
                break

        #Insufficient balance
        if(sum < amount+commission):
            print('Not enough BTC balance')
            return False

        #Generating input and output

        for output in tmpUTXO:
            sum += output.value
            in_counter += 1
            # 자신의 개인키로 서명한 unlock 생성
            vin.append(Vin(output.txOutid, output.index, privateKey.sign(output.txOutid + str(output.index))))
            # myUTXOset과 DB로부터 output 제거해야함
            myUTXOset.pop(output)
        vout.append(Vout(amount, receiver))
        change = sum - commission - amount
        vout.append(Vout(change, publicKey))

        #Generating tx_id
        SumString = SumString + str(in_counter)
        for input in vin:
           SumString = SumString + str(input.tx_id) + str(input.index) + str(input.unlock)
        SumString = SumString + str(out_counter)
        for output in vout:
           SumString = SumString + str(output.tx_id) + str(output.index) + str(output.unlock)
        keccak_hash = keccak.new(digest_bits=256)
        keccak_hash.update(SumString.encode('ascii')) #keccak_hash == tx_id of current transaction

        #Add to UTXOset and myUTXOset
        UTXOset.append(UTXO(str(keccak_hash), 0, receiver, amount))
        UTXOset.append(UTXO(str(keccak_hash), 1, publicKey, change))
        myUTXOset.append(UTXO(str(keccak_hash), 1, publicKey, change))

        #Add to memoryPool
        Transaction(str(keccak_hash), in_counter, vin, out_counter, vout)

        return True

    def isValid(self):
        SumString = ""
        for output in self.vout:
            if(output.value < 0):
                return False

        #Check if tx_id is valid
        SumString = SumString + str(self.in_num)
        for input in self.vin:
            SumString = SumString + str(input.tx_id) + str(input.index) + str(input.unlock)
        SumString = SumString + str(self.out_num)
        for output in self.vout:
            SumString = SumString + str(output.tx_id) + str(output.index) + str(output.unlock)
        keccak_hash = keccak.new(digest_bits=256)
        keccak_hash.update(SumString.encode('ascii'))  # keccak_hash == tx_id of current transaction
        if(str(keccak_hash) != self.tx_id):
            return False

        outSum = 0
        inSum = 0
        for output in self.vout:
            outSum += output.value
        if(outSum < 0 or outSum > 21000000):
            return False

        #Check if inputs are valid
        for input in self.vin:
            #DB에서 검색하는 방식으로 바뀌어야 함

            #Block이나 UTXOset에 있는지 확인(혹은 memoryPool)

            #해당 input의 unlock sign을 대응하는 output의 lock으로 복호화 가능한지 확인
            #publicKey.verify(sig)

            #일단 index가 음수인지만 확인
            if(input.index < 0):
                return False

        #Check if sum of input values are less than sum of outputs
        #UTXO에서 합을 계산해야 가능

        #Cehck if double-spended in memoryPool
        #DB 구현후에 구현할 예정

        return True

#UTXO
# UTXOset : 전체 UTXO
UTXOset = []
# myUTXOset : 내 지갑의 UTXO
myUTXOset = []
class UTXO:
    def __init__(self, txOutid, index, address, amount):
        self.txOutid = txOutid
        self.index = index
        self.address = address
        self.amount = amount

#Block class의 method로 바꿔야 함(수정 요망)
def mining(): #내용 추가
    global miningFlag
    while(miningFlag):
        block_index = len(Blockchain)+1
        previous_block = Blockchain[-1].block_hash

        #아직 난이도는 고정값 사용, 지난 6개의 블록을 생성하는데 걸린 시간으로 다시 계산해야 함
        difficulty = 0x0fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff

        #transaction의 priority는 아직 구현 못함
        #Block에 들어가는 transactino의 최대 크기는 아직 4개로 고정, 수정해야 함
        #DB의 memoryPool에서 가져와야 함
        tx_set = memoryPool[:4]

        #Merkle root 생성
        #일단 tree를 만들지 않고, 모든 transaction의 hash를 다시 hash한 값을 merkle root로 간단하게 만듦, 수정 요망
        keccak_hash = keccak.new(digest_bits=256)
        for tx in tx_set:
            keccak_hash.update(tx.tx_id.encode('ascii'))
        merkle_root = str(keccak_hash)

        blockData = str(previous_block) + str(merkle_root) + str(difficulty)

        #PoW 호출
        targetNonce = proofOfWork(blockData, difficulty)
        keccak_hash = keccak.new(digest_bits=256)
        keccak_hash.update(blockData.encode('ascii'))
        keccak_hash.update(bytes(targetNonce))
        block_hash = str(keccak_hash)
        timestamp = time.time()

        Blockchain.append(Block(len(Blockchain), block_hash, previous_block, merkle_root, difficulty, timestamp, targetNonce, tx_set))
        print('successfully mined new block#'+ str(len(Blockchain)))

        #로그 확인을 위해서 2초 기다림
        sleep(2.0)

#수정 요망, 이상하게 코딩함
def proofOfWork(blockData, targetValue):
    global miningFlag
    nonce = 0
    while(miningFlag):
        keccak_hash = keccak.new(digest_bits=256)
        keccak_hash.update(blockData.encode(('ascii')))
        keccak_hash.update(bytes(nonce))
        if(int('0x'+keccak_hash.hexdigest(), 0) < targetValue):
            print('target nonce :'+ str(nonce))
            return nonce
        nonce+=1

#genesis block 생성, 추후 수정 필요
#파일에서 genesis block을 읽어오는 방향으로 수정(e.g /block/genesis.json)
def getGenesisBlock():
    Blockchain.append(Block(0,0,0,0,0,0,0,[]))

miningFlag = False
cmd = ""

#웹소켓(혹은 다른 방식으로)으로 연결된 노드들에게 transaction과 block 주고받아야 함


#주소 및 개인키 생성 구현해야함(아직 랜덤 주소생성만 가능)
#https://stackoverflow.com/questions/34451214/how-to-sign-and-verify-signature-with-ecdsa-in-python
#https://pycryptodome.readthedocs.io/en/latest/src/examples.html 참고하여 다시 바꾸기

privateKey = SigningKey.generate(curve=SECP256k1)
publicKey = privateKey.get_verifying_key()

#임시로 genesis block 생성
#추후 삭제
getGenesisBlock()

while(cmd != 'exit'):
    cmd = input('>>')
    if(cmd == 'help'):
        print('Command List:\n\tmine.start : start mining work\n\tmine.stop : stop mining work\n\tnewTransaction : generate new transaction\n\tgetBlock : print main blockchain stream\n')
    elif(cmd == 'mine.start'):
        #마이닝 thread 생성
        if(miningFlag==True):
            continue
        print('Mining work starts')
        miningFlag = True
        miningThread= threading.Thread(target=mining)
        miningThread.start()

    elif(cmd == 'mine.stop'):
        mininFlag = False
        print('Mining work stops')

    elif(cmd == 'newTransaction'):
        sender = input('Address of receiver : ')
        amount = input('BTC : ')
        commission = input('Commission : ')

    elif(cmd == 'getBlock'):
        #Blockchain 출력
        #아직 구현안함
        print('block....')