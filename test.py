#pip install Flask
from flask import Flask

#pip install ecdsa
from ecdsa import SigningKey, VerifyingKey, SECP256k1

#pip install pycryptodome
from Crypto.Hash import keccak

#pip install secp256k1prp
from secp256k1prp import PrivateKey, PublicKey

import binascii
import threading
import time
from time import sleep

#Block
# Blockchain : 가장 최근의 10개 블록 리스트
Blockchain = []
class Block:
    def __init__(self, block_index, block_hash, previous_block, merkle_root, difficulty, timestamp, nonce, tx_set):
        self.block_index = block_index          #int
        self.block_hash = block_hash            #string
        self.previous_block = previous_block    #string
        self.merkle_root = merkle_root          #string
        self.difficluty = difficulty            #int
        self.timestamp = timestamp              #float
        self.nonce = nonce                      #int
        self.tx_set = tx_set                    #list[Transaction]

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
        self.tx_id = tx_id                      #string
        self.index = index                      #int
        self.unlock = unlock                    #class '_cffi_backend.CDataOwn'
class Vout:
    def __init__(self, value, lock):
        self.value = value                      #float
        self.lock = lock                        #class 'secp256k1prp.PublicKey'

#Transaction
# memoryPool : 아직 블록에 포함되지 않은 트랜잭션 리스트
memoryPool = []
# orphanPool : input중에 부모 output이 존재하지않는 트랜잭션 리스트
orphanPool = []
class Transaction:
    def __init__(self, tx_id, in_num, vin, out_num, vout):
        self.tx_id = tx_id                      #string
        self.in_num = in_num                    #int
        self.vin = vin                          #list[Vin]
        self.out_num = out_num                  #int
        self.vout = vout                        #list[Vout]
        memoryPool.append(self)

    #CLI로부터 transaction 생성 명령을 받았을 때(받는 사람, 보내는 양, 수수료 입력)
    def generate(self, receiver, amount, commission):
        #공개키 / 개인키 다시 구현
        global privateKey, publicKey


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
            # 공개키 / 개인키 다시 구현
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

            # 공개키 / 개인키 다시 구현
            vin.append(Vin(output.txOutid, output.index, privateKey.ecdsa_sign(bytes(bytearray.fromhex(output.txOutid), raw=False))))

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
        self.txOutid = txOutid                  #string
        self.index = index                      #int
        self.address = address                  #class 'secp256k1prp.PublicKey'
        self.amount = amount                    #float

#Block class의 method로 바꿔야 함(수정 요망)
def mining(): #내용 추가
    global miningFlag, privateKey, publicKey
    while(miningFlag):
        block_index = len(Blockchain)+1
        previous_block = Blockchain[-1].block_hash
        tx_set = []

        #아직 난이도는 고정값 사용, 지난 6개의 블록을 생성하는데 걸린 시간으로 다시 계산해야 함
        #이유는 모르겠지만 자꾸 keccak_hash(256bit)이 512bit으로 나온다
        difficulty = 0x0fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff

        #transaction의 priority는 아직 구현 못함
        #Block에 들어가는 transactino의 최대 크기는 아직 3개로 고정, 수정해야 함

        #DB의 memoryPool에서 가져와야 함
        tx_set = memoryPool[:3]

        #수수료 계산(모든 input의 value - 모든 output의 value)
        #input의 value 구하기 위해서는 UTXOset을 검색해야함(추후에 추가 예졍)
        #for tx in tx_set:

        #고정된 블록 보상인 12.5BTC만 일단 지급

        #coinbase transaction 생성
        in_num = 0
        vin = []
        out_num = 1
        vout = [Vout(12.5, publicKey)]
        SumString = str(in_num) + str(vin) + str(out_num) + str(vout)
        keccak_hash = keccak.new(digest_bits=256)
        keccak_hash.update(SumString.encode('ascii'))
        tx_id = str(keccak_hash)

        tx_set.insert(0, Transaction(tx_id, in_num, vin, out_num, vout))


        #Merkle root 생성
        #일단 tree를 만들지 않고, 모든 transaction의 hash를 다시 hash한 값을 merkle root로 간단하게 만듦, 수정 요망
        keccak_hash = keccak.new(digest_bits=256)
        for tx in tx_set:
            keccak_hash.update(tx.tx_id.encode('ascii'))
        merkle_root = str(keccak_hash)

        blockData = str(previous_block) + str(merkle_root) + str(difficulty)

        #PoW 호출
        targetNonce = proofOfWork(blockData, difficulty)

        if(targetNonce == False):
            print('Failed to get golden nonce')
            continue

        #채굴에 성공하면, 해당 블록에 포함되는transaction과 utxo를 memoryPool과 UTXOset에서 제거한다
        del memoryPool[:len(tx_set)]
        #del UTXOset[]
        #del myUTXOset[]

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
        if(int('0x' + keccak_hash.hexdigest(), 0) < targetValue):
            print('target nonce :'+ str(nonce))
            return nonce
        nonce+=1
    return False

#genesis block 생성, 추후 수정 필요
#파일에서 genesis block을 읽어오는 방향으로 수정(e.g /block/genesis.json)
def getGenesisBlock():
    Blockchain.append(Block(0,0,0,0,0,0,0,[]))

miningFlag = False
cmd = ""

#웹소켓(혹은 다른 방식으로)으로 연결된 노드들에게 transaction과 block 주고받아야 함

#임시로 genesis block 생성
#추후 삭제
getGenesisBlock()

#private / public key 생성
#https://github.com/ludbb/secp256k1-py
passphrase = input('Enter your passphrase for private key : ')
keccak_hash = keccak.new(digest_bits=256)
keccak_hash.update(passphrase.encode('ascii'))
passphrase = keccak_hash.hexdigest()
privateKey = PrivateKey(bytes(bytearray.fromhex(passphrase)), raw=True)
publicKey = privateKey.pubkey

print('My public key :')
print(bytes(bytearray(privateKey.pubkey.serialize(compressed=False))).hex())
print('My private key :')
print(bytes(bytearray(privateKey.private_key)).hex())

newPubkey = PrivateKey.pubkey()

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
        miningFlag = False
        print('Mining work stops')

    elif(cmd == 'newTransaction'):
        receiver = input('Address of receiver : ')
        #receiver의 주소에 대응하는 'secp256k1prp.PublicKey' "오브젝트"를 넘겨야함
        #밑의 코드 참조
        # def _update_public_key(self):
        #public_key = self._gen_public_key(self.private_key)
        #self.pubkey = PublicKey(
        #    public_key, raw=False, ctx=self.ctx, flags=self.flags)

        amount = int(input('BTC : '))
        commission = int(input('Commission : '))
        Transaction(0, 0, [], 0, []).generate(receiver, amount, commission)

    elif(cmd == 'getBlock'):
        #Blockchain 출력
        #아직 구현안함
        print('block....')