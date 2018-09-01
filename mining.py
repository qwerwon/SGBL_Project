from Crypto.Hash import keccak
import time
import json
import base64
from time import sleep
from transaction import Transaction
from key import Key
from blockchain import Blockchain
from block import Block
from utxo import UTXOset, Vout

class Mining(object):
    #class variables
    _MiningFlag = False
    publicKey = 0
    publicKey_ser =0

    #difficulty 조절하려고 이전 6개 블록의 elapsedtime을 저장한다.
    elaped_time_sum = 0
    number_of_blocks =0


    def mineStart(self):
        self.publicKey = Key._publicKey
        self.publicKey_ser = self.publicKey.serialize(compressed=False)

        if(self._MiningFlag):
            return True

        self.flagup()

        while(Mining._MiningFlag):
            
            tx_set = []     #tx_set변수
            
            # coinbase transaction
            tx_set.insert(0, self.generate_coinbase())

            # transaction의 priority는 아직 구현 못함
            # Block에 들어가는 transactino의 최대 크기는 아직 3개로 고정, 수정해야 함

            # DB의 memoryPool에서 가져와야 함
            # tx_set = memoryPool[:3]
            #for i in range(0, len(tx_tmp)):
            #    tx_set[i] = memoryPool.get(tx_tmp[i].encode())
            # 수수료 계산(모든 input의 value - 모든 output의 value)
            # input의 value 구하기 위해서는 UTXOset을 검색해야함(추후에 추가 예졍)
            # for tx in tx_set:

            # 고정된 블록 보상인 12.5BTC만 일단 지급


            merkle_root = Block.create_merkle_root(tx_set)
            previous_block = Blockchain.getLatestBlock().block_hash
            blockData = str(previous_block) + str(merkle_root) + str(Block.difficulty)

            # PoW 호출
            (targetNonce,time) = Mining.proofofwork(blockData, Block.difficulty)


            if (targetNonce == False):
                print('Failed to get golden nonce')
                continue
            else:
                #채굴된 코인 베이스 tx를 가지는 첫 블록을 생성한다.
                tmp_block = Block.candidateblock(targetNonce, tx_set,merkle_root,time)
                #생성된 블록을 블록 체인에 추가합니다.
                Blockchain.addBlock(tmp_block)
                print('successfully mined new block#' + str(Blockchain._BlockHeight))

            # 채굴에 성공하면, 해당 블록에 포함되는transaction memoryPool에서 delete
            #for tx in tx_set:
            #   MemoryPool.delelte(tx.txid)





            #Add to UTXOsets and myUTXOsets
            for tx in tx_set:
                index = 0
                for vout in tx.vout:
                    address = base64.b64encode(vout.lock).decode('utf-8')
                    utxo_data = {"index": index, "address": address, "amount": vout.value}
                    utxo_data_en = json.dumps(utxo_data)
                    UTXOset._UTXOset.put(tx.tx_id, utxo_data_en.encode())
                    if(vout.lock == self.publicKey_ser):
                        UTXOset._myUTXOset.put(tx.tx_id, utxo_data_en.encode())

            # 로그 확인을 위해서 3초 기다림
            sleep(3.0)

    @classmethod
    def flagup(cls):
        cls._MiningFlag = True

    @classmethod
    def flagdown(cls):
        cls._MiningFlag = False

    def miningflag(self):
        return self.__class__._MiningFlag

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
            if (int('0x' + keccak_hash.hexdigest(), 0) < targetValue):

                # 첫블록은 자꾸 경과시간이 0 이뜨더라구요....
                if (Blockchain._BlockHeight < 6):
                    cls.elaped_time_sum = 6
                else:
                    if (cls.number_of_blocks < 7):
                        cls.elaped_time_sum += elaped_time
                        cls.number_of_blocks += 1

                    elif (cls.number_of_blocks == 7):
                        Block.difficulty = int(cls.elaped_time_sum /50 * targetValue)
                        cls.elaped_time_sum = 0
                        cls.number_of_blocks = 0


                print('target nonce :' + str(nonce))
                print('elapsed time: '+ str(elaped_time))
                print('elapsed time of sum: ' + str(cls.elaped_time_sum))

                return (nonce,current_time)
            nonce += 1

        return (False,0)


    def generate_coinbase(self):
        # coinbase transaction 생성
        self.in_num = 0
        self.vin = []
        self.out_num = 1
        self.vout = [Vout(12.5, self.publicKey_ser)]
        SumString = str(self.in_num) + str(self.vin) + str(self.out_num) + str(self.vout)
        keccak_hash = keccak.new(digest_bits=256)
        keccak_hash.update(SumString.encode('ascii'))
        tx_id = keccak_hash.hexdigest().encode()

        return Transaction(tx_id, self.in_num, self.vin, self.out_num, self.vout)

      
    #Method that caculates the vout's values of currenctBlock
    def Caculate_curBlock(cls):
        total_val=0
        for tx in tx_set:
            tx_vout=tx.vout
            for i in range(0,len(tx_vout)):
                total_val+=tx_vout.value
