import base64
import json
import plyvel
from Crypto.Hash import keccak
from key import Key
from utxo import UTXOset, Vout, Vin, UTXO


class Transaction(object):
    # class variables
    _MemoryPool = 0

    def __init__(self, tx_id, in_num, vin, out_num, vout):
        self.tx_id = tx_id          # bytes : key
        self.in_num = in_num        # int
        self.vin = vin              # list[Vin]
        self.out_num = out_num      # int
        self.vout = vout            # list[Vout]

    @classmethod
    def initialize(cls):
        cls._MemoryPool = plyvel.DB('./db/MemoryPool/', create_if_missing=True)

    # CLI로부터 transaction 생성 명령을 받았을 때(받는 사람, 보내는 양, 수수료 입력)
    def generate(self, receiver, amount, commission):
        publicKey = Key._publicKey
        privateKey = Key._privateKey

        publicKey_ser = publicKey.serialize(compressed=False)

        # DB로부터 myUTXOset 가져와야 함
        total = 0
        in_counter = 0
        out_counter = 0
        vin = []
        vout = []
        tmpUTXO = []  # Temporary UTXOset for resulting transaction

        # Check if balance is sufficient
        for key, value in UTXOset._myUTXOset.iterator():
            d_value = json.loads(value)

            lock_ser = base64.b64decode(d_value["address"])
            if (lock_ser != publicKey_ser):
                UTXOset.Pop_myUTXO(key)
                continue
            tmpUTXO.append(UTXO(key, d_value["index"], d_value["address"], d_value["amount"]))
            total += d_value["amount"]
            if (total > amount + commission):
                break

        # Insufficient balance
        if (total < amount + commission):
            print('Insufficient BTC balance')
            return False

        # Generating input and output
        for output in tmpUTXO:
            total += output.amount
            in_counter += 1
            # 자신의 개인키로 서명한 unlock 생성

            unlockSig = privateKey.ecdsa_sign(output.txOutid, raw=False)
            unlock = privateKey.ecdsa_serialize(unlockSig)
            vin.append(Vin(output.txOutid, output.index, unlock))

            # myUTXOset과 DB로부터 output 제거해야함
            UTXOset.Pop_UTXO(output.txOutid)
            UTXOset.Pop_myUTXO(output.txOutid)


        vout.append(Vout(amount, receiver))
        change = total - commission - amount
        if (change > 0):
            vout.append(Vout(change, publicKey_ser))

        # Generating tx_id
        Sumstring=str(in_counter)
        for input in vin:
            SumString = SumString + str(input.tx_id) + str(input.index) + str(input.unlock)
        SumString = SumString + str(out_counter)
        for output in vout:
            SumString = SumString + str(output.value) + str(output.lock)
        keccak_hash = keccak.new(digest_bits=256)
        keccak_hash.update(SumString.encode('ascii'))  # keccak_hash == tx_id of current transaction

        # Add to UTXOset and myUTXOset
        address = base64.b64encode(receiver).decode('utf-8')
        UTXOset.Insert_UTXO(keccak_hash.hexdigest(),index,address,amount)

        if (change > 0):
            address = base64.b64encode(publicKey_ser).decode('utf-8')
            UTXOset.Insert_UTXO(keccak_hash.hexdigest(),index,address,amount)
            UTXOset.Insert_myUTXO(keccak_hash.hexdigest(),index,address,amount)
       
       # Add to memoryPool
        Transaction.Insert_MemoryPool(self,keccak_hash.hexdigest(),in_counter,vin,out_counter,vout)

        return True

    def isValid(self):

        for output in self.vout:
            if (output.value < 0):
                print("Negative output value")
                return False

        # Check if tx_id is valid
        SumString = str(self.in_num)
        for input in self.vin:
            SumString = SumString + str(input.tx_id) + str(input.index) + str(input.unlock)
        SumString = SumString + str(self.out_num)
        for output in self.vout:
            SumString = SumString + str(output.value) + str(output.lock)
        keccak_hash = keccak.new(digest_bits=256)
        keccak_hash.update(SumString.encode('ascii'))  # keccak_hash == tx_id of current transaction
        if (keccak_hash.hexdigest().encode() != self.tx_id):
            print("Hash does not match")
            return False

        outSum = 0
        inSum = 0
        for output in self.vout:
            outSum += output.value
        if (outSum < 0 or outSum > 21000000):
            print("Sum of output is out of range")
            return False

        # Check if inputs are valid
        for input in self.vin:

            # Block이나 UTXOset에 있는지 확인(혹은 memoryPool)
            tmp = UTXOset._UTXOset.get(input.tx_id, default=False)
            if (tmp == False or json.loads(tmp)["index"] != input.index):
                print("Does not exist in UTXOset")
                return False

            # 해당 input의 unlock sign을 대응하는 output의 lock으로 복호화 가능한지 확인
            # sig_des = PrivateKey().ecdsa_deserialize(input.unlock)
            # Search rawBlock and transaction pool that match with input.txid and input.index
            # verify = vout.lock.ecdsa_verify(bytes(bytearray.fromhex(txOutid)),sig_des)

            # index가 음수인지만 확인
            if (input.index < 0):
                return False

        # Check if sum of input values are less than sum of outputs

        # Cehck if double-spended in memoryPool
        # DB 구현후에 구현할 예정

        print("Valid transaction")
        return True
    
    
    def Insert_MemoryPool(self,tx_id,in_counter,vin,out_counter,vout):
        newVin=[]
        newVout=[]

        for vin_el in vin:
            newVin.append(json.dumps(vin_el.__dict__))
        for vout_el in vout:
            newVout.append(json.dumps(vout_el.__dict__))
        mempool={"tx_id": str(tx_id), "in_num": str(in_counter),"vin": json.dumps(newVin),"out_num": str(out_counter),"vout": json.dumps(newVout)}
        mempool_en=json.dumps(mempool)
        Transaction._MemooryPool.put(str(tx_id).encode(),mempool_en.encode())
    
    def Pop_MemoryPool(self,tx_id):
        
        MemoryPool.delete(str(tx_id).encode(),sync=True)


    #using vin's tx_id, find this transaction and add all the values of its vout

    def Calculate_mem(self,tx_id):
        total_val=0
        if MemoryPool._MemoryPool.get(str(tx_id).encode() ,default=None) is None:
            return 0
        else:
            tmptx_Data=json.loads(_MemoryPool.get(str(tx_id).encode()),default=None)
            tmpvout=json.loads(tmptx_Data["vout"])
            for i in range(0,len(tmpvout)):
                tmpvout_el=json.loads(tmpvout[i])
                total_val+=float(tmpvout_el["value"])
            return total_val




