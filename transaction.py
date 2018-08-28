import json
import base64
import plyvel
from Crypto.Hash import keccak
from secp256k1prp import PublicKey, PrivateKey
from blockchain import Blockchain
from utxo import UTXOset, Vout, Vin, UTXO
from key import Key

class Transaction(object):
    #class variables
    _MemoryPool = 0
    def __init__(self, tx_id, in_num, vin, out_num, vout):
        self.tx_id = tx_id                      # bytes : key
        self.in_num = in_num                    # int
        self.vin = vin                          # list[Vin]
        self.out_num = out_num                  # int
        self.vout = vout                        # list[Vout]

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
        for key, value in UTXOset._UTXOset.iterator():
            d_value = json.loads(value)

            # Debugging
            print('d_value is:')
            print(d_value)

            lock_ser = base64.b64decode(d_value["address"])
            if (lock_ser != publicKey_ser):
                UTXOset._myUTXOset_db.delete(key)
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
            UTXOset._myUTXOset.delete(output.txOutid, sync=True)
            UTXOset._UTXOset.delete(output.txOutid, sync=True)

        vout.append(Vout(amount, receiver))
        change = total - commission - amount
        if(change > 0):
            vout.append(Vout(change, publicKey_ser))

        # Generating tx_id
        SumString = str(in_counter)
        for input in vin:
            SumString = SumString + str(input.tx_id) + str(input.index) + str(input.unlock)
        SumString = SumString + str(out_counter)
        for output in vout:
            SumString = SumString + str(output.value) + str(output.lock)
        keccak_hash = keccak.new(digest_bits=256)
        keccak_hash.update(SumString.encode('ascii'))  # keccak_hash == tx_id of current transaction

        # Add to UTXOset and myUTXOset
        address = base64.b64encode(receiver).decode('utf-8')
        utxo = {'index': 0, 'address': address, 'amount': amount}
        utxo_en = json.dumps(utxo)
        UTXOset._UTXOset.put((keccak_hash.hexdigest()).encode(), utxo_en.encode())

        if(change > 0):
            address = base64.b64encode(publicKey_ser).decode('utf-8')
            utxo = {'index': 1, 'address': address, 'amount': change}
            utxo_en = json.dumps(utxo)
            UTXOset._UTXOset.put((keccak_hash.hexdigest()).encode(), utxo_en.encode())

            utxo = {'index': 1, 'address': address, 'amount': change}
            utxo_en = json.dumps(utxo)
            UTXOset._myUTXOset.put((keccak_hash.hexdigest()).encode(), utxo_en.encode())

        # Add to memoryPool
        # Error : Object of type 'Vin' is not JSON serializable
        for input in vin:
            input.unlock = base64.b64encode(input.unlock).decode('utf-8')
        for output in vout:
            output.lock = base64.b64encode(output.lock).decode('utf-8')
        mempool = {'in_num': in_counter, 'vin': vin, 'out_num': out_counter,
                 'vout': vout}
        mempool_en = json.dumps(mempool)
        Transaction._MemoryPool.put((keccak_hash.hexdigest()).encode(), mempool_en.encode())

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
            if(tmp==False or json.loads(tmp)["index"]!=input.index):
                print("Does not exist in UTXOset")
                return False

            # 해당 input의 unlock sign을 대응하는 output의 lock으로 복호화 가능한지 확인
            #sig_des = PrivateKey().ecdsa_deserialize(input.unlock)
            # Search rawBlock and transaction pool that match with input.txid and input.index
            #verify = vout.lock.ecdsa_verify(bytes(bytearray.fromhex(txOutid)),sig_des)

            # index가 음수인지만 확인
            if (input.index < 0):
                return False

        # Check if sum of input values are less than sum of outputs


        # Cehck if double-spended in memoryPool
        # DB 구현후에 구현할 예정

        print("Valid transaction")
        return True

