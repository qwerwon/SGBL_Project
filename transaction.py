import base64
import json

from Crypto.Hash import keccak

from key import Key
from utxo import UTXOset, Vout, Vin, UTXO
from memorypool import MemoryPool

class Transaction(object):

    def __init__(self, tx_id, in_num, vin, out_num, vout):
        # Key = tx_id
        self.tx_id = tx_id          # bytes
        self.in_num = in_num        # int
        self.vin = vin              # list[Vin]
        self.out_num = out_num      # int
        self.vout = vout            # list[Vout]

    # Generate a transaction from command line
    def generate(self, receiver, amount, commission):
        publicKey = Key._publicKey
        privateKey = Key._privateKey

        publicKey_ser = publicKey.serialize(compressed=False)

        total = 0
        in_counter = 0
        out_counter = 0
        vin = []
        vout = []
        tmpUTXO = []  # Temporary UTXOset for resulting transaction

        # Check if amount or commission is negative
        if amount <= 0 or commission < 0:
            print('Invalid input value')
            return False

        # Check if balance is sufficient
        for key, value in UTXOset._myUTXOset.iterator():
            d_value = json.loads(value)

            address_ser = base64.b64decode(d_value["address"])
            if address_ser != publicKey_ser:
                UTXOset.Pop_myUTXO(key, d_value["index"])
                continue

            tmpUTXO.append(UTXO(key, d_value["index"], d_value["address"], d_value["amount"]))
            total += d_value["amount"]
            if total > amount + commission:
                break

        # Insufficient balance
        if total < amount + commission:
            print('Insufficient BTC balance')
            return False

        # Generate inputs
        for output in tmpUTXO:
            total += output.amount
            in_counter += 1

            # Generate signatures
            unlockSig = privateKey.generate_sign(output.txOutid)
            unlock = privateKey.ecdsa_serialize(unlockSig)
            vin.append(Vin(output.txOutid, output.index, unlock))

        # Generate outputs
        vout.append(Vout(amount, receiver))
        change = total - commission - amount
        if change > 0:
            vout.append(Vout(change, publicKey_ser))

        # Generate tx_id
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
        UTXOset.Insert_UTXO(keccak_hash.hexdigest().encode(), 0, address, float(amount))

        if (change > 0):
            address = base64.b64encode(publicKey_ser).decode('utf-8')
            UTXOset.Insert_UTXO(keccak_hash.hexdigest().encode(), 1, address, float(amount))
            UTXOset.Insert_myUTXO(keccak_hash.hexdigest().encode(), 1, address, float(amount))

        # Delete from UTXOset and myUTXOset
        for otuput in tmpUTXO:
            UTXOset.Pop_UTXO(output.txOutid, output.index)
            UTXOset.Pop_myUTXO(output.txOutid, output.index)
       
        # Add to memoryPool
        MemoryPool.Insert_MemoryPool(self,keccak_hash.hexdigest().encode(), in_counter, vin, out_counter, vout)

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

        if keccak_hash.hexdigest().encode() != self.tx_id:
            print("Hash does not match")
            return False

        outSum = 0
        inSum = 0
        for output in self.vout:
            outSum += output.value
        if outSum < 0 or outSum > 21000000:
            print("Sum of output is out of range")
            return False

        # Check if inputs are valid
        for input in self.vin:

            # Check if inputs exist in UTXOset
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

        print("Valid transaction")
        return True

    def generate_coinbase(self, total_fee):
        self.in_num = 0
        self.vin = []
        self.out_num = 1
        self.vout = [Vout(total_fee, Key._publicKey.serialize(compressed=False))]
        SumString = str(self.in_num) + str(self.vin) + str(self.out_num) + str(self.vout)
        keccak_hash = keccak.new(digest_bits=256)
        keccak_hash.update(SumString.encode('ascii'))
        tx_id = keccak_hash.hexdigest().encode()
        self.tx_id = tx_id

    # using vin's tx_id, find this transaction and add all the values of its vout
    def Calculate_mem(self, tx_id):
        total_val=0
        if MemoryPool._MemoryPool.get(tx_id, default=None) is None:
            return 0
        else:
            tmptx_Data = json.loads(MemoryPool._MemoryPool.get(tx_id, default=None))
            tmpvout=json.loads(tmptx_Data["vout"])
            for i in range(0,len(tmpvout)):
                tmpvout_el = json.loads(tmpvout[i])
                total_val += float(tmpvout_el["value"])
            return total_val
