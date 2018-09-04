import base64
import json

from Crypto.Hash import keccak

from key import Key
from transaction import Transaction, Vin, Vout
from utxo import UTXOset, UTXO



# Generate a transaction from command line
def generate_transaction(receiver, amount, commission):
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
        #여기 수정, Key의 메소드임 generate_sign은.
        unlockSig = Key.generate_sign(privateKey,output.txOutid)
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

    UTXOset.Insert_UTXO(keccak_hash.hexdigest().encode(), 0, receiver, float(amount))


    if (change > 0):
        address = base64.b64encode(publicKey_ser).decode('utf-8')
        UTXOset.Insert_UTXO(keccak_hash.hexdigest().encode(), 1, receiver, float(amount))
        UTXOset.Insert_myUTXO(keccak_hash.hexdigest().encode(), 1, receiver, float(amount))

    # Delete from UTXOset and myUTXOset
    for output in tmpUTXO:
        UTXOset.Pop_UTXO(output.txOutid, output.index)
        UTXOset.Pop_myUTXO(output.txOutid, output.index)

    #지금 여기문제임!!!
    # Add to memoryPool
    Transaction.Insert_MemoryPool(keccak_hash.hexdigest().encode(), in_counter, vin, out_counter, vout)

    print("\n\n\n103\n\n\n")

    return True


def isValid(transaction):
"""김동환 하는중.
    #1.타입 및 format 체크
    for input in transaction.vin:
        if( type(input.tx_id) != type("str")):
            return False
        if( type(input.index) != type(2)):
            return False
        if(type(input.unlock)!= type(b"23")):
            return False

    for output in transaction.vout:
        if( type(output.value) != type(2.3)):
            return False
        if(type(output.lock) != type(b"12")):
            return False
    #####

    for output in transaction.vout:
        if (output.value < 0):
            print("Negative output value")
            return False

    #2.출력값이 비어있지 않아야 한다. 만약 입력값이 비어있으면 코인베이스인지 확인한다.
    #코인 베이스일 경우 100개의 block interval이 지나야 사용할 수 있도록 한다.
    if( len(transaction.vout) == 0):
        return  False
    if( len(transaction.vin) == 0 ):
        if( transaction.out_num != 1):
            return False
    #2. ??? 어떻게 100개 블록 생성된 다음에 coinbase가 사용되게 하지?

    #4.해당 input의 unlock(서명)이 대응하는 publickey를 이용해서 복호화 가능한지 확인
    from secp256k1prp import PrivateKey
    if( Key.verify( PrivateKey().ecdsa_deserialize(transaction.vout.lock) ) == False):
        return False

    #5. input의 총합이 output의 총합보다 크거나 같아야함
    #== Check if sum of input values are less than sum of outputs
    input_sum =0
    for input in transaction.vin:
        for tx in Transaction._MemoryPool:
            if(input.tx_id == tx.tx_id):
                input_sum += tx.vout.value
    output_sum =0
    for output in transaction.vout:
        output_sum += output.value

    if( input_sum < output_sum):
        return False

    #6. input이 이미 사용된 input인지 memorypool에서 확인한다
    for input in transaction.vin:
        for tx in Transaction._MemoryPool:
            if( input.tx_id == tx.vin.tx_id):
                return False
"""


    # Check if tx_id is valid
    SumString = str(transaction.in_num)
    for input in transaction.vin:
        SumString = SumString + str(input.tx_id) + str(input.index) + str(input.unlock)
    SumString = SumString + str(transaction.out_num)
    for output in transaction.vout:
        SumString = SumString + str(output.value) + str(output.lock)
    keccak_hash = keccak.new(digest_bits=256)
    keccak_hash.update(SumString.encode('ascii'))  # keccak_hash == tx_id of current transaction

    if keccak_hash.hexdigest().encode() != transaction.tx_id:
        print("Hash does not match")
        return False

    outSum = 0
    inSum = 0
    for output in transaction.vout:
        outSum += output.value
    if outSum < 0 or outSum > 21000000:
        print("Sum of output is out of range")
        return False

    # Check if inputs are valid
    for input in transaction.vin:

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



    print("Valid transaction")
    return True


def generate_coinbase(total_fee):
    """
    Returns:
        Transaction(
            tx_id       : bytes(key of db)
            in_counter  : int
            vin         : list[Vin]
            out_counter : int
            vout        : list[Vout]
        )
    """

    in_num = 0
    vin = []
    out_num = 1
    vout = [Vout(total_fee, Key._publicKey.serialize(compressed=False))]
    SumString = str(in_num) + str(vin) + str(out_num) + str(vout)
    keccak_hash = keccak.new(digest_bits=256)
    keccak_hash.update(SumString.encode('ascii'))
    tx_id = keccak_hash.hexdigest().encode()
    return Transaction(tx_id, in_num, vin, out_num, vout)

"""    
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
"""