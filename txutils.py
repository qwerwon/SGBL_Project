import base64
import json

from secp256k1prp import PrivateKey
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

        """"
        type(output.txOutid)     #bytes->str
        type(output.index)       #ints
        type(unlock)             #bytes->str
        """
        vin.append(Vin(base64.b64encode(output.txOutid).decode('utf-8'), output.index, base64.b64encode(unlock).decode('utf-8')))

    # Generate outputs

    """
    type(amount)  #float
    type(receiver)  #bytes->str
    type(publicKey_ser)  # bytes->str
    """
    vout.append(Vout(amount, base64.b64encode(receiver).decode('utf-8')))
    change = total - commission - amount
    if change > 0:
        vout.append(Vout(change, base64.b64encode(publicKey_ser).decode('utf-8')))

    # Generate tx_id
    SumString = str(in_counter)
    for input in vin:
        SumString = SumString + str(input.tx_id) + str(input.index) + str(input.unlock)
    SumString = SumString + str(out_counter)
    for output in vout:
        SumString = SumString + str(output.value) + str(output.lock)
    keccak_hash = keccak.new(digest_bits=256)
    keccak_hash.update(SumString.encode('ascii'))  # keccak_hash == tx_id of current transaction

    # Add to memoryPool
    Transaction.Insert_MemoryPool(keccak_hash.hexdigest().encode(), in_counter, vin, out_counter, vout)

    return True


def isValid(transaction):
    # Type check for elements
    check_flag = True
    if type(transaction.tx_id) is not bytes or \
        type(transaction.in_num) is not int or \
        type(transaction.out_num) is not int:
        check_flag = False

    for input in transaction.vin:
        if type(input.tx_id) is not str:
            check_flag = False
            break
        if type(input.index is not int):
            check_flag = False
            break
        if type(input.unlock) is not bytes:
            check_flag = False
            break

    for output in transaction.vout:
        if type(output.value) is not float:
            check_flag = False
            break
        if type(output.lock) is not bytes:
            check_flag = False
            break

    if check_flag is False:
        print('Transaction type error')
        return False

    # Check if there is any negative value
    for output in transaction.vout:
        if (output.value < 0):
            print("Negative output value")
            return False

    # Check if output is empty
    if len(transaction.vout) == 0:
        print('Output is empty')
        return False

    # Check if input is empty
    # Coinbase transaction limit are not implemneted
    if len(transaction.vin) == 0 :
        if transaction.out_num != 1:
            print('Input is empty')
            return False
        else:
            pass

    # Check if signature(unlock script) of input is valid
    if Key.verify(PrivateKey().ecdsa_deserialize(transaction.vout.lock)) is False:
        print('Invalid unlock script')
        return False

    # Check if inputs of transactions are unspent
    # Calculate total input value
    input_sum = 0
    for tmp in transaction.vin:
        # Check if remains on UTXOset
        result = UTXOset.get_UTXO(tmp.tx_id, tmp.index)
        if result is False:
            print('Not exist in UTXOset')
            return False
        # Check if arlready spent in MemoryPool
        for key, value in Transaction._MemoryPool.iterator():
            tx = Transaction.get_MemoryPool(key)
            for vin in tx.vin:
                if vin.tx_id == tmp.tx_id and vin.index == tmp.index:
                    print('It already spent')
                    return False
        input_sum += result.amount

    # Calculate total output value
    output_sum =0
    for output in transaction.vout:
        output_sum += output.value

    # Check if total input is less than total output
    if input_sum < output_sum:
        print('Total input < total output')
        return False

    # Check if tx_id is valid
    SumString = str(transaction.in_num)
    for input in transaction.vin:
        SumString = SumString + str(input.tx_id) + str(input.index) + str(input.unlock)
    SumString = SumString + str(transaction.out_num)
    for output in transaction.vout:
        SumString = SumString + str(output.value) + str(output.lock)
    keccak_hash = keccak.new(digest_bits=256)
    keccak_hash.update(SumString.encode('ascii'))

    if keccak_hash.hexdigest().encode() != transaction.tx_id:
        print("Hash does not match")
        return False

    if output_sum < 0 or output_sum > 21000000:
        print("Sum of output is out of range")
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
