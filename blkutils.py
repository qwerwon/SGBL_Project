import time

from Crypto.Hash import keccak

from block import Block
from transaction import Transaction, Vin, Vout
from txutils import generate_coinbase
from utxo import UTXOset


def getLatestBlock():
    if Block._BlockHeight > 10:
        return Block._BlockChain[9]
    else:
        return Block._BlockChain[Block._BlockHeight - 1]


def get_difficulty(index, prev_diff):
    if index > 6:
        if index > 9:
            elapsed = Block._BlockChain[9].timestamp - Block._BlockChain[3].timestamp
        else:
            elapsed = Block._BlockChain[index - 1].timestamp - Block._BlockChain[index - 6].timestamp
        return int(elapsed / 40 * prev_diff)
    else:
        return 0x00008fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff


def get_candidateblock():
    # warning for poinint class var
    block_index = Block._BlockHeight
    previous_block = getLatestBlock()

    tx_set = []
    total_fee = 12.5
    
    Block_Size = 10
    i = 0
    # get tx_set from MemPool
    for key, value in Transaction._MemoryPool.iterator():
        tx = Transaction.get_MemoryPool(key)
        tx_set.append(tx)
        i += 1
        if i == Block_Size-1:
            break

    # calculate total commission of tx_set(total_fee)
    output_comm = Calculate_curBlock(tx_set)
    input_comm=0
    for tx in tx_set:
        input_comm += Calculate_utxo_vouts(tx)

    commission = input_comm - output_comm
    total_fee += commission

    coinbase = generate_coinbase(total_fee)
    tx_set.insert(0, coinbase)

    # Error here~~~~~~~~~~~~~~~~
    merkle_root = create_merkle_root(tx_set)
    difficulty = get_difficulty(Block._BlockHeight, previous_block.difficulty)
    print(block_index, previous_block.block_hash, merkle_root, difficulty, tx_set)
    return Block(block_index, '0', previous_block.block_hash, merkle_root, difficulty, 0, 0, tx_set)


def create_merkle_root(tx_set):
    num = len(tx_set)
    relist = []
    if num == 1:
        return tx_set[0]
    i = 0
    if num % 2 == 1:
        tx_set[num] = tx_set[num-1]
        num = num+1
    keccak_hash = keccak.new(digest_bits=256)

    while True:
        keccak_hash.update(tx_set[i].encode('ascii'))
        tmp1 = keccak_hash.hexdigest()
        keccak_hash.update(tx_set[i+1].encode('ascii'))
        tmp2 = keccak_hash.hexdigest()

        keccak_hash.update((tmp1+tmp2).encode('ascii'))
        relist.append(keccak_hash.hexigest())
        
        i = i+2
        if i >= num:
            break

    create_merkle_root(relist)


# Not fundamental method for Block class
def Calculate_curBlock(tx_set):
    total_val = 0
    for tx in tx_set:
        tx_vout = tx.vout
        for i in range(0, len(tx_vout)):
            total_val += tx_vout.value
    return total_val


# using vin's tx_id, find this transaction and add all the values of its vout
def Calculate_utxo_vouts(tx):
    """

    :param tx       : Transaction()
    :return:        : Commission of tx
    """
    total_val=0
    for input in tx.vin:
        result = UTXOset.get_UTXO(input.txOutid, input.index)
        if result is False: # Invalid transaction included
            continue
        total_val += result.amount

    return total_val

# Require block fork management methods

# Block validation
def Block_Validation(block):
    """
       Key of DB       : str(index).encode()
        Args:
        block_index           : int
        block_hash      : string
        previous_block  : string
        merkle_root     : string
        difficulty      : int
        timestamp       : int
        nonce           : int
        tx_set          : list[Transaction()]
        """
    # Block Format check
    if type(block.block_index) is not int or \
            type(block.block_hash) is not str or \
            type(block.previous_block) is not str or \
            type(block.merkle_root) is not str or \
            type(block.difficulty) is not int or \
            type(block.timestamp) is not int or \
            type(block.nonce) is not int or \
            type(block.tx_set) is not list:
        print("Block type error")
        return False

    # Block Difficulty check
    prev_diff = None
    for tmp_block in Block._BlockChain:
        if tmp_block.block_idex == block.block_index-1:
            prev_diff = tmp_block.difficulty
    if prev_diff is None:
        print('Invalid block index')
        return False
    tmp_diff = get_difficulty(block.block_index, prev_diff)
    if tmp_diff != block.difficulty:
        print("Difficulty Value")
        return False

    # Nonce value check
    hash_input = str(block.previous_block) + \
                str(block.merkle_root) + \
                str(block.difficulty) + \
                str(block.nonce)

    keccak_hash = keccak.new(digest_bits=256)
    keccak_hash.update(hash_input.encode('ascii'))

    if block.block_hash != keccak_hash.hexdigest():
        print("Invalid block hash")
        return False

    # Within 2 hours -> 10 min
    current_time = int(time.time())
    elapsed_time = int(current_time - block.timestamp)
    if elapsed_time > 600:
        print("Old block")
        return False

    # Is it coinbase transaction?
    coinbase_tx = block.tx_set[0]
    if coinbase_tx.in_num != 0:
        print("Coinbase transaction error")
        return False

    # transaction valid is not make
    for tx in block.tx_set:
        if Transaction.isValid(tx) == False :
            print("Invalid transaction included")
            return False

    max_num = 10
    # length of list
    if len(block.tx_set) > max_num :
        print("Tx num")
        return False

    print('Valid block')
    return True
