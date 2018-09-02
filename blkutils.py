from block import Block
from merkleroot import create_merkle_root
from txutils import generate_coinbase

"""
# Method that calculates the vout's values
def Calculate_block_vouts(self, tx_id, index):
    # if there is no key-value data in db
    if RawBlock._raw_block.get(str(index).encode(),default=None) is None:
        return 0

    #if there is key-value data in db
    else:
        total_val=0
        tmpbl_Data=json.loads(RawBlock._raw_block.get(str(index).encode()),default=None)
        tmptx_set=json.loads(tmpbl_Data["tx_set"])
        for i in range(0,len(tmptx_set)):
            tmptx_set_el=json.loads(tmptx_set[i])
            if tmptx_set_el.tx_id == tx_id:
                tmptx_vout=tmptx_set_el.vout
                break
        for i in range(0,len(tmptx_vout)):
            total_val += tmptx_vout.value
        return total_val
"""

def getLatestBlock():
    if Block._BlockHeight > 10:
        return Block._BlockChain[9]
    else:
        return Block._BlockChain[Block._BlockHeight-1]


def get_difficulty(index, prev_diff):
    return 0x0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    """
    if index > 6:
        if index > 9:
            elapsed = Block._BlockChain[9].timestamp - Block._BlockChain[3].timestamp
        else:
            elapsed = Block._BlockChain[index-1].timestamp - Block._BlockChain[index-6].timestamp
        return int(elapsed/50*prev_diff)
    else:
        return 0x0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    """

def target_to_diff(target):
    pass


def diff_to_target(difficulty):
    pass


def get_candidateblock():
    # warning for poinint class var
    block_index = Block._BlockHeight
    previous_block = getLatestBlock()

    tx_set = []
    total_fee = 12.5

    # get tx_set from MemPool greedy
    # calculate total commission of tx_set(total_fee)
    # Transaction priority required

    coinbase = generate_coinbase(total_fee)
    tx_set.insert(0, coinbase)

    merkle_root = create_merkle_root(tx_set)
    difficulty = get_difficulty(Block._BlockHeight, previous_block.difficulty)

    return Block(block_index, '0', previous_block.block_hash, merkle_root, difficulty, 0, 0, tx_set)

#Require block fork management methods