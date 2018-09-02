from merkletools import MerkleTools

def create_merkle_root(tx_set):
    # Merkle root 생성
    mt = MerkleTools(hash_type='sha256')

    for tx in tx_set:
        mt.add_leaf(str(tx), True)
    mt.make_tree()

    root_value = mt.get_merkle_root()
    return root_value
