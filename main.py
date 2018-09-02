from interface import Interface
from key import Key
from block import Block
from transaction import Transaction
from utxo import UTXOset


def main():
    # init
    Block.initialize()
    UTXOset.initialize()
    Transaction.initialize()

    # key generation
    privateKey = Key().keyPairGenerate()
    print('My public key :')
    print(bytes(bytearray(privateKey.pubkey.serialize(compressed=False))).hex())
    print('My private key :')
    print(bytes(bytearray(privateKey.private_key)).hex())

    # command line interface
    interface = Interface()
    interface.cmdloop()


if __name__ == '__main__':
    main()
