from interface import Interface
from key import Key
from blockchain import Blockchain
from utxo import UTXOset
from memorypool import MemoryPool

def main():

    #init
    Blockchain.initialize()
    UTXOset.initialize()
    MemoryPool.initialize()

    #key generation
    privateKey=Key.keyPairGenerate()
    print('My public key :')
    print(bytes(bytearray(privateKey.pubkey.serialize(compressed=False))).hex())
    print('My private key :')
    print(bytes(bytearray(privateKey.private_key)).hex())

    #command line interface
    interface = Interface()
    interface.cmdloop()

if __name__ == '__main__':
    main()
