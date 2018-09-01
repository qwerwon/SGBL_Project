import cmd
import os
from command import Command
from transaction import Transaction
from utxo import UTXOset
from blockchain import Blockchain

class Interface(cmd.Cmd):

    def __init__(self):
        super().__init__()
        self.prompt = '(blockchain) '
        self._default_host = '127.0.0.1'
        self._command = Command()

    def do_open(self, port):
        '''
        Open peer listening port Eg: open 5000
        '''
        self._command.start_peer(self._default_host, int(port))

    def do_mine(self, arg):
        '''
        Mine a new block Eg: mine hello
        '''
        port = arg.split(' ')[0]
        data = arg.split(' ')[1]
        self._command.mine(self._default_host, int(port), data)

    def do_stop(self, _):
        self._command.stop()

    def do_newTransaction(self,_):
        self._command.newTx()
 
    def do_connect(self, arg):
        '''
        Connect a peer to another Eg: connect 5000 5001
        '''
        port = arg.split(' ')[0]
        target_port = arg.split(' ')[1]
        self._command.connect_peer(
            self._default_host, int(port), self._default_host, int(target_port))

    def do_show(self, port):
        '''
        Show blockchain of peer Eg: show 5000
        '''
        self._command.get_chain(self._default_host, int(port))

    def do_exit(self, _):
        UTXOset._UTXOset.close()
        UTXOset._myUTXOset.close()
        Transaction._MemoryPool.close()
        Blockchain._RawBlock.close()
        os._exit(0)

    def do_help(self, _):
        print('\n')
        print('Commands:')
        print('\n')
        print('help \t\t\t\t Help for given commands')
        print('exit \t\t\t\t Exit application')
        print('\n')
        print('open <port> \t\t\t Open peer listening port Eg: open 5000')
        print(
            'connect <port> <target_port> \t '
            'Connect a peer to another Eg: connect 5000 5001')
        print('\n')
        print('mine <port> <data> \t\t Mine a new block Eg: mine hello')
        
        print('stop  \t\t Stop mining block Eg: stop')

        print('newTransaction \t\t Generate new Transaction.')
        print('show <port> \t\t\t Show blockchain of peer Eg: show 5000')
        print('\n')

    def emptyline(self):
        pass
