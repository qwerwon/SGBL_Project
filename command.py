import json
import multiprocessing
import socket
import threading
import base64
from mining import Mining
from peer import Peer
from txutils import generate_transaction
from transaction import Transaction


class Command(object):

    def start_peer(self, host, port):
        p = multiprocessing.Process(target=self._start_peer, args=(host, port))
        p.start()
        print(f'Peer running at {host}:{port}')

    def _start_peer(self, host, port):
        peer = Peer(host, port)
        peer.start()

    def connect_peer(self, host, port, target_host, target_port):
        print('Connecting...')
        message = {'type': 'CONNECT', 'host': target_host, 'port': target_port}
        result = self._unicast(host, port, message)
        if result == 'OK':
            print(f'Peer {host}:{port} connected to {target_host}:{target_port}')
        else:
            print('Connect failed')
        return result

    def mine(self, host, port, data):
        print('Mining work starts')
        '''
        message = {'type': 'MINE', 'data': data}
        result = self._unicast(host, port, message)
        if result == 'OK':
            print('A new block was mined')
        else:
            print('Mine failed')
        return result
        '''
        miningThread = threading.Thread(target=Mining.mineStart)
        miningThread.start()

    def stop(self):
        Mining.flagdown()
        print('Stop Mining.\n')

    def newTx(self):
        receiver = input('Address of receiver : ')  #type(receiver) : string
        receiver = base64.b64decode(receiver)

        amount = float(input('BTC : '))
        commission = float(input('Commission : '))
        generate_transaction(receiver, amount, commission)

    def get_chain(self, host, port):
        message = {'type': 'SHOW'}
        result = self._unicast(host, port, message)
        if result:
            chain = json.loads(result)
            for block in chain:
                index = block['index']
                prev_hash = block['previous_hash']
                timestamp = block['timestamp']
                data = block['data']
                nonce = block['nonce']
                hash = block['hash']
                print('\n')
                print(f'# Block {index}')
                print('+-----------+-------------------------------------------'
                      '---------------------+')
                print(f'| prev_hash |{prev_hash: >{64}}|')
                print('|-----------|-------------------------------------------'
                      '---------------------|')
                print(f'| timestamp |{timestamp: >{64}}|')
                print('|-----------|-------------------------------------------'
                      '---------------------|')
                print(f'|    data   |{data[:64]: >{64}}|')
                print('|-----------|-------------------------------------------'
                      '---------------------|')
                print(f'|   nonce   |{nonce: >{64}}|')
                print('|-----------|-------------------------------------------'
                      '---------------------|')
                print(f'|    hash   |{hash: >{64}}|')
                print('+-----------+-------------------------------------------'
                      '---------------------+')
        else:
            print('Empty blockchain')
        return result
    def get_Tx(self, txid):
        newtrans = Transaction._MemoryPool.get(txid.encode())
        print('567890-9iuyu')
        newtemp = json.loads(newtrans)
        Command.print_Tx(newtemp)
        print('567890-9iuyu')
        
    def print_Tx(self, newtrans):
        print('sdgfhjkl;hjgfdghjkl;/kjhgf')
        newtrans_el=json.loads(newtrans)
        tx_id=newtrans["tx_id"]
        in_num=newtrans["in_num"]
        out_num=newtrans["out_num"]
        vinlist=newtrans["vin"]
        vinlist_el=json.loads(vinlist)

        voutlist=newtrans["vout"]
        voutlist_el=json.loads(voutlist)

        print('tx_id : ', tx_id)
        print('in_num : ', in_num)
        for i in range(0, len(vinlist)):
            print('vin : ')
            print('\ttx_id : ', str(vinlist_el['tx_id']))
            print('\tindex : ', int(vinlist_el['index']))
            print('\tunlock : ', bytes(vinlist_el['unlock']))
        for i in range(0, len(vin)):
            print('\ttx_id : ', str(voutlist_el['tx_id']))
            print('\tindex : ', int(voutlist_el['index']))
            print('\tunlock : ', bytes(voutlist_el['unlock']))
        print('out_num : ', out_num)
        for i in range(0, len(voutlist)):
            print('vout : ')
            print('\tvalue : ', float(voutlist_el['value']))
            print('\tlock : ', bytes(voutlist_el['lock']))

    def getall_Mem(self):
        for key, value in Transaction._MemoryPool:
            newvalue=Transaction._MemoryPool(key)
            newtemp=json.loads(newvalue)
            

            print(newtemp)


    def _unicast(self, host, port, message):
        pool = multiprocessing.Pool(1)
        result = pool.apply_async(  self._send_message, args=(host, port, message))
        pool.close()
        pool.join()
        return result.get()

    def _send_message(self, host, port, message):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((host, port))
            s.sendall(json.dumps(message).encode('utf-8'))
            response = s.recv(655350)
            return response.decode('utf-8')
