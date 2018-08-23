import json
import socket
import socketserver

#CLP
import multiprocessing

import test

class _PeerRequestHandler(socketserver.BaseRequestHandler):

    #Message Handling function.
    def handle(self):
        msg_str = self.request.recv(655350).strip().decode('utf-8')
        msg_obj = json.loads(msg_str)
        msg_type = msg_obj['type']
        response = 'OK'
        peer = self.server.peer

        if msg_type == 'MINE': 
            # Call mine func
            peer.mine(msg_obj['data'])
        elif msg_type == 'CONNECT':
            host = msg_obj['host']
            port = msg_obj['port']
            peer.connect_to_peer(host, port)
        elif msg_type == 'PEERS':
            response = json.dumps(peer.peers)
        elif msg_type == 'SHOW':
            response = json.dumps(peer.chain.to_dict())
        elif msg_type == 'CHAIN':
            chain = msg_obj['chain']
            peer.replace_chain(chain)
        self.request.sendall(response.encode('utf-8'))

class Peer(object):

    def __init__(self, host='127.0.0.1', port=5000):
        self.host = host
        self.port = port
        self._peers = set()
   #     self._chain = Chain()

    def start(self):
        server = socketserver.ThreadingTCPServer(
                (self.host, self.port), _PeerRequestHandler)
        server.peer = self

        try:
            server.serve_forever()
        except KeyboardInterrupt as _:
            server.server_close()


    # connect new peer.
    def connect_to_peer(self, host, port):
        if (host, port) in self._peers:
            return 
        '''
        When new peer is added.
        1. You will add peer.
        2. send connection request.
        3. broadcast your chain.

        '''
        self._peers.add((host, port))
        peers = self._request_peers(host, port)
        self._add_peers(json.loads(peers))
        self._request_connection()
#        self._broadcast_chain()

    # it will be useless maybe...

    def mine(self, data):
        self._chain.mine(data)
        self._broadcast_chain()

    # replace chain function need to be coded.
    def replace_chain(self,chain):
        self._chain.replace_chain(chain)

    @property
    def chain(self):
        return self._chain

    @property
    def peers(self):
        return [{'host': host, 'port': port} for (host, port) in self._peers]

    def _add_peers(self, peers):
        for peer in peers:
            host = peer['host']
            port = peer['port']
            if host == self.host and port == self.port:
                continue
            if (host, port) in self._peers:
                continue
            self._peers.add((host,port))

    
    # Communication part.

    def _request_connection(self):
        message = {'type': 'CONNECT', 'host': self.host, 'port': self.port}
        return self._broadcast(message)

    def _request_peers(self, host, port):
        message = {'type': 'PEERS', 'host': self.host, 'port': self.port}
        return self._unicast(host, port, message)

    def _broadcast_chain(self):
        message = {'type': 'CHAIN', 'chain': self._chain.to_dict()}
        return self._broadcast(message)

    # Base communication

    def _unicast(self, host, port, message):
        pool = multiprocessing.Pool(1)
        result = pool.apply_async(
            self._send_message, args=(host, port, message))
        pool.close()
        pool.join()
        return result.get()

    def _broadcast(self, message):
        results = []
        pool = multiprocessing.Pool(5)
        for (host, port) in self._peers:
            results.append(pool.apply_async(
                self._send_message, args=(host, port, message)))
        pool.close()
        pool.join()
        return [result.get() for result in results]

    def _send_message(self, host, port, message):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((host, port))
            s.sendall(json.dumps(message).encode('utf-8'))
            response = s.recv(655350, 0)
            return response.decode('utf-8')
