import json
import sys
import binascii
import time
import hashlib
import struct
import pickle
import leveldb


TARGET_BITS = 24
MAX_NONCE = sys.maxsize
FILE_NAME = './db'
TIP_KEY = b'l'


def _sha256(bs):
    m = hashlib.sha256()
    m.update(bs)
    return m.digest()


def _int64_bytes(i):
    return struct.pack('>q', i)


def _bytes_str(bs):
    return binascii.hexlify(bs)


class _Store:
    def __init__(self, path):
        self.db = leveldb.LevelDB(path)

    def get(self, key):
        try:
            return self.db.Get(key)
        except:
            return None

    def put(self, key, value):
        return self.db.Put(key, value)


class Block:
    def __init__(self, data, prev_hash):
        self.timestamp = int(time.time())
        self.data = data
        self.prev_hash = prev_hash
        self.pow = POW(self)
        nonce, hash_ = self.pow.run()
        self.hash = hash_
        self.nonce = nonce

    def serialize(self):
        return pickle.dumps(self)

    def __repr__(self):
        return 'timestamp:{},prev_hash:{},hash={}'.format(
            self.timestamp, _bytes_str(self.prev_hash), _bytes_str(self.hash))

    @staticmethod
    def deserialize(bs):
        return pickle.loads(bs)

    @staticmethod
    def genesis():
        return Block("GenesisBlock", b'')


class BlockChain:
    def __init__(self, store):
        self.tip = b''
        self.store = store

    def add(self, data):
        tip = self.store.get(TIP_KEY)
        if not tip:
            raise ValueError('tip')
        block = Block(data, tip)
        self.store.put(block.hash, block.serialize())
        self.store.put(TIP_KEY, block.hash)
        return block

    def iterator(self):
        return BlockChainIterator(self.tip, self.store)

    @staticmethod
    def create(path):
        store = _Store(path)
        tip = store.get(TIP_KEY)
        bc = BlockChain(store)
        if tip is None:
            genesis = Block.genesis()
            store.put(genesis.hash, genesis.serialize())
            store.put(TIP_KEY, genesis.hash)
            tip = genesis.hash
        bc.tip = tip
        return bc


class BlockChainIterator:
    def __init__(self, tip, store):
        self.current_hash = tip
        self.store = store

    def __iter__(self):
        return self

    def __next__(self):
        bs = self.store.get(self.current_hash)
        if bs is None:
            raise StopIteration()
        block = Block.deserialize(bs)
        self.current_hash = block.prev_hash
        return block


class POW:
    def __init__(self, block):
        self.block = block
        self.target = 1 << (256 - TARGET_BITS)

    def prepare(self, nonce):
        return self.block.prev_hash \
               + bytes(self.block.data, 'utf-8') \
               + _int64_bytes(self.block.timestamp) \
               + _int64_bytes(TARGET_BITS) \
               + _int64_bytes(nonce)

    def run(self):
        nonce = 0
        hash_ = b''
        print('Mining the block containing {}'.format(self.block.data))
        while nonce < MAX_NONCE:
            data = self.prepare(nonce)
            hash_ = _sha256(data)
            # print(hash_)
            i = int.from_bytes(hash_, 'big')
            if i < self.target:
                break
            nonce += 1
        return nonce, hash_


class TX:
    def __init__(self, vin, vout):
        self.id = b''
        # [TXI]
        self.vin = vin
        # [TXO]
        self.vout = vout
        # set the ID
        self._set_id()

    def _set_id(self):
        self.id = _sha256(pickle.dumps(self))

    @staticmethod
    def new_coinbase_tx(to, data):
        if data == '':
            data = 'Reward to {]'.format(to)
        txi = TXI()
        txo = TXO()
        tx = TX([txi,], [txo,])
        return tx


class TXI:
    def __init__(self):
        self.txid = b''
        self.vout = 0
        self.script_sig = b''


class TXO:
    def __init__(self):
        self.value = b''
        self.script_pub_key = b''


class UTXO:
    def __init__(self):
        pass


class CLI:
    def __init__(self, bc):
        self.bc = bc

    def cmd_add(self, data):
        self.bc.add(data)

    def cmd_print(self):
        it = self.bc.iterator()
        for b in it:
            print(b)

    def run(self):
        import argparse
        parser = argparse.ArgumentParser()
        parser.add_argument('-a', '--add', dest='add_data')
        parser.add_argument('-p', '--print', help='print chain')
        args = parser.parse_args()

        if args.add_data:
            self.cmd_add(args.add_data)
        elif args.print:
            self.cmd_print()


if __name__ == '__main__':
    bc = BlockChain.create('./db')
    cli = CLI(bc)
    cli.run()
