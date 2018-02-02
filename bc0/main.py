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
    pass


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


class TXI:
    pass


class TXO:
    pass


class UTXO:
    pass


if __name__ == '__main__':
    bc = BlockChain.create('./db')
    print(bc.tip)
