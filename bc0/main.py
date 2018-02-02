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
TIP_KEY = 'l'


def _sha256(bs):
    m = hashlib.sha256()
    m.update(bs)
    return m.digest()


def _int64_bytes(i):
    return struct.pack('>q', i)


class Block:
    def __init__(self, data, prev_hash):
        self.timestamp = int(time.time())
        self.data = data
        self.prev_hash = prev_hash
        self.pow = POW(self)
        nonce, hash_ = self.pow.run()
        self.hash = hash_
        self.nonce = nonce

    def _set_hash(self):
        headers = self.prev_hash + bytes(self.data, 'utf-8') + bytes(str(self.timestamp), 'utf-8')
        self.hash = _sha256(headers)

    def serialize(self):
        return pickle.dumps(self)

    @staticmethod
    def deserialize(bs):
        return pickle.loads(bs)

    @staticmethod
    def genesis():
        return Block("GenesisBlock", b'')


class BlockChain:
    def __init__(self):
        self.tip = b''
        self.db = None

    @staticmethod
    def create():
        return BlockChain()


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
    bc = BlockChain()
    bc.add('send 1 to Ivan')
    bc.add('send 2 to Ivan')

    for b in bc.blocks:
        print('prev: {0}\ndata: {1}\nhash: {2}\n'.format(
            binascii.hexlify(b.prev_hash), b.data, binascii.hexlify(b.hash)))
