#!/usr/bin/env python


import json
import atexit
import pickle
import hashlib
from Crypto.Cipher import AES
try:
    import pylzma
except ImportError:
    pylzma = None


class Crypter(object):
    SALT = '9>_|\x01j+(+S\xd9|\x91N\xcfB\x89,\xdcGE\xa5\x1d;*\xb2|Bt9\xc7p'
    GZIP = 'g'
    LZMA = 'l'
    BZ2 = 'b'
    RAW = 'r'
    JSON = 'j'
    PICKLE = 'p'
    PADDING = '\x00'
    BLOCK_SIZE = 32
    BYTE = 1
    KB = 1024 * BYTE
    MB = 1024 * KB
    GB = 1024 * MB
    TB = 1024 * GB
    WALLET_SIZE = MB

    def __init__(self, password, salt=SALT):
        self.password = password
        self.salt = salt

    @property
    def raw_key(self):
        if not hasattr(self, '_raw_key'):
            self._raw_key = hashlib.sha512(self.password + self.salt).digest()
        return self._raw_key

    @property
    def key(self):
        return self.raw_key[:32]

    @property
    def iv(self):
        if not hasattr(self, '_iv'):
            with open('/dev/urandom', 'rb') as f:
                self._iv = f.read(16)
        return self._iv

    @property
    def cipher(self):
        if not hasattr(self, '_cipher'):
            self._cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        return self._cipher

    def reset(self):
        if hasattr(self, '_cipher'):
            del self._cipher
        if hasattr(self, '_iv'):
            del self._iv
        return self

    def read_file(self, file_name):
        self.reset()
        with open(file_name, 'rb') as f:
            return self._file_decode(self.decrypt(f.read(), raw=True))

    def write_file(self, file_name, data, header=RAW, wallet_size=WALLET_SIZE):
        best = sorted(
            self._compressions(data, header=header),
            key=lambda x: len(x)
        )[0]
        with open(file_name, 'wb') as f:
            f.write(
                self.encrypt(
                    self.pad_random(best, self.WALLET_SIZE),
                    raw=True,
                )
            )

    def write_raw(self, file_name, data, wallet_size=WALLET_SIZE):
        self.write_file(file_name, data, self.RAW, wallet_size)

    def write_json(self, file_name, data, wallet_size=WALLET_SIZE):
        self.write_file(file_name, json.dumps(data), self.JSON, wallet_size)

    def write_pickle(self, file_name, data, wallet_size=WALLET_SIZE):
        self.write_file(file_name, pickle.dumps(data), self.PICKLE, wallet_size)

    def encrypt(self, data, raw=False):
        encrypted = self.cipher.encrypt(self.pad(data))
        if raw:
            return self.iv + encrypted
        return (self.iv + encrypted).encode('base64').strip()

    def decrypt(self, data, raw=False):
        if not raw:
            data = data.decode('base64')
        iv, data = data[:16], data[16:]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return cipher.decrypt(data).rstrip(self.PADDING).strip()

    @classmethod
    def _file_decode(cls, data):
        """{z,b,l}{j,p}<data_len><pad><DATA>"""
        alg = data[0]
        header = data[1]
        idx = data.find(cls.PADDING)
        size = int(data[2:idx])
        data = data[idx + 1:idx + 1 + size]
        if alg == cls.GZIP:
            data = data.decode('zlib')
        elif alg == cls.BZ2:
            data = data.decode('bz2')
        elif alg == cls.LZMA:
            data = pylzma.decompress(data)
        if header == cls.JSON:
            data = json.loads(data)
        if header == cls.PICKLE:
            data = pickle.loads(data)
        return data

    @classmethod
    def _file_gzip(cls, data, header=RAW):
        gzip_data = data.encode('zlib')
        return cls.GZIP + header + str(len(gzip_data)) + cls.PADDING + gzip_data

    @classmethod
    def _file_bz2(cls, data, header=RAW):
        bz2_data = data.encode('bz2')
        return cls.BZ2 + header + str(len(bz2_data)) + cls.PADDING + bz2_data

    @classmethod
    def _file_lzma(cls, data, header=RAW):
        lzma_data = pylzma.compress(data)
        return cls.LZMA + header + str(len(lzma_data)) + cls.PADDING + lzma_data

    @classmethod
    def _file_raw(cls, data, header=RAW):
        return cls.RAW + header + str(len(data)) + cls.PADDING + data

    @classmethod
    def _compressions(cls, data, header=RAW):
        compressions = [
            cls._file_gzip(data, header=header),
            cls._file_bz2(data, header=header),
            cls._file_raw(data, header=header),
        ]
        if pylzma is not None:
            compressions.append(cls._file_lzma(header + data))
        return compressions

    @classmethod
    def pad(cls, data, block_size=BLOCK_SIZE):
        data_and_iv_len = len(data) + 16
        block_size = block_size or cls.BLOCK_SIZE
        return data + (block_size - data_and_iv_len % block_size) * cls.PADDING

    @classmethod
    def pad_random(cls, data, block_size=WALLET_SIZE):
        while len(data) % block_size:
            data = data + cls.random()
        return data

    @classmethod
    def random(cls, size=1):
        if hasattr(cls, '_random'):
            return cls._random.read(size)
        atexit.register(cls._clear_random)
        cls._random = open('/dev/urandom', 'rb')
        return cls.random(size)

    @classmethod
    def _clear_random(cls):
        cls._random.close()


if __name__ == '__main__':
    message = 'attack at dawn'
    password = 'password'
    file_name = 'test.cry'
    data = {'attack': ['at', 'dawn'], 'long': message}
    crypter = Crypter(password)
    encrypted = crypter.encrypt(message)
    print 'Encrypted base64:', repr(encrypted)
    print 'Decrypted string:', repr(crypter.reset().decrypt(encrypted))
    crypter.reset().write_file(file_name, message)
    print 'Decrypted file  :', repr(crypter.read_file(file_name))
    crypter.reset().write_json(file_name, data)
    print 'Decrypted json  :', repr(crypter.read_file(file_name))
    crypter.reset().write_pickle(file_name, data)
    print 'Decrypted pickle:', repr(crypter.read_file(file_name))
