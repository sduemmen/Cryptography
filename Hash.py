from abc import ABC, abstractmethod
import sha256

class Hash(ABC):
    @abstractmethod
    def hash(self):
        pass

class SHA256(Hash):
    @staticmethod
    def hash(message='', encoding='utf-8', fileName=''):
        return sha256.hash(message, encoding, fileName)
