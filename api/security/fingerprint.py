from hashlib import pbkdf2_hmac
from abc import ABC


class IFingerprintGenerator(ABC):

    def fingerprint(self):
        pass

SALT = 'fingerprint-salt'.encode()

class CognitoFingerprintGenerator(IFingerprintGenerator):

    def __init__(self, client_id, client_secret, user_pool_id):
        self.client_id = client_id
        self.client_secret = client_secret
        self.user_pool_id = user_pool_id

    def fingerprint(self):
        to_encrypt = self.client_id + self.client_secret + self.user_pool_id
        return pbkdf2_hmac('sha256', to_encrypt.encode(), SALT, 500_000).hex()

class AzureADFingerprintGenerator(IFingerprintGenerator):
    def __init__(self, client_id, client_secret):
        self.client_id = client_id
        self.client_secret = client_secret

    def fingerprint(self):
        to_encrypt = self.client_id + self.client_secret
        return pbkdf2_hmac('sha256', to_encrypt.encode(), SALT, 500_000).hex()