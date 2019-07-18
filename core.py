import base64
import datetime
import hashlib
import os

from Crypto.Cipher import AES

CHECKSUM_VERSE = os.environ['CRYPTER_CHECKSUM_VERSE']
CHECKSUM_SIZE = os.environ.get('CRYPTER_CHECKSUM_SIZE', 32)
GCM_IV_CODE = os.environ['CRYPTER_GCM_IV_CODE']
TIME_OFFSET = os.environ.get('CRYPTER_TIME_OFFSET', 180)


def get_timestamp():
    return int(int(datetime.datetime.now().timestamp()) / int(TIME_OFFSET))


def checksum(string_value):
    m = hashlib.md5()
    m.update(string_value.encode('utf-8'))
    m.update(CHECKSUM_VERSE.encode('utf-8'))

    return m.hexdigest()[:CHECKSUM_SIZE]


def get_time_based_key(offset=0):
    m = hashlib.sha256()
    m.update(str(get_timestamp() + offset).encode('utf-8'))
    m.update(CHECKSUM_VERSE.encode('utf-8'))

    return m.digest()


def get_crypter(offset=0):
    return AES.new(get_time_based_key(offset), AES.MODE_GCM, GCM_IV_CODE.encode('utf-8'))


def encrypt(string_data):
    """
    :param string_data:
    :return: base64 string
    """
    base64_bytes = base64.b64encode(string_data.encode('utf-8'))
    encrypted_bytes = get_crypter().encrypt(base64_bytes)
    return base64.b64encode(encrypted_bytes).decode('utf-8')


def decrypt(base64_string):
    """
    :param base64_string:
    :return: string data
    """
    encrypted_bytes = base64.b64decode(base64_string.encode('utf-8'))
    for i in range(2):
        try:
            decrypted_bytes = get_crypter(-i).decrypt(encrypted_bytes)
            return base64.b64decode(decrypted_bytes).decode('utf-8')
        except:
            pass
    return ''
