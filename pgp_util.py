""" pgp_util.py

this is where the armorable PGP block objects live
"""

from pathlib import Path
from typing import Final

from pgpy import PGPKey
from pgpy import PGPMessage
from pgpy import PGPUID
from pgpy.constants import CompressionAlgorithm
from pgpy.constants import HashAlgorithm
from pgpy.constants import KeyFlags
from pgpy.constants import PubKeyAlgorithm
from pgpy.constants import SymmetricKeyAlgorithm


class PGPUtil:
    """
    Util Class for PGP
    """
    __PRIVATE_KEY: Final = 'keys/pv.asc'
    __PUBLIC_KEY: Final = 'keys/pb.asc'
    __PASSPHRASE_FILE: Final = 'keys/passphrase.asc'
    __pass_phrase = 'C0rrectPassphr@se'
    __key_pair = None

    def __init__(self):
        if Path(self.__PASSPHRASE_FILE).is_file():
            with open(self.__PASSPHRASE_FILE, 'r') as file:
                self.__pass_phrase = file.readline().strip()

    def get_keys(self):
        """
        we can start by generating a primary key. For this example,
        we'll use RSA, but it could be DSA or ECDSA as well
        """
        if not Path(self.__PRIVATE_KEY).is_file() and not Path(self.__PUBLIC_KEY).is_file():
            self.__key_pair = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 4096)

            name = 'Trideep'
            comment = 'Trideep Chatterjee'
            email = 'trideep@gmail.com'
            uid = PGPUID.new(name, comment=comment, email=email)
            usage = {
                KeyFlags.Sign,
                KeyFlags.EncryptCommunications,
                KeyFlags.EncryptStorage
            }
            hashes = [
                HashAlgorithm.SHA256,
                HashAlgorithm.SHA384,
                HashAlgorithm.SHA512,
                HashAlgorithm.SHA224
            ]
            ciphers = [
                SymmetricKeyAlgorithm.AES256,
                SymmetricKeyAlgorithm.AES192,
                SymmetricKeyAlgorithm.AES128
            ]
            compression = [
                CompressionAlgorithm.ZLIB,
                CompressionAlgorithm.BZ2,
                CompressionAlgorithm.ZIP,
                CompressionAlgorithm.Uncompressed
            ]

            self.__key_pair.add_uid(
                uid, usage=usage, hashes=hashes,
                ciphers=ciphers, compression=compression
            )
            self.__key_pair.protect(
                self.__pass_phrase,
                SymmetricKeyAlgorithm.AES256,
                HashAlgorithm.SHA256
            )

    def write_keys_to_file(self):
        """
        Writes asymmetric key pair to files
        Returns:

        """
        if not Path(self.__PRIVATE_KEY).is_file():
            with open(self.__PRIVATE_KEY, 'w') as file:
                file.write(str(self.__key_pair))
        if not Path(self.__PUBLIC_KEY).is_file():
            with open(self.__PUBLIC_KEY, 'w') as file:
                file.write(str(self.__key_pair.pubkey))
        if not Path(self.__PASSPHRASE_FILE).is_file():
            with open(self.__PASSPHRASE_FILE, 'w') as file:
                file.write(self.__pass_phrase)

    def encrypt(self, str_message):
        """
        Encrypts a message using public key
        Args:
            str_message: Should be a string or an instance of PGPMessage

        Returns: Encrypted message

        """
        public_key = PGPKey.from_file(self.__PUBLIC_KEY)[0]
        print(public_key.is_public)
        encrypted_message = public_key.encrypt(PGPMessage.new(str_message))
        print("is msg encrypted: ", encrypted_message.is_encrypted)
        print("encrypted msg: \n", encrypted_message)
        print("message encrypted")
        return encrypted_message

    def decrypt(self, enc_message):
        """
        Decrypts a encrypted message using private key
        Args:
            enc_message: can be a string or an instance of PGPMessage

        Returns: Decrypted message

        """
        private_key = PGPKey.from_file(self.__PRIVATE_KEY)[0]
        if not isinstance(enc_message, PGPMessage):
            enc_message = PGPMessage.from_blob(enc_message)
        assert private_key.is_protected
        with private_key.unlock(self.__pass_phrase):
            assert private_key.is_unlocked
            decrypted_message = private_key.decrypt(enc_message)
            print("is msg encrypted: ", decrypted_message.is_encrypted)
            print("decrypted msg: ", decrypted_message.message)
            print("message decrypted")
        return decrypted_message.message
