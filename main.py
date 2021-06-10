from pgp_util import PGPUtil


class Main(object):
    pgp = None

    def __init__(self):
        self.pgp = PGPUtil()

    def encrypt_decrypt(self, message):
        self.pgp.get_keys()
        self.pgp.write_keys_to_file()
        enc_msg = self.pgp.encrypt(message)
        return self.pgp.decrypt(enc_msg)


if __name__ == '__main__':
    msg = "This is a test message to encrypt"
    main = Main()
    assert main.encrypt_decrypt(msg) == msg
