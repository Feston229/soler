# python 3.8

from Cryptodome.Cipher import AES
import argparse
import getpass
import os


class Soler:
    def __init__(self, BLOCK_SIZE=32):
        self.set_block_size(BLOCK_SIZE)

    def set_block_size(self, BLOCK_SIZE):
        if BLOCK_SIZE in [16, 24, 32]:
            self.BLOCK_SIZE = BLOCK_SIZE
        else:
            raise Exception()

    def pad(self, s):
        return s + (self.BLOCK_SIZE - len(s) % self.BLOCK_SIZE) * chr(
            self.BLOCK_SIZE - len(s) % self.BLOCK_SIZE
        )

    def encrypt_file(self, file_in, key):
        try:
            if len(key) < self.BLOCK_SIZE:
                key = self.pad(key)
            else:
                key = key[: self.BLOCK_SIZE]
            key = bytes(key, "utf-8")
            cipher = AES.new(key, AES.MODE_EAX)
            ciphertext, tag = cipher.encrypt_and_digest(open(file_in, "rb").read())
            file_out = open(file_in + ".bin", "wb")
            [file_out.write(x) for x in (cipher.nonce, tag, ciphertext)]
            file_out.close()
            os.remove(file_in)
        except Exception as exc:
            raise exc

    def decrypt_file(self, filename, key):
        try:
            file_in = open(filename, "rb")
            nonce, tag, ciphertext = [file_in.read(x) for x in (16, 16, -1)]
            cipher = AES.new(bytes(self.pad(key), "utf-8"), AES.MODE_EAX, nonce)
            data = cipher.decrypt_and_verify(ciphertext, tag)
            file_out = open(filename[:-4], "wb")
            file_out.write(data)
            os.remove(filename)
        except Exception as exc:
            raise exc


def _parser():
    parser = argparse.ArgumentParser(
        description="Encrypt and decrypt files via AES-256"
    )
    parser.add_argument("-e", "--encrypt", type=str, help="encrypt file")
    parser.add_argument("-d", "--decrypt", type=str, help="decrypt file")
    parser.add_argument(
        "-b",
        "--block",
        type=int,
        help="define block size: 16, 24 or 32",
        choices=(16, 24, 32),
    )
    return parser.parse_args()


if __name__ == "__main__":
    soler = Soler()
    args = _parser()
    if args.block:
        soler = Soler(args.block)
    if args.encrypt:
        soler.encrypt_file(args.encrypt, getpass.getpass("Enter your password:"))
        print("Encrypted!")
    if args.decrypt:
        soler.decrypt_file(args.decrypt, getpass.getpass("Enter your password:"))
        print("Decrypted!")
