#!/usr/bin/python

from sys import stdout
from time import sleep
import donna25519


prefixes = ['192.168.0.0/24',]




def gen_key_attr():
    # TODO: generate the crypto-based value
    private_key = donna25519.PrivateKey()
    priv_key_str = private_key.private
    pub_key_str = private_key.get_public().public
    return priv_key_str, pub_key_str


#    return '0x'+('0010000000000001'*4) # return static example now - 32 bytes

def main():
    sleep(5)
    message = 'announce route %s next-hop self attribute [0x40 0xe0 %s] \n'
    for p in prefixes:
        private_key, public_key = gen_key_attr()
        stdout.write(message % (p, public_key))
        stdout.flush()
        sleep(1)

    while True:
        sleep(1) # keep running, do nothing so ExaBGP keeps running



if __name__ == '__main__':
    main()

