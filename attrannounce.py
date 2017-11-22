#!/usr/bin/python

from sys import stdout
from time import sleep


prefixes = ['192.168.0.0/24',]


def gen_key_attr(prefix):
    # TODO: generate the crypto-based value
    return '0x'+('0010000000000001'*4) # return static example now - 32 bytes

def main():
    sleep(5)

    message = 'announce route %s next-hop self attribute [0x40 0xe0 %s] \n'
    for p in prefixes:
        stdout.write(message % (p, gen_key_attr(p)))
        stdout.flush()
        sleep(1)

    while True:
        sleep(1) # keep running, do nothing so ExaBGP keeps running



if __name__ == '__main__':
    main()

