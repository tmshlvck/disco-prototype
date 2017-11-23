#!/usr/bin/python

import sys
from optparse import OptionParser
from datetime import *
from mrtparse import *

attrnum = 0x40
certify_threshold = 0.95

def parse_bgp4mp(m, askeys):
    if not m.bgp.msg:
        return

    if ( m.subtype == BGP4MP_ST['BGP4MP_MESSAGE']
        or m.subtype == BGP4MP_ST['BGP4MP_MESSAGE_AS4']
        or m.subtype == BGP4MP_ST['BGP4MP_MESSAGE_LOCAL']
        or m.subtype == BGP4MP_ST['BGP4MP_MESSAGE_AS4_LOCAL']):
        keys = list(parse_bgp_msg(m.bgp.msg, m.subtype))
    else:
        return

    if m.bgp.msg.nlri:
        for n in m.bgp.msg.nlri:
            plen = n.plen - (((len(n.label) * 3 + 8) * 8) if n.label else 0)
            prefix = "%s/%d" % (n.prefix, plen)
            if not prefix in askeys:
                askeys[prefix] = []
            askeys[prefix] += keys
    else:
        return


def parse_bgp_msg(msg, subtype):
    def get_key(attr):
        if attr.type == attrnum and attr.val:
            return "0x"+"".join("%02x" % ord(c) for c in attr.val)
        else:
            return None

    if msg.type == BGP_MSG_T['UPDATE']:
        match = False
        for attr in msg.attr:
             k = get_key(attr)
             if k:
                 match = True
                 yield k
        if not match:
            yield None


def resolve_certification(askeys):
    def group_count(keys):
        groups = {}
        for k in keys:
            if k in groups:
                groups[k]+=1
            else:
                groups[k]=1
        return groups

    def verify(counted_groups, total, prefix):
        for k in counted_groups:
            if counted_groups[k] > certify_threshold * total and k:
                print("Certified prefix %s with key %s (%.2f%%)" % (prefix, k, (100*float(counted_groups[k])/total)))
                return
        if len(counted_groups) > 1:
            print("Warning: Prefix %s announced with multiple keys:" % p)
            for k in counted_groups:
                print("%s (%.2f)" % (k, (float(counted_groups[k])/total)))

    for p in askeys:
        g = group_count(askeys[p])
        verify(g, len(askeys[p]), p)


def main():
    if len(sys.argv) < 2:
        print('Usage: %s <FILENAME> [FILENAME ...]' % sys.argv[0])
        exit(1)

    askeys = {}

    for f in sys.argv[1:]:
        d = Reader(f)

        for m in d:
            m = m.mrt
            if m.err == MRT_ERR_C['MRT Header Error']:
                print("MRT Header Error")
                continue
            elif ( m.type == MRT_T['BGP4MP']
                or m.type == MRT_T['BGP4MP_ET']):
                parse_bgp4mp(m, askeys)

    resolve_certification(askeys)

if __name__ == '__main__':
    main()

