#-*-coding:utf-8-*-
from scapy.all import *
import difflib, httplib, itertools, optparse, random, re, urllib, urllib2, urlparse
def _ip_scan(dstip):
    a=sr1(IP(dst=dstip)/ICMP())
    print "ttl is:"+a[IP].ttl
    if a:
        if a[IP].ttl<=64:
            print "host is Linux/unix"
        else:
            print "host is windows"
    else:
        print "sth error"
if __name__ == "__main__":
    parser = optparse.OptionParser()
    parser.add_option("--ip",  dest="ip", help="dst ip")
    options, _ = parser.parse_args()
    if options.ip:
        _ip_scan(options.ip)
    else:
        parser.print_help()