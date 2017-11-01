from scapy.all import *
import difflib, httplib, itertools, optparse, random, re, urllib, urllib2, urlparse
def _scan_port(dst_ip,dst_port):
    src_port = RandShort()
    stealth_scan_resp = sr1(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="S"),timeout=10)
    if(str(type(stealth_scan_resp))==""):
        print "Filtered"
    elif(stealth_scan_resp.haslayer(TCP)):
        if(stealth_scan_resp.getlayer(TCP).flags == 0x12):
            send_rst = sr(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="R"),timeout=10)
            print "Open"
        elif (stealth_scan_resp.getlayer(TCP).flags == 0x14):
            print "Closed"
    elif(stealth_scan_resp.haslayer(ICMP)):
        if(int(stealth_scan_resp.getlayer(ICMP).type)==3 and int(stealth_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
            print "Filtered"
if __name__ == "__main__":
    parser = optparse.OptionParser(version=VERSION)
    parser.add_option("--ip", dest="ip", help="Target ip")
    parser.add_option("--port", dest="port", help="POST port")
    options, _ = parser.parse_args()
    if options.ip and options.port:
        result = _scan_port(options.ip,(int)(options.port))
    else:
        parser.print_help()