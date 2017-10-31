#!/usr/bin/python3.4
# -*- coding=utf-8 -*-
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)#清除报错
from scapy.all import *
import difflib, httplib, itertools, optparse, random, re, urllib, urllib2, urlparse
#配置各种信息，以便调用
def _arp_scan(localip,localmac):
    ip_list = []
    prefix = localip.split('.')
    for i in range(254):  # 0到253
        ipno = prefix[0] + '.' + prefix[1] + '.' + prefix[2] + '.' + str(i + 1)  # 需要把i+1,这样就是1-254
        ip_list.append(ipno)  # 把IP地址添加到扫描清单
    #######################源MAC为本地MAC####目的MAC为广播#########操作码为1（请求）#######################################################由于多个网卡所以需要指派iface###########
    result_raw = srp(Ether(src=localmac, dst='FF:FF:FF:FF:FF:FF')/ARP(op=1, hwsrc=localmac, hwdst='00:00:00:00:00:00', psrc=localip, pdst=ip_list), verbose = False)
    result_list = result_raw[0].res #res: the list of packets，产生由收发数据包所组成的清单（list）
    IP_MAC_LIST = []
    for n in range(len(result_list)):  # len(result_list)表示响应数据包对的数量
        IP = result_list[n][1][1].fields['psrc']  # 提取响应包，ARP头部中的['psrc']字段，这是IP地址
        MAC = result_list[n][1][1].fields['hwsrc']  # 提取响应包，ARP头部中的['hwsrc']字段，这是MAC地址
        print('IP地址: ' + IP + ' MAC地址: ' + MAC)
if __name__ == "__main__":
    parser = optparse.OptionParser(version=VERSION)
    parser.add_option("--ip",  dest="ip", help="source ip")
    parser.add_option("--mac", dest="mac", help="souce mac")
    options, _ = parser.parse_args()
    if options.ip and options.mac:
        _arp_scan(options.ip,options.mac)
    else:
        parser.print_help()