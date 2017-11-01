#-*- coding:utf-8 -*-
__author__ = "Neil"
__time__ = "2017/10/31 23:49"

from Tkinter import *
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)#清除报错
from scapy.all import *
import difflib, httplib, itertools, optparse, random, re, urllib, urllib2, urlparse
root=Tk()
root.title("网络扫描器")
root.geometry("500x420")

result= Label(root,text = '扫描结果:',font=("",12))
result.grid(row=3,column=3,sticky=W,padx=5)
result_listbox=Listbox(root,height=7,width=30)
result_listbox.grid(row=4,column=3,padx=10,rowspan=7)
# for item in ['pythonsdasdadsadsasdadsasdasdasdasdasdasdasdasdasd','tkinter','widget']:
#     result_listbox.insert(END,item)
# result_list.delete(0,0)
arp_title= Label(root,text = 'arp扫描',font=("",13))
arp_mac_label= Label(root,text = 'mac 地址',font=("",10))
arp_ip_label= Label(root,text = 'ip 地址',font=("",10))
arp_title.grid(row=0,column=1)
arp_ip=Entry(root)
arp_mac=Entry(root)
arp_ip_label.grid(row=1,column=0)
arp_mac_label.grid(row=2,column=0)
arp_ip.grid(row=1,column=1,pady=5)
arp_mac.grid(row=2,column=1,pady=5)
# arp_list=Listbox(root,height=3)
# arp_list.grid(row=2,column=3,padx=10,rowspan=2)
arp_button=Button(root,text="开始arp扫描",command = lambda : _arp_scan(arp_ip.get(),arp_mac.get()))
arp_button.grid(row=3,column=1,sticky=W)


tcp_title= Label(root,text = 'tcp端口扫描',font=("",13))
#tcp_result= Label(root,text = '扫描结果:',font=("",12))
tcp_ip_label= Label(root,text = 'ip 地址',font=("",10))
tcp_port_label= Label(root,text = '端口号',font=("",10))
#tcp_result.grid(row=1,column=3,sticky=W,padx=5)
tcp_title.grid(row=5,column=1)
tcp_ip=Entry(root)
tcp_port=Entry(root)
tcp_ip_label.grid(row=6,column=0)
tcp_port_label.grid(row=7,column=0)
tcp_ip.grid(row=6,column=1,pady=5)
tcp_port.grid(row=7,column=1,pady=5)
# arp_list=Listbox(root,height=3)
# arp_list.grid(row=2,column=3,padx=10,rowspan=2)
tcp_button=Button(root,text="开始端口扫描")
tcp_button.grid(row=8,column=1,sticky=W)

sql_title= Label(root,text = '应用层漏洞扫描',font=("",13))
#tcp_result= Label(root,text = '扫描结果:',font=("",12))
sql_url_label= Label(root,text = 'url 地址',font=("",10))
sql_post_label= Label(root,text = '表单参数',font=("",10))
sql_cookie_label= Label(root,text = 'Cookie',font=("",10))
#tcp_result.grid(row=1,column=3,sticky=W,padx=5)
sql_title.grid(row=10,column=1)
sql_url=Entry(root)
sql_post=Entry(root)
sql_cookie=Entry(root)
sql_url_label.grid(row=11,column=0)
sql_post_label.grid(row=12,column=0)
sql_cookie_label.grid(row=13,column=0)
sql_url.grid(row=11,column=1,pady=5)
sql_post.grid(row=12,column=1,pady=5)
sql_cookie.grid(row=13,column=1,pady=5)
# arp_list=Listbox(root,height=3)
# arp_list.grid(row=2,column=3,padx=10,rowspan=2)
sql_button=Button(root,text="开始sql漏洞扫描")
xss_button=Button(root,text="开始xss漏洞扫描")
xss_button.grid(row=15,column=1,sticky=W)
sql_button.grid(row=14,column=1,sticky=W)

#配置各种信息，以便调用
def _arp_scan(localip,localmac):
    global result_listbox
    result_listbox.delete(0,END)
    ip_list = []
    prefix = localip.split('.')
    for i in range(254):  # 0到253
        ipno = prefix[0] + '.' + prefix[1] + '.' + prefix[2] + '.' + str(i + 1)  # 需要把i+1,这样就是1-254
        ip_list.append(ipno)  # 把IP地址添加到扫描清单
    #######################源MAC为本地MAC####目的MAC为广播#########操作码为1（请求）#######################################################由于多个网卡所以需要指派iface###########
    result_raw = srp(Ether(src=localmac, dst='FF:FF:FF:FF:FF:FF')/ARP(op=1, hwsrc=localmac, hwdst='00:00:00:00:00:00', psrc=localip, pdst=ip_list),timeout=1)
    result_list = result_raw[0].res #res: the list of packets，产生由收发数据包所组成的清单（list）
    IP_MAC_LIST = []
    for n in range(len(result_list)):  # len(result_list)表示响应数据包对的数量
        IP = result_list[n][1][1].fields['psrc']  # 提取响应包，ARP头部中的['psrc']字段，这是IP地址
        MAC = result_list[n][1][1].fields['hwsrc']  # 提取响应包，ARP头部中的['hwsrc']字段，这是MAC地址
        result_listbox.insert(END,'IP地址: ' + IP + ' MAC地址: ' + MAC)


def _scan_port(dst_ip,dst_port):
    global result_listbox
    result_listbox.delete(0, END)
    src_port = RandShort()
    stealth_scan_resp = sr1(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="S"),timeout=10)
    if(str(type(stealth_scan_resp))==""):
        result_listbox.insert(END,str(dst_ip)+" port"+str(dst_port)+"Filtered")
    elif(stealth_scan_resp.haslayer(TCP)):
        if(stealth_scan_resp.getlayer(TCP).flags == 0x12):
            send_rst = sr(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="R"),timeout=10)
            result_listbox.insert(END,str(dst_ip)+" port"+str(dst_port)+"Open")
        elif (stealth_scan_resp.getlayer(TCP).flags == 0x14):
            result_listbox.insert(END,str(dst_ip)+" port"+str(dst_port)+"Closed")
    elif(stealth_scan_resp.haslayer(ICMP)):
        if(int(stealth_scan_resp.getlayer(ICMP).type)==3 and int(stealth_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
            result_listbox.insert(END,str(dst_ip)+" port"+str(dst_port)+"Filtered")

mainloop()
