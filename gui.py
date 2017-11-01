#-*- coding:utf-8 -*-
__author__ = "Neil"
__time__ = "2017/10/31 23:49"

from Tkinter import *
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)#清除报错
from scapy.all import *
import difflib, httplib, itertools, optparse, random, re, urllib, urllib2, urlparse
_headers = {}
NAME, VERSION, AUTHOR, LICENSE = " seu srtp sql scanner ", "0.2y", "Neil", "Public domain (FREE)"
PREFIXES, SUFFIXES = (" ", ") ", "' ", "') "), ("", "-- -", "#", "%%16")            # prefix/suffix values used for building testing blind payloads
TAMPER_SQL_CHAR_POOL = ('(', ')', '\'', '"',"'")                                        # characters used for SQL tampering/poisoning of parameter values
BOOLEAN_TESTS = ("AND %d=%d", "OR NOT (%d>%d)")
# boolean tests used for building testing blind payloads
COOKIE, UA, REFERER = "Cookie", "User-Agent", "Referer"                             # optional HTTP header names
GET, POST = "GET", "POST"                                                           # enumerator-like values used for marking current phase
TEXT, HTTPCODE, TITLE, HTML = xrange(4)                                             # enumerator-like values used for marking content type
FUZZY_THRESHOLD = 0.95                                                              # ratio value in range (0,1) used for distinguishing True from False responses
TIMEOUT = 30                                                                        # connection timeout in seconds
RANDINT = random.randint(1, 255)                                                    # random integer value used across all tests
BLOCKED_IP_REGEX = r"(?i)(\A|\b)IP\b.*\b(banned|blocked|bl(a|o)ck\s?list|firewall)" # regular expression used for recognition of generic firewall blocking messages
SMALLER_CHAR_POOL    = ('<', '>')                                                           # characters used for XSS tampering of parameter values (smaller set - for avoiding possible SQLi errors)
LARGER_CHAR_POOL     = ('\'', '"', '>', '<', ';')                                           # characters used for XSS tampering of parameter values (larger set)
DOM_FILTER_REGEX = r"(?s)<!--.*?-->|\bescape\([^)]+\)|\([^)]+==[^(]+\)|\"[^\"]+\"|'[^']+'"  # filtering regex used before DOM XSS search
#在这里添加xss样式
REGULAR_PATTERNS = (                                                                        # each (regular pattern) item consists of (r"context regex", (prerequisite unfiltered characters), "info text", r"content removal regex")
    (r"\A[^<>]*%(chars)s[^<>]*\Z", ('<', '>'), "\".xss.\", pure text response, %(filtering)s filtering", None),#纯文本返回
    (r"<!--[^>]*%(chars)s|%(chars)s[^<]*-->", ('<', '>'), "\"<!--.'.xss.'.-->\", inside the comment, %(filtering)s filtering", None),#嵌在评论里
    (r"(?s)<script[^>]*>[^<]*?'[^<']*%(chars)s|%(chars)s[^<']*'[^<]*</script>", ('\'', ';'), "\"<script>.'.xss.'.</script>\", enclosed by <script> tags, inside single-quotes, %(filtering)s filtering", None),
    (r'(?s)<script[^>]*>[^<]*?"[^<"]*%(chars)s|%(chars)s[^<"]*"[^<]*</script>', ('"', ';'), "'<script>.\".xss.\".</script>', enclosed by <script> tags, inside double-quotes, %(filtering)s filtering", None),
    (r"(?s)<script[^>]*>[^<]*?%(chars)s|%(chars)s[^<]*</script>", (';',), "\"<script>.xss.</script>\", enclosed by <script> tags, %(filtering)s filtering", None),
    (r">[^<]*%(chars)s[^<]*(<|\Z)", ('<', '>'), "\">.xss.<\", outside of tags, %(filtering)s filtering", r"(?s)<script.+?</script>|<!--.*?-->"),
    (r"<[^>]*'[^>']*%(chars)s[^>']*'[^>]*>", ('\'',), "\"<.'.xss.'.>\", inside the tag, inside single-quotes, %(filtering)s filtering", r"(?s)<script.+?</script>|<!--.*?-->"),
    (r'<[^>]*"[^>"]*%(chars)s[^>"]*"[^>]*>', ('"',), "'<.\".xss.\".>', inside the tag, inside double-quotes, %(filtering)s filtering", r"(?s)<script.+?</script>|<!--.*?-->"),
    (r"<[^>]*%(chars)s[^>]*>", (), "\"<.xss.>\", inside the tag, outside of quotes, %(filtering)s filtering", r"(?s)<script.+?</script>|<!--.*?-->"),
)
DOM_PATTERNS = (                                                                            # each (dom pattern) item consists of r"recognition regex"
    r"(?s)<script[^>]*>[^<]*?(var|\n)\s*(\w+)\s*=[^;]*(document\.(location|URL|documentURI)|location\.(href|search)|window\.location)[^;]*;[^<]*(document\.write(ln)?\(|\.innerHTML\s*=|eval\(|setTimeout\(|setInterval\(|location\.(replace|assign)\(|setAttribute\()[^;]*\2.*?</script>",
    r"(?s)<script[^>]*>[^<]*?(document\.write\(|\.innerHTML\s*=|eval\(|setTimeout\(|setInterval\(|location\.(replace|assign)\(|setAttribute\()[^;]*(document\.(location|URL|documentURI)|location\.(href|search)|window\.location).*?</script>",
)

DBMS_ERRORS = {                                                                     # regular expressions used for DBMS recognition based on error message response
    "MySQL": (r"SQL syntax.*MySQL", r"Warning.*mysql_.*", r"valid MySQL result", r"MySqlClient\."),
    "PostgreSQL": (r"PostgreSQL.*ERROR", r"Warning.*\Wpg_.*", r"valid PostgreSQL result", r"Npgsql\."),
    "Microsoft SQL Server": (r"Driver.* SQL[\-\_\ ]*Server", r"OLE DB.* SQL Server", r"(\W|\A)SQL Server.*Driver", r"Warning.*mssql_.*", r"(\W|\A)SQL Server.*[0-9a-fA-F]{8}", r"(?s)Exception.*\WSystem\.Data\.SqlClient\.", r"(?s)Exception.*\WRoadhouse\.Cms\."),
    "Microsoft Access": (r"Microsoft Access Driver", r"JET Database Engine", r"Access Database Engine"),
    "Oracle": (r"\bORA-[0-9][0-9][0-9][0-9]", r"Oracle error", r"Oracle.*Driver", r"Warning.*\Woci_.*", r"Warning.*\Wora_.*"),
    "IBM DB2": (r"CLI Driver.*DB2", r"DB2 SQL error", r"\bdb2_\w+\("),
    "SQLite": (r"SQLite/JDBCDriver", r"SQLite.Exception", r"System.Data.SQLite.SQLiteException", r"Warning.*sqlite_.*", r"Warning.*SQLite3::", r"\[SQLITE_ERROR\]"),
    "Sybase": (r"(?i)Warning.*sybase.*", r"Sybase message", r"Sybase.*Server message.*"),
}


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
tcp_button=Button(root,text="开始端口扫描",command = lambda : _scan_port(tcp_ip.get(),int(tcp_port.get())))
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
sql_button=Button(root,text="开始sql漏洞扫描",command = lambda : sql(sql_url.get(),sql_post.get(),sql_cookie.get()))
xss_button=Button(root,text="开始xss漏洞扫描",command = lambda : xss(sql_url.get(),sql_post.get(),sql_cookie.get()))
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
    _ip_scan(dst_ip)
    if(str(type(stealth_scan_resp))==""):
        result_listbox.insert(END,str(dst_ip)+" port"+str(dst_port)+"Filtered")
    elif(stealth_scan_resp.haslayer(TCP)):
        if(stealth_scan_resp.getlayer(TCP).flags == 0x12):
            send_rst = sr(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="R"),timeout=10)
            result_listbox.insert(END," port"+str(dst_port)+" is Open")
        elif (stealth_scan_resp.getlayer(TCP).flags == 0x14):
            result_listbox.insert(END," port"+str(dst_port)+" is Closed")
    elif(stealth_scan_resp.haslayer(ICMP)):
        if(int(stealth_scan_resp.getlayer(ICMP).type)==3 and int(stealth_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
            result_listbox.insert(END,"port"+str(dst_port)+"is Filtered")


def _ip_scan(dstip):
    a=sr1(IP(dst=dstip)/ICMP())
    result_listbox.insert("ttl is:"+str(a[IP].ttl))
    if a:
        if a[IP].ttl<=64:
            result_listbox.insert(END,"host is Linux/unix")
        else:
            result_listbox.insert(END,"host is windows")
    else:
        result_listbox.insert(END,"sth error!!!may be filtered")


def _retrieve_content(url, data=None):
    retval = {HTTPCODE: httplib.OK}
    try:
        req = urllib2.Request("".join(url[_].replace(' ', "%20") if _ > url.find('?') else url[_]  for _ in xrange(len(url))), data, globals().get("_headers", {}))
        retval[HTML] = urllib2.urlopen(req,timeout=TIMEOUT).read()
    except Exception as ex:
        retval[HTTPCODE] = getattr(ex,"code", None)
        retval[HTML] = ex.read() if hasattr(ex, "read") else getattr(ex, "msg", "")
    retval[HTML] = "" if re.search(BLOCKED_IP_REGEX, retval[HTML]) else retval[HTML]
    retval[HTML] = re.sub(r"(?i)[^>]*(AND|OR)[^<]*%d[^<]*" % RANDINT, "__REFLECTED__",retval[HTML])
    match = re.search(r"<title>(?P<result>[^<]+)</title>", retval[HTML], re.I)
    retval[TITLE] = match.group("result") if match and "result" in match.groupdict() else None
    retval[TEXT] = re.sub(r"(?si)<script.+?</script>|<!--.+?-->|<style.+?</style>|<[^>]+>|\s+", " ", retval[HTML])
    return retval


def scan_page(url, data=None):
    retval, usable = False, False
    url, data = re.sub(r"=(&|\Z)", "=1\g<1>", url) if url else url, re.sub(r"=(&|\Z)", "=1\g<1>", data) if data else data
    try:
        for phase in (GET, POST):
            original, current = None, url if phase is GET else (data or "")
            for match in re.finditer(r"((\A|[?&])(?P<parameter>[^_]\w*)=)(?P<value>[^&#]+)", current):# 找到每一个参数
                vulnerable, usable = False,True
                print "*scanning %s parameter '%s'" % (phase,match.group("parameter"))
                original = original or (_retrieve_content(current, data) if phase is GET else _retrieve_content(url, current))#获取原始页面
                tampered = current.replace(match.group(0), "%s%s" % (match.group(0), urllib.quote("".join(random.sample(TAMPER_SQL_CHAR_POOL, len(TAMPER_SQL_CHAR_POOL))))))#更改后缀
                content = _retrieve_content(tampered, data) if phase is GET else _retrieve_content(url , tampered)
                for (dbms, regex) in ((dbms, regex) for dbms in DBMS_ERRORS for regex in DBMS_ERRORS[dbms]):
                    if not vulnerable and re.search(regex, content[HTML], re.I) and not re.search(regex, original[HTML], re.I):
                        result_listbox.insert(END,"(i) %s parameter '%s' appears to be error SQLi vulnerable (%s)" % (phase, match.group("parameter"), dbms))#检查返回页面的错误
                        retval = vulnerable = True
                vulnerable = False
                for prefix, boolean, suffix,inline_comment in itertools.product(PREFIXES, BOOLEAN_TESTS, SUFFIXES, (False,True)):#盲注,以及控制结果是真还是假
                    if not vulnerable:
                        template = ("%s%s%s" % (prefix, boolean, suffix)).replace(" " if inline_comment else "/**/", "/**/")#全部改为内联注释
                        payloads = dict((_ , current.replace(match.group(0),"%s%s" % (match.group(0), urllib.quote(template % (RANDINT if _ else RANDINT + 1, RANDINT), safe='%')))) for _ in (True, False))#一个参数是真，一个参数是假
                        contents = dict((_ , _retrieve_content(payloads[_], data) if phase is GET else _retrieve_content(url, payloads[_])) for _ in (False,True))
                        if all(_[HTTPCODE] and _[HTTPCODE] < httplib.INTERNAL_SERVER_ERROR for _ in (original, contents[True], contents[False])):
                            if any(original[_] == contents[True][_] != contents[False][_] for _ in (HTTPCODE, TITLE)):
                                vulnerable = True
                            else:
                                ratios = dict((_, difflib.SequenceMatcher(None, original[TEXT], contents[_][TEXT]).quick_ratio()) for _ in (False, True))#找到条件为真假与原网页的差异。
                                vulnerable = all(ratios.values()) and min(ratios.values()) < FUZZY_THRESHOLD < max(ratios.values()) and abs(ratios[True] - ratios[False]) > FUZZY_THRESHOLD / 10
                        if vulnerable:
                            result_listbox.insert(END," (i) %s parameter '%s' appears to be blind SQLi vulnerable (e.g.: '%s')" % (phase, match.group("parameter"), payloads[True]))
                            retval = True
        if not usable:
            result_listbox.insert(END," (x) no usable GET/POST parameters found")
    except KeyboardInterrupt:
        print "\r (x) Ctrl-C pressed"
    return retval

def init_options(proxy=None, cookie=None, ua=None, referer=None):
    globals()["_headers"] = dict(filter(lambda  _ : _[1] , ((COOKIE, cookie.replace('"','')), (UA, ua or NAME), (REFERER , referer))))#筛选有值的参数
    urllib2.install_opener(urllib2.build_opener(urllib2.ProxyHandler({'http': proxy})) if proxy else None)

def sql(url,data=None,cookie=None):
    global result_listbox
    result_listbox.delete(0, END)
    init_options(None, cookie, None, None)
    result = scan_page(url if url.startswith("http") else "http://%s" % url,data)
    result_listbox.insert(END,"scan results: %s vulnerabilities found" % ("possible" if result else "no"))


def _retrieve_content_xss(url, data=None):
    try:
        req = urllib2.Request("".join(url[i].replace(' ', "%20") if i > url.find('?') else url[i] for i in xrange(len(url))), data, _headers)
        retval = urllib2.urlopen(req, timeout=TIMEOUT).read()
    except Exception, ex:
        retval = ex.read() if hasattr(ex, "read") else getattr(ex, "msg", str())
    return retval or ""

def _contains(content, chars):
    content = re.sub(r"\\[%s]" % re.escape("".join(chars)), "", content) if chars else content
    return all(char in content for char in chars)


def scan_page_xss(url, data=None):
    retval, usable = False, False
    url, data = re.sub(r"=(&|\Z)", "=1\g<1>", url) if url else url, re.sub(r"=(&|\Z)", "=1\g<1>", data) if data else data
    original = re.sub(DOM_FILTER_REGEX, "", _retrieve_content_xss(url, data))
    dom = max(re.search(_ ,original) for _ in DOM_PATTERNS)#检查 dom xss
    if dom:
        result_listbox.insert(END," (i) page itself appears to be XSS vulnerable (DOM)")
        result_listbox.insert(END,"  (o) ...%s..." % dom.group(0))
        retval = True
    try:
        for phase in (GET, POST):
            current = url if phase is GET else (data or "")
            for match in re.finditer(r"((\A|[?&])(?P<parameter>[\w\[\]]+)=)(?P<value>[^&#]*)", current):#匹配出参数
                found, usable = False, True
                result_listbox.insert(END,"* scanning %s parameter '%s'" % (phase, match.group("parameter")))
                prefix, suffix = ("".join(random.sample(string.ascii_lowercase, PREFIX_SUFFIX_LENGTH)) for i in xrange(2))#随机产生字符串
                for pool in (LARGER_CHAR_POOL, SMALLER_CHAR_POOL):
                    if not found:
                        tampered = current.replace(match.group(0), "%s%s" % (match.group(0), urllib.quote("%s%s%s%s" % ("'" if pool == LARGER_CHAR_POOL else "", prefix, "".join(random.sample(pool, len(pool))), suffix))))
                        content = (_retrieve_content_xss(tampered, data) if phase is GET else _retrieve_content_xss(url, tampered)).replace("%s%s" % ("'" if pool == LARGER_CHAR_POOL else "", prefix), prefix)
                        for sample in re.finditer("%s([^ ]+?)%s" % (prefix, suffix), content, re.I):#匹配字符串中间
                            for regex, condition, info, content_removal_regex in REGULAR_PATTERNS:
                                context = re.search(regex % {"chars": re.escape(sample.group(0))}, re.sub(content_removal_regex or "", "", content), re.I)#寻找到xss注入点
                                if context and not found and sample.group(1).strip():
                                    if _contains(sample.group(1), condition):#确定一些必须的字符没有过滤掉
                                        result_listbox.insert(END," (i) %s parameter '%s' appears to be XSS vulnerable (%s)" % (phase, match.group("parameter"), info % dict((("filtering", "no" if all(char in sample.group(1) for char in LARGER_CHAR_POOL) else "some"),))))
                                        found = retval = True
                                    break

        if not usable:
            result_listbox.insert(END," (x) no usable GET/POST parameters found")
    except KeyboardInterrupt:
        print "\r (x) Ctrl-C pressed"
    return retval

def xss(url,data=None,cookie=None):
    global result_listbox
    result_listbox.delete(0, END)
    init_options(None, cookie, None, None)
    result = scan_page(url if url.startswith("http") else "http://%s" % url,data)
    result_listbox.insert(END,"scan results: %s vulnerabilities found" % ("possible" if result else "no"))

mainloop()
