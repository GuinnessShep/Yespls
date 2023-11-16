import os
import sys
import ssl
import re
import time
import random
import threading
import requests
import hashlib
import json
from urllib3.exceptions import InsecureRequestWarning
from http import cookiejar
from pystyle import *
from urllib.parse import urlencode

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
ssl._create_default_https_context = ssl._create_unverified_context

class BlockCookies(cookiejar.CookiePolicy):
    return_ok = set_ok = domain_return_ok = path_return_ok = lambda self, *args, **kwargs: False
    netscape = True
    rfc2965 = hide_cookie2 = False

r = requests.Session()
r.cookies.set_policy(BlockCookies())

__domains = ["api22-core-c-useast1a.tiktokv.com", "api19-core-c-useast1a.tiktokv.com",
             "api16-core-c-useast1a.tiktokv.com", "api21-core-c-useast1a.tiktokv.com",
             "api16-va.tiktokv.com"]
__devices = ["SM-G9900", "SM-A136U1", "SM-M225FV", "SM-E426B", "SM-M526BR", "SM-M326B",
             "SM-A528B", "SM-F711B", "SM-F926B", "SM-A037G", "SM-A225F", "SM-M325FV",
             "SM-A226B", "SM-M426B", "SM-A525F", "SM-N976N", "SM-G973N"]
__versions = ["190303", "190205", "190204", "190103", "180904", "180804", "180803",
              "180802", "270204", "160904"]

class Gorgon:
    def __init__(self, params: str, data: str, cookies: str, unix: int) -> None:
        self.unix = unix
        self.params = params
        self.data = data
        self.cookies = cookies

    def hash(self, data: str) -> str:
        try:
            _hash = str(hashlib.md5(data.encode()).hexdigest())
        except Exception:
            _hash = str(hashlib.md5(data).hexdigest())
        return _hash

    def get_base_string(self) -> str:
        base_str = self.hash(self.params)
        base_str = base_str + self.hash(self.data) if self.data else base_str + str('0' * 32)
        base_str = base_str + self.hash(self.cookies) if self.cookies else base_str + str('0' * 32)
        return base_str

    def get_value(self) -> json:
        base_str = self.get_base_string()
        return self.encrypt(base_str)

    def encrypt(self, data: str) -> json:
        unix = self.unix
        length = 20
        key = [223, 119, 185, 64, 185, 155, 132, 131, 209, 185, 203, 209, 247, 194, 185, 133, 195, 208, 251, 195]
        param_list = []
        for i in range(0, 12, 4):
            temp = data[8 * i:8 * (i + 1)]
            for j in range(4):
                H = int(temp[j * 2:(j + 1) * 2], 16)
                param_list.append(H)
            param_list.extend([0, 6, 11, 28])
            H = int(hex(unix), 16)
            param_list.extend([(H & 4278190080) >> 24, (H & 16711680) >> 16, (H & 65280) >> 8, H & 255])
        eor_result_list = [A ^ B for A, B in zip(param_list, key)]
        for i in range(length):
            D = eor_result_list[(i + 1) % length]
            E = 255 ^ D
            H = (E ^ 4294967295 ^ length) & 255
            eor_result_list[i] = H
        result = ''.join([format(param, '02x') for param in eor_result_list])
        return {'X-Gorgon': '0404b0d30000' + result, 'X-Khronos': str(unix)}

def send(did, iid, cdid, openudid):
    global reqs, _lock, success, fails    
    for x in range(10):
        try:
            version = random.choice(__versions)
            device = random.choice(__devices)
            params = urlencode({
                "device_id": did,
                "iid": iid,
                "device_type": device,
                "app_name": "musically_go",
                "channel": "googleplay",
                "device_platform": "android",
                "version_code": version,
                "device_brand": "samsung",
                "os_version": "9",
                "aid": "1340"
            })
            payload = f"item_id={__aweme_id}&play_delta=1"
            sig = Gorgon(params=params, cookies=None, data=None, unix=int(time.time())).get_value()
            proxy = random.choice(proxies) if config['proxy']['use-proxy'] else ""
            response = r.post(
                url="https://" + random.choice(__domains) + "/aweme/v1/aweme/stats/?" + params,
                data=payload,
                headers={'cookie': 'sessionid=90c38a59d8076ea0fbc01c8643efbe47', 'x-gorgon': sig['X-Gorgon'],
                         'x-khronos': sig['X-Khronos'], 'user-agent': 'okhttp/3.10.0.1'},
                verify=False,
                proxies={"http": proxy_format + proxy, "https": proxy_format + proxy} if config['proxy']['use-proxy'] else {}
            )
            reqs += 1
            try:
                _lock.acquire()
                print(Colorate.Horizontal(Colors.green_to_white, f"+ - sent views {response.json()['log_pb']['impr_id']} {__aweme_id} {reqs}"))
                _lock.release()
                success += 1
            except:
                if _lock.locked(): _lock.release()
                fails += 1
                continue
        except Exception as e:
            pass

def rpsm_loop():
    global rps, rpm
    while True:
        initial = reqs
        time.sleep(1.5)
        rps = round((reqs - initial) / 1.5, 1)
        rpm = round(rps * 60, 1)

def title_loop():
    global rps, rpm, success, fails, reqs
    if os.name == "nt":
        while True:
            os.system(f'title TikTok by @guinnessgshep ^| success: {success} fails: {fails} reqs: {reqs} rps: {rps} rpm: {rpm}')
            time.sleep(0.1)

def fetch_proxies():
    url_list = [
        "https://raw.githubusercontent.com/yemixzy/proxy-list/main/proxy-list/data.txt",
        "https://raw.githubusercontent.com/UptimerBot/proxy-list/main/proxies/http.txt",
        "https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies/http.txt",
        "https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies/socks4.txt",
        "https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies/socks5.txt"        
    ]
    for url in url_list:
        response = requests.get(url=url)
        if response.ok:
            with open("proxies.txt", "a+") as f:
                f.write(response.text)
                f.close()

if __name__ == "__main__":
    os.system("cls" if os.name == "nt" else "clear")
    print(Colorate.Vertical(Colors.DynamicMIX((Col.light_blue, Col.purple)), Center.XCenter("TikTok ViewBot by Guinnes")))
    try:
        link = str(Write.Input("\n\nTikTok ViewBot by Guinnes - Paste tiktok video URL here ==>: ", Colors.yellow_to_red, interval=0.0001))
        __aweme_id = str(
            re.findall(r"(\d{18,19})", link)[0]
            if len(re.findall(r"(\d{18,19})", link)) == 1
            else re.findall(
                r"(\d{18,19})", requests.head(link, allow_redirects=True, timeout=5).url
            )[0]
        )
        thread_count = int(input("Enter the number of threads you'd like to run: "))
    except:
        os.system("cls" if os.name == "nt" else "clear")
        input(Col.red + "x - paste your url, please  " + Col.reset)
        sys.exit(0)
    os.system("cls" if os.name == "nt" else "clear")
    print("Loading.....")
    _lock = threading.Lock()
    reqs = 0
    success = 0
    fails = 0
    rpm = 0
    rps = 0
    threading.Thread(target=rpsm_loop).start()
    threading.Thread(target=title_loop).start()
    with open('devices.txt', 'r') as f:
        devices = f.read().splitlines()
    with open('config.json', 'r') as f:
        config = json.load(f)
    if config["proxy"]['proxyscrape']:
        fetch_proxies()
    proxy_format = (
        f'{config["proxy"]["proxy-type"].lower()}://{config["proxy"]["credential"] + "@" if config["proxy"]["auth"] else ""}'
        if config['proxy']['use-proxy'] else ''
    )
    if config['proxy']['use-proxy']:
        with open('proxies.txt', 'r') as f:
            proxies = f.read().splitlines()
    while True:
        device = random.choice(devices)
        if threading.active_count() < thread_count:
            did, iid, cdid, openudid = device.split(':')
            threading.Thread(target=send, args=[did, iid, cdid, openudid]).start()
