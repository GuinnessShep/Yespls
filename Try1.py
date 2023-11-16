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
from urllib.parse import urlencode
from http import cookiejar
from pystyle import Colorate, Colors, Write, Col, Center
from urllib3.exceptions import InsecureRequestWarning

# Suppress SSL and Insecure Request Warnings
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
ssl._create_default_https_context = ssl._create_unverified_context

# Clear console
os.system("cls" if os.name == "nt" else "clear")

# Block Cookies
class BlockCookies(cookiejar.CookiePolicy):
    return_ok = set_ok = domain_return_ok = path_return_ok = lambda self, *args, **kwargs: False
    netscape = True
    rfc2965 = hide_cookie2 = False

# Session setup
r = requests.Session()
r.cookies.set_policy(BlockCookies())

__domains = ["api22-core-c-useast1a.tiktokv.com", "api19-core-c-useast1a.tiktokv.com", 
             "api16-core-c-useast1a.tiktokv.com", "api21-core-c-useast1a.tiktokv.com"]
__devices = ["SM-G9900", "SM-A136U1", "SM-M225FV", "SM-E426B", "SM-M526BR", "SM-M326B", 
             "SM-A528B", "SM-F711B", "SM-F926B", "SM-A037G", "SM-A225F", "SM-M325FV", 
             "SM-A226B", "SM-M426B", "SM-A525F", "SM-N976N"]
__versions = ["190303", "190205", "190204", "190103", "180904", "180804", 
              "180803", "180802", "270204"]

# Gorgon class
class Gorgon:
    def __init__(self, params: str, data: str = None, cookies: str = None, unix: int = None):
        self.params = params
        self.data = data
        self.cookies = cookies
        self.unix = unix or int(time.time())
    
    @staticmethod
    def hash(data: str) -> str:
        return hashlib.md5(data.encode()).hexdigest() if data else '0' * 32

    def get_base_string(self) -> str:
        return self.hash(self.params) + self.hash(self.data) + self.hash(self.cookies)

    def encrypt(self, data: str) -> json:
        key = [223, 119, 185, 64, 185, 155, 132, 131, 209, 185, 203, 209, 247, 194, 185, 133, 195, 208, 251, 195]
        param_list = [int(data[i:i+2], 16) for i in range(0, len(data), 2)]
        param_list.extend([0, 6, 11, 28])
        H = int(hex(self.unix), 16)
        param_list.extend([(H & 4278190080) >> 24, (H & 16711680) >> 16, (H & 65280) >> 8, H & 255])

        eor_result_list = [a ^ b for a, b in zip(param_list, key)]
        length = 20
        for i in range(length):
            E = 255 ^ eor_result_list[(i + 1) % length]
            H = (E ^ 4294967295 ^ length) & 255
            eor_result_list[i] = H

        result = ''.join([format(param, '02x') for param in eor_result_list])
        return {'X-Gorgon': '0404b0d30000' + result, 'X-Khronos': str(self.unix)}

    def get_value(self) -> json:
        return self.encrypt(self.get_base_string())

# Variables for tracking statistics
_lock = threading.Lock()
reqs = 0
success = 0
fails = 0
rps = 0
rpm = 0

# Sending logic
def send(did, iid, cdid, openudid):
    global reqs, success, fails
    __aweme_id = fetch_aweme_id(link)
    for x in range(10):
        try:
            version = random.choice(__versions)
            params = urlencode(
                {
                    "os_api": "25",
                    "device_type": random.choice(__devices),
                    "ssmix": "a",
                    "manifest_version_code": version,
                    "dpi": "240",
                    "region": "VN",
                    "carrier_region": "VN",
                    "app_name": "musically_go",
                    "version_name": "27.2.4",
                    "timezone_offset": "-28800",
                    "ab_version": "27.2.4",
                    "ac2": "wifi",
                    "ac": "wifi",
                    "app_type": "normal",
                    "channel": "googleplay",
                    "update_version_code": version,
                    "device_platform": "android",
                    "iid": __install_id,
                    "build_number": "27.2.4",
                    "locale": "vi",
                    "op_region": "VN",
                    "version_code": version,
                    "timezone_name": "Asia/Ho_Chi_Minh",
                    "device_id": __device_id,
                    "sys_region": "VN",
                    "app_language": "vi",
                    "resolution": "720*1280",
                    "device_brand": "samsung",
                    "language": "vi",
                    "os_version": "7.1.2",
                    "aid": "1340"
                }
            )
            payload = f"item_id={__aweme_id}&play_delta=1"
            sig = Gorgon(params=params).get_value()
            proxy = random.choice(proxies) if config['proxy']['use-proxy'] else ""
            response = r.post(
                url="https://" + random.choice(__domains) + "/aweme/v1/aweme/stats/?" + params,
                data=payload,
                headers={'x-gorgon': sig['X-Gorgon'], 'x-khronos': sig['X-Khronos'], 'user-agent': 'okhttp/3.10.0.1'},
                verify=False,
                proxies={"http": proxy_format + proxy, "https": proxy_format + proxy} if config['proxy']['use-proxy'] else {}
            )
            _lock.acquire()
            reqs += 1
            if response.json().get('status_code') == 0:
                success += 1
            else:
                fails += 1
            _lock.release()
        except Exception as e:
            if _lock.locked():
                _lock.release()
            fails += 1

# Function to fetch aweme_id from link
def fetch_aweme_id(link: str) -> str:
    aweme_search = re.findall(r"(\d{18,19})", link)
    if aweme_search:
        return aweme_search[0]
    return re.findall(r"(\d{18,19})", requests.head(link, allow_redirects=True, timeout=5).url)[0]

# RPS and RPM calculation loop
def rpsm_loop():
    global rps, rpm
    while True:
        initial = reqs
        time.sleep(1.5)
        rps = round((reqs - initial) / 1.5, 1)
        rpm = round(rps * 60, 1)

def fetch_proxies():
    url_list =[
        "https://raw.githubusercontent.com/yemixzy/proxy-list/main/proxy-list/data.txt",
        "https://raw.githubusercontent.com/UptimerBot/proxy-list/main/proxies/http.txt",
        "https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies/http.txt",
        "https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies/socks4.txt",
        "https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies/socks5.txt"        
    ]
    for url in url_list :
        response = requests.get(
            url=url
        )
        if response.ok:
            with open("proxies.txt", "a+") as f:
                f.write(response.text)
                f.close()
        else:
            pass
            
# Main execution
if __name__ == "__main__":
    # Load devices, proxies, and config
    with open('devices.txt', 'r') as f:
        devices = f.read().splitlines()
    with open('config.json', 'r') as f:
        config = json.load(f)
    if config["proxy"]['proxyscrape']:
        fetch_proxies()
    proxy_format = f'{config["proxy"]["proxy-type"].lower()}://{config["proxy"]["credential"]+"@" if config["proxy"]["auth"] else ""}' if config['proxy']['use-proxy'] else ''
    if config['proxy']['use-proxy']:
        with open('proxies.txt', 'r') as f:
            proxies = f.read().splitlines()
            
    os.system("cls" if os.name == "nt" else "clear")
    print(r"""
                                         do. 
                                        :NOX 
                                       ,NOM@: 
                                       :NNNN: 
                                       :XXXON 
                                       :XoXXX. 
                                       MM;ONO: 
  .oob..                              :MMO;MOM 
 dXOXYYNNb.                          ,NNMX:MXN 
 Mo"'  '':Nbb                        dNMMN MNN: 
 Mo  'O;; ':Mb.                     ,MXMNM MNX: 
 @O :;XXMN..'X@b.                  ,NXOMXM MNX: 
 YX;;NMMMM@M;;OM@o.                dXOOMMN:MNX: 
 'MOONM@@@MMN:':NONb.            ,dXONM@@MbMXX: 
  MOON@M@@MMMM;;:OOONb          ,MX'"':ONMMMMX: 
  :NOOM@@MNNN@@X;""XNN@Mb     .dP"'   ,..OXM@N: 
   MOON@@MMNXXMMO  :M@@M...@o.oN"0MQOOOXNNXXOo:
   :NOX@@@MNXXXMNo :MMMM@K"`,:;NNM@@NXM@MNO;.'N. 
    NO:X@@MNXXX@@O:'X@@@@MOOOXMM@M@NXXN@M@NOO ''b 
    `MO.'NMNXXN@@N: 'XXM@NMMXXMM@M@XO"'"XM@X;.  :b 
     YNO;'"NXXXX@M;;::"XMNN:""ON@@MO: ,;;.:Y@X: :OX. 
      Y@Mb;;XNMM@@@NO: ':O: 'OXN@@MO" ONMMX:`XO; :X@. 
      '@XMX':OX@@MN:    ;O;  :OX@MO" 'OMM@N; ':OO;N@N 
       YN;":.:OXMX"': ,:NNO;';XMMX:  ,;@@MNN.'.:O;:@X: 
       `@N;;XOOOXO;;:O;:@MOO;:O:"" ,oMP@@K"YM.;NMO;`NM 
        `@@MN@MOX@@MNMN;@@MNXXOO: ,d@NbMMP'd@@OX@NO;.'bb. 
       .odMX@@XOOM@M@@XO@MMMMMMNNbN"YNNNXoNMNMO"OXXNO.."";o. 
     .ddMNOO@@XOOM@@XOONMMM@@MNXXMMo;."' .":OXO ':.'"'"'  '""o. 
    'N@@X;,M@MXOOM@OOON@MM@MXOO:":ONMNXXOXX:OOO               ""ob. 
   ')@MP"';@@XXOOMMOOM@MNNMOO""   '"OXM@MM: :OO.        :...';o;.;Xb. 
  .@@MX" ;X@@XXOOM@OOXXOO:o:'      :OXMNO"' ;OOO;.:     ,OXMOOXXXOOXMb 
 ,dMOo:  oO@@MNOON@N:::"      .    ,;O:."'  .dMXXO:    ,;OX@XO"":ON@M@ 
:Y@MX:.  oO@M@NOXN@NO. ..: ,;;O;.       :.OX@@MOO;..   .OOMNMO.;XN@M@P 
,MP"OO'  oO@M@O:ON@MO;;XO;:OXMNOO;.  ,.;.;OXXN@MNXO;.. oOX@NMMN@@@@@M: 
`' "O:;;OON@@MN::XNMOOMXOOOM@@MMNXO:;XXNNMNXXXN@MNXOOOOOXNM@NM@@@M@MP 
   :XN@MMM@M@M:  :'OON@@XXNM@M@MXOOdN@@@MM@@@@MMNNXOOOXXNNN@@M@MMMM" 
   .oNM@MM@ONO'   :;ON@@MM@MMNNXXXM@@@@M@PY@@MMNNNNNNNNNNNM@M@M@@P' 
  ;O:OXM@MNOOO.   'OXOONM@MNNMMXON@MM@@b. 'Y@@@@@@@@@@@@@M@@MP"' 
 ;O':OOXNXOOXX:   :;NMO:":NMMMXOOX@MN@@@@b.:M@@@M@@@MMM@ 
 :: ;"OOOOOO@N;:  'ON@MO.'":""OOOO@@NNMN@@@. Y@@@MMM@@@@b 
 :;   ':O:oX@@O;;  ;O@@XO'   "oOOOOXMMNMNNN@MN""YMNMMM@@MMo. 
 :N:.   ''oOM@NMo.::OX@NOOo.  ;OOOXXNNNMMMNXNM@bd@MNNMMM@MM@bb    @GUINNESSGSHEP 
  @;O .  ,OOO@@@MX;;ON@NOOO.. ' ':OXN@NNN@@@@@M@@@@MNXNMM@MMM@, 
  M@O;;  :O:OX@@M@NXXOM@NOO:;;:,;;ON@NNNMM'`"@@M@@@@@MXNMMMMM@N 
  N@NOO;:oO;O:NMMM@M@OO@NOO;O;oOOXN@NNM@@'   `Y@NM@@@@MMNNMM@MM 
  ::@MOO;oO:::OXNM@@MXOM@OOOOOOXNMMNNNMNP      ""MNNM@@@MMMM@MP 
    @@@XOOO':::OOXXMNOO@@OOOOXNN@NNNNNNNN        '`YMM@@@MMM@P' 
    MM@@M:'''' O:":ONOO@MNOOOOXM@NM@NNN@P            "`SHEP' 
    ''MM@:     "' 'OOONMOYOOOOO@MM@MNNM" 
      YM@'         :OOMN: :OOOO@MMNOXM'
      `:P           :oP''  "'OOM@NXNM' 
       `'                    GUINNESS' 
                               '"'  """) 

    try:
        link = str(Write.Input("Enter TikTok URL: ", Colors.white_to_green, interval=0.0001))
        thread_count = int(input("Enter the number of threads you'd like to run: "))
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

    threading.Thread(target=rpsm_loop).start()

while True:
    device = random.choice(devices)
    parts = device.split(':')
    
    # Check if the split parts are exactly four
    if len(parts) != 4:
        print(f"Skipping device with incorrect format: {device}")
        continue  # Skip to the next iteration if the format is incorrect

    did, iid, cdid, openudid = parts  # Unpack the values

    if threading.active_count() < thread_count:
        threading.Thread(target=send, args=[did, iid, cdid, openudid]).start()
