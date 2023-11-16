import requests
import json
import os
import re
import sys
import time
import threading
import random
import hashlib
import ssl
from http import cookiejar
from urllib.parse import urlencode
from rich import print, console, progress
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.table import Table
from rich.prompt import Prompt

# Disabling SSL warnings and cookie policy
requests.packages.urllib3.disable_warnings()
ssl._create_default_https_context = ssl._create_unverified_context

class BlockCookies(cookiejar.CookiePolicy):
    return_ok = set_ok = domain_return_ok = path_return_ok = lambda self, *args, **kwargs: False
    netscape = True
    rfc2965 = hide_cookie2 = False

# Session settings
session = requests.Session()
session.cookies.set_policy(BlockCookies())

# Constants
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
def main():
    console = Console()
    console.clear()

    print("[bold magenta]TikTok Viewbot[/bold magenta]")
    
    # Load configurations
    with open('devices.txt', 'r') as f:
        devices = f.read().splitlines()    

    with open('config.json', 'r') as f:
        config = json.load(f)

    if config["proxy"]['proxyscrape']:
        fetch_proxies()

    proxy_format = ...
    proxies = ...
    
    # Get video link
    link = Prompt.ask("[bold green]Paste the TikTok video link[/bold green]")
    try:
        __aweme_id = ...
    except:
        console.print("[bold red]Invalid link, try inputting just the video ID[/bold red]")
        sys.exit(0)

    # Thread count
    thread_count = Prompt.ask("[bold green]Enter the number of threads[/bold green]", default="100")
    thread_count = int(thread_count)

    # Initializing statistics
    statistics = {
        'reqs': 0,
        'success': 0,
        'fails': 0,
        'rps': 0,
        'rpm': 0
    }

    # Start RPSM loop
    threading.Thread(target=rpsm_loop, args=(statistics,)).start()

    # Start sending requests
    with Progress("[progress.description]{task.description}", SpinnerColumn(), BarColumn(), "[progress.percentage]{task.percentage:>3.0f}%", TextColumn("{task.completed} requests"), TextColumn("Success: {task.fields[success]}"), TextColumn("Fails: {task.fields[fails]}")) as progress:
        task = progress.add_task("[cyan]Sending requests...", total=1000, success=0, fails=0)
        while not progress.finished:
            device = random.choice(devices)
            if threading.active_count() < thread_count + 1: 
                did, iid, cdid, openudid = device.split(':')
                threading.Thread(target=send_request, args=[did, iid, cdid, openudid, __aweme_id, proxies, config, statistics]).start()
            
            # Update statistics
            progress.update(task, advance=1, success=statistics['success'], fails=statistics['fails'])

if __name__ == "__main__":
    main()
