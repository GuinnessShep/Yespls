import json
import os
import random
import re
import requests
import sys
import threading
import time
from queue import Queue
from urllib.parse import urlencode
import hashlib
import ssl
from rich.console import Console
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn, SpinnerColumn
from rich.table import Table
from rich import box
from urllib3.exceptions import InsecureRequestWarning
from http.cookiejar import CookiePolicy

# Disable warnings and SSL verification
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
ssl._create_default_https_context = ssl._create_unverified_context

# Custom Cookie Policy
class BlockCookies(CookiePolicy):
    def return_ok(self, *args, **kwargs): return False
    def set_ok(self, *args, **kwargs): return False
    def domain_return_ok(self, *args, **kwargs): return False
    def path_return_ok(self, *args, **kwargs): return False
    netscape = True
    rfc2965 = hide_cookie2 = False

# Session setup
r = requests.Session()
r.cookies.set_policy(BlockCookies())

# Constants
__domains = ["api22-core-c-useast1a.tiktokv.com", "api19-core-c-useast1a.tiktokv.com",
             "api16-core-c-useast1a.tiktokv.com", "api21-core-c-useast1a.tiktokv.com"]
__versions = ["190303", "190205", "190204", "190103", "180904", "180804", "180803", "180802",  "270204"]

# Gorgon encryption class
class Gorgon:
    def __init__(self, params: str, data: str, cookies: str, unix: int):
        self.unix = unix
        self.params = params
        self.data = data
        self.cookies = cookies

    @staticmethod
    def hash(data: str) -> str:
        return hashlib.md5(data.encode()).hexdigest()

    def get_base_string(self) -> str:
        base_str = self.hash(self.params)
        base_str += self.hash(self.data) if self.data else '0' * 32
        base_str += self.hash(self.cookies) if self.cookies else '0' * 32
        return base_str

    def get_value(self) -> json:
        base_str = self.get_base_string()
        return self.encrypt(base_str)

    def encrypt(self, data: str) -> json:
        key = [223, 119, 185, 64, 185, 155, 132, 131, 209, 185, 203, 209, 247, 194, 185, 133, 195, 208, 251, 195]
        param_list = [int(data[i:i + 2], 16) for i in range(0, 96, 2)]
        for i in range(20):
            param_list[i] = param_list[i] ^ key[i]
        result = ''.join(f'{p:02x}' for p in param_list)
        return {'X-Gorgon': '0404b0d30000' + result, 'X-Khronos': str(self.unix)}

# Thread Worker
def worker(queue):
    global success, fails
    while True:
        device = queue.get()
        if device is None:
            break
        did, iid, cdid, openudid = device.split(':')
        send(did, iid, cdid, openudid)
        queue.task_done()

# Send function with threading and Gorgon
def send_requests(device_id, install_id, cdid, openudid, __aweme_id, session, proxies, proxy_format, domains, versions, layout, task_    global reqs, _lock, success, fails, rps, rpm
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
            sig     = Gorgon(params=params, cookies=None, data=None, unix=int(time.time())).get_value()

            proxy = random.choice(proxies) if config['proxy']['use-proxy'] else ""

            response = r.post(
                url = (
                    "https://"
                    +  random.choice(__domains)  +
                    "/aweme/v1/aweme/stats/?" + params
                ),
                data    = payload,
                headers = {'cookie':'sessionid=90c38a59d8076ea0fbc01c8643efbe47','x-gorgon':sig['X-Gorgon'],'x-khronos':sig['X-Khronos'],'user-agent':'okhttp/3.10.0.1'},
                verify  = False,
                proxies = {"http": proxy_format+proxy, "https": proxy_format+proxy} if config['proxy']['use-proxy'] else {}
            )
            reqs += 1
            try:
                if response.json()['status_code'] == 0:
                    _lock.acquire()
                    print(Colorate.Horizontal(Colors.red_to_green, f'TikTok Viewbot by N.H.K TOOL^| success: {success} fails: {fails} reqs: {reqs} rps: {rps} rpm: {rpm}'))
                    success += 1
                    _lock.release()
            except:
                if _lock.locked():_lock.release()
                fails += 1
                continue

        except Exception as e:
            pass


# Fetch Proxies
def fetch_proxies():
    url_list = [...]
    for url in url_list:
        response = requests.get(url=url)
        if response.ok:
            with open("proxies.txt", "a+") as f:
                f.write(response.text)

# Console setup
console = Console()
progress = Progress(TextColumn("[bold green]{task.description}"), BarColumn(), 
                    TextColumn("[bold yellow]{task.completed} successes"), 
                    TextColumn("[bold red]{task.failed} fails"), 
                    SpinnerColumn(), TimeRemainingColumn(), 
                    expand=True)

# Main
if __name__ == "__main__":
    # Read devices, config, and proxies
    with open('devices.txt', 'r') as f:
        __devices = f.read().splitlines()
    with open('config.json', 'r') as f:
        config = json.load(f)
    if config["proxy"]['proxyscrape']:
        fetch_proxies()
    proxy_format = f'{config["proxy"]["proxy-type"].lower()}://{config["proxy"]["credential"]+"@" if config["proxy"]["auth"] else ""}' if config['proxy']['use-proxy'] else ''
    if config['proxy']['use-proxy']:
        with open('proxies.txt', 'r') as f:
            proxies = f.read().splitlines()

    # Input TikTok URL and threads
    link = input("Enter TikTok video URL: ")
    __aweme_id = re.findall(r"(\d{18,19})", link)[0] if re.search(r"(\d{18,19})", link) else None
    if not __aweme_id:
        print("Invalid TikTok URL")
        sys.exit(1)
    threads_count = int(input("Enter number of threads: "))

    # Status
    success, fails = 0, 0
    queue = Queue()
    threads = []
    for _ in range(threads_count):
        t = threading.Thread(target=worker, args=(queue,))
        t.start()
        threads.append(t)

    # Add devices to queue
    for device in __devices:
        queue.put(device)

    # Start progress
    with progress:
        task = progress.add_task("Sending requests...", total=100)
        while not queue.empty():
            progress.update(task, advance=1, completed=success, failed=fails)
        queue.join()

    # Stop threads
    for _ in threads:
        queue.put(None)
    for t in threads:
        t.join()

    # Final status
    table = Table(title="Request Status", box=box.ROUNDED)
    table.add_column("Total Requests", justify="right")
    table.add_column("Successes", justify="right")
    table.add_column("Fails", justify="right")
    table.add_row(str(success + fails), str(success), str(fails))
    console.print(table)
