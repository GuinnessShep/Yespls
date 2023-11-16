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
def send_requests(device_id, install_id, cdid, openudid, __aweme_id, session, proxies, proxy_format, domains, versions, layout, task_id):
    for _ in range(100):
        try:
            version = random.choice(versions)
            params = urlencode(
                {
                    "device_type": random.choice(devices),
                    "version_code": version,
                    "device_id": device_id,
                    "iid": install_id
                }
            )
            payload = f"item_id={__aweme_id}&play_delta=1"
            sig = Gorgon(params=params, data=None, cookies=None, unix=int(time.time())).get_value()

            proxy = random.choice(proxies) if proxies else ""

            response = session.post(
                url="https://" + random.choice(domains) + "/aweme/v1/aweme/stats/?" + params,
                data=payload,
                headers={'x-gorgon': sig['X-Gorgon'], 'x-khronos': sig['X-Khronos']},
                proxies={"http": proxy_format + proxy, "https": proxy_format + proxy} if proxies else {}
            )

            if response.json().get('status_code') == 0:
                layout["status"].update(Panel(f"[green]Thread {task_id}: Request Successful", title="Status"))
            else:
                layout["status"].update(Panel(f"[red]Thread {task_id}: Request Failed", title="Status"))

        except Exception as e:
            layout["status"].update(Panel(f"[red]Thread {task_id}: Error {str(e)}", title="Status"))
        time.sleep(0.1)

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
