import threading
import time
import requests
import random
import json
import os
import sys
from rich.console import Console
from rich.panel import Panel
from rich.layout import Layout
from rich.live import Live
from rich.text import Text
from rich.prompt import Prompt
from urllib.parse import urlencode
import hashlib
from http import cookiejar
from queue import Queue
from rich.traceback import install

install()
console = Console()

class BlockCookies(cookiejar.CookiePolicy):
    return_ok = set_ok = domain_return_ok = path_return_ok = lambda self, *args, **kwargs: False
    netscape = True
    rfc2965 = hide_cookie2 = False

__domains = ["api22-core-c-useast1a.tiktokv.com", "api19-core-c-useast1a.tiktokv.com",
                          "api16-core-c-useast1a.tiktokv.com", "api21-core-c-useast1a.tiktokv.com"]
__devices = ["SM-G9900", "SM-A136U1", "SM-M225FV", "SM-E426B", "SM-M526BR", "SM-M326B", "SM-A528B",
                          "SM-F711B", "SM-F926B", "SM-A037G", "SM-A225F", "SM-M325FV", "SM-A226B", "SM-M426B",
                          "SM-A525F", "SM-N976N"]
__versions = ["190303", "190205", "190204", "190103", "180904", "180804", "180803", "180802",  "270204"]

class Gorgon:
    def __init__(self, params: str, data: str, cookies: str, unix: int) -> None:
        self.unix = unix
        self.params = params
        self.data = data
        self.cookies = cookies

    def hash(self, data: str) -> str:
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
        unix = self.unix
        len = 20
        key = [223, 119, 185, 64, 185, 155, 132, 131, 209, 185, 203, 209, 247, 194, 185, 133, 195, 208, 251, 195]
        param_list = []
        for i in range(0, 12, 4):
            temp = data[8 * i:8 * (i + 1)]
            for j in range(4):
                H = int(temp[j * 2:(j + 1) * 2], 16)
                param_list.append(H)
        param_list.extend([0, 6, 11, 28])
        H = int(hex(unix), 16)
        param_list.append((H & 4278190080) >> 24)
        param_list.append((H & 16711680) >> 16)
        param_list.append((H & 65280) >> 8)
        param_list.append((H & 255) >> 0)
        eor_result_list = []
        for (A, B) in zip(param_list, key):
            eor_result_list.append(A ^ B)
        for i in range(len):
            C = self.reverse(eor_result_list[i])
            D = eor_result_list[(i + 1) % len]
            E = C ^ D
            F = self.rbit_algorithm(E)
            H = (F ^ 4294967295 ^ len) & 255
            eor_result_list[i] = H
        result = ''
        for param in eor_result_list:
            result += self.hex_string(param)
        return {'X-Gorgon': '0404b0d30000' + result, 'X-Khronos': str(unix)}

    def rbit_algorithm(self, num):
        result = ''
        tmp_string = bin(num)[2:]
        while len(tmp_string) < 8: tmp_string = '0' + tmp_string
        for i in range(0, 8): result = result + tmp_string[7 - i]
        return int(result, 2)

    def hex_string(self, num):
        tmp_string = hex(num)[2:]
        if len(tmp_string) < 2: tmp_string = '0' + tmp_string
        return tmp_string

    def reverse(self, num):
        tmp_string = self.hex_string(num)
        return int(tmp_string[1:] + tmp_string[:1], 16)

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

def rpsm_loop():
    global rps, rpm
    while True:
        initial = reqs
        time.sleep(1.5)
        rps = round((reqs - initial) / 1.5, 1)
        rpm = round(rps * 60, 1)

def fetch_proxies():
    proxies = []
    url_list = [
      "https://raw.githubusercontent.com/yemixzy/proxy-list/main/proxy-list/data.txt",
      "https://raw.githubusercontent.com/UptimerBot/proxy-list/main/proxies/http.txt",
      "https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies/http.txt",
      "https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies/socks4.txt",
      "https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies/socks5.txt"
    ]
    for url in url_list:
        try:
            response = requests.get(url)
            if response.ok:
                proxies.extend(response.text.splitlines())
        except Exception as e:
            console.log(f"Failed to fetch proxies from {url}: {str(e)}")
    return proxies

def worker(queue, session, proxies, proxy_format, domains, versions, layout):
    while not queue.empty():
        task = queue.get()
        send_requests(task['device_id'], task['install_id'], task['cdid'], task['openudid'], task['__aweme_id'],
                      session, proxies, proxy_format, domains, versions, layout, task['task_id'])
        queue.task_
done()


def main():
    os.system("cls" if os.name == "nt" else "clear")
    layout = Layout()
    layout.split(
        Layout(name="header", size=3),
        Layout(name="status"),
    )
    layout["header"].update(Panel(Text("TikTok ViewBot", justify="center", style="bold magenta"), title="Title"))
    layout["status"].update(Panel(Text("Initializing...", style="bold cyan"), title="Status"))

    with Live(layout, console=console, refresh_per_second=10):
        try:
            link = Prompt.ask("[bold cyan]? Paste Video Link[/bold cyan]")
            __aweme_id = re.findall(r"(\d{18,19})", link)[0]
        except:
            layout["status"].update(Panel(Text("Invalid link, try inputting video id only", style="bold red"), title="Status"))
            sys.exit(0)

    thread_count = Prompt.ask("[bold cyan]? Enter number of threads[/bold cyan]", default="10")
    thread_count = int(thread_count)

    session = requests.Session()
    session.cookies.set_policy(BlockCookies())

    with open('config.json', 'r') as f:
        config = json.load(f)
    if config["proxy"]['proxyscrape']:
        fetch_proxies()
    proxy_format = f'{config["proxy"]["proxy-type"].lower()}://{config["proxy"]["credential"]+"@" if config["proxy"]["auth"] else ""}' if config['proxy']['use-proxy'] else ''
    if config['proxy']['use-proxy']:
        with open('proxies.txt', 'r') as f:
            proxies = f.read().splitlines()

    queue = Queue()
    for i in range(thread_count):
        device = random.choice(__devices)
        did, iid, cdid, openudid = device.split(':')
        queue.put({'device_id': did, 'install_id': iid, 'cdid': cdid, 'openudid': openudid, '__aweme_id': __aweme_id, 'task_id': i + 1})

    for _ in range(thread_count):
        threading.Thread(target=worker, args=(queue, session, proxies, proxy_format, domains, versions, layout)).start()

    queue.join()
    time.sleep(15)

if __name__ == "__main__":
    main()
