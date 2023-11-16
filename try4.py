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
__domains = [...]
__devices = [...]
__versions = [...]

# Gorgon encryption function
class Gorgon:
    ...

# Request sending function
def send_request(__device_id, __install_id, cdid, openudid, __aweme_id, proxies, config, statistics):
    ...

# RPSM (Requests Per Second Monitor) function
def rpsm_loop(statistics):
    ...

# Proxy fetching function
def fetch_proxies():
    ...

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
