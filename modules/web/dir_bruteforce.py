import requests
from concurrent.futures import ThreadPoolExecutor


def check_directory(url, directory):

    directory = directory.strip()

    target_url = f"{url}/{directory}"

    try:
        response = requests.get(target_url)

        if response.status_code in [200, 301, 302, 403]:
            print(f"[{response.status_code}] {target_url}")

    except requests.exceptions.RequestException:
        pass


def dir_scan(url, wordlist):

    with open(wordlist, "r") as file:
        directories = file.readlines()

    with ThreadPoolExecutor(max_workers=50) as executor:

        for directory in directories:
            executor.submit(check_directory, url, directory)
