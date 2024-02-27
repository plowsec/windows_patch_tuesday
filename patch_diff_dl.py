import requests
import gzip
import re
from io import BytesIO
import json
import sys

def make_symbol_server_url(pe_name, time_stamp, image_size):
    """
    Generates a URL for downloading symbols from Microsoft's symbol server.

    Args:
    - pe_name: The name of the PE file.
    - time_stamp: The timestamp associated with the file.
    - image_size: The size of the image.

    Returns:
    - A URL string for downloading the symbols.
    """
    file_id = f"{time_stamp:08X}{image_size:x}"
    return f"https://msdl.microsoft.com/download/symbols/{pe_name}/{file_id}/{pe_name}"


def filter_and_extract_build_number(data):
    filtered_build_numbers = []

    for key, value in data.items():
        windows_versions = value.get("windowsVersions", {})
        for version_info in windows_versions.values():
            for kb_info in version_info.values():
                update_info = kb_info.get("updateInfo", {})
          

                other_versions = update_info.get("otherWindowsVersions", [])
                if "11-23H2" in other_versions:
                    version_string = value["fileInfo"]["version"]
                    match = re.search(r"(\d+\.\d+\.\d+\.\d+)", version_string)
                    if match:
                        build_number = match.group(1)
                        assemblyInfo = kb_info.get("assemblies", {})

                        if len(list(assemblyInfo.values())) == 0:
                            print("Error")
                            print(list(assemblyInfo.values()))
                            continue

                        print(list(assemblyInfo.values())[0])
                        filename = list(assemblyInfo.values())[0]["attributes"][0]["name"]


                        download_link = make_symbol_server_url(filename, value["fileInfo"]["timestamp"], value["fileInfo"]["virtualSize"])
                        filtered_build_numbers.append(
                            {
                                "build_number": build_number,
                                "download_link": download_link
                            }
                        )

    return filtered_build_numbers

def get_data_and_filter(filename):
    headers = {
        'Accept': '*/*',
        'X-Requested-With': 'XMLHttpRequest',
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    }

    response = requests.get(f'https://winbindex.m417z.com/data/by_filename_compressed/{filename}.json.gz', headers=headers)

    if response.status_code == 200:
        # Decompress the gzip response
        decompressed_data = gzip.decompress(response.content)
        data = json.loads(decompressed_data.decode('utf-8'))
        filtered_build_numbers = filter_and_extract_build_number(data)
        return filtered_build_numbers
    else:
        print("Failed to retrieve data")
        return []
    

def get_download_link_for_build_number(filename, build_number):

    infos = get_data_and_filter(filename)

    print(infos)

    for i, build in enumerate(infos):

        if build["build_number"].split(".")[-1] == build_number.split(".")[-1]:

            print(f"Patched file: {build['download_link']}")
            print(f"Unpatched file: {infos[i-1]['download_link']}")

            patched_location = f"{filename}_patched.sys"
            unpatched_location = f"{filename}_unpatched.sys"
            download_binary(build['download_link'], patched_location)
            print(f"Binary download and saved at {patched_location}")
            download_binary(infos[i-1]['download_link'], unpatched_location)
            print(f"Binary download and saved at {unpatched_location}")

def download_binary(url, save_path):
    """
    Downloads a binary from the specified URL and saves it to the given path.

    Args:
    - url: The URL from which to download the binary.
    - save_path: The local file path where the binary should be saved.

    Returns:
    - None
    """
    headers = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Accept-Language': 'en-US,en;q=0.9',
        # Include other headers as necessary
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    }
    response = requests.get(url, headers=headers, stream=True)
    if response.status_code == 200:
        with open(save_path, 'wb') as f:
            for chunk in response.iter_content(1024):
                f.write(chunk)

if __name__ == '__main__':

    filename = sys.argv[1]
    build_number = sys.argv[2]
    get_download_link_for_build_number(filename, build_number)