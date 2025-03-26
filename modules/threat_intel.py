import pathlib
import os

from modules.api_keys import abuseIPdb_api_key as ipdb
from modules.api_keys import alien_vault_otx_api_key as otx
from modules.api_keys import abusech_api_key as abch

import pandas as pd
import redis
import re
import requests
import csv

from modules.message_log import success_op, mid_op, fail_op

# Constants for regex patterns
MD5_REGEX = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_REGEX = re.compile(r"^[a-fA-F0-9]{40}$")
SHA256_REGEX = re.compile(r"^[a-fA-F0-9]{64}$")
SHA512_REGEX = re.compile(r"^[a-fA-F0-9]{128}$")
IP_REGEX = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
DOMAIN_REGEX = re.compile(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")

def check_api_key(ioc_filename):
    """
    Check if all API keys are loaded.
    """
    if all([ipdb, otx, abch]):
        success_op("API key loaded successfully.")
        check_extracted_ioc(ioc_filename)
    else:
        fail_op("No API keys found!")

def check_extracted_ioc(ioc_file_name):
    """
    Check if the extracted IOCs file exists and process it.
    """
    ioc_file = pathlib.Path(ioc_file_name).resolve()
    
    if os.path.exists(ioc_file):
        success_op(f"{ioc_file} - IOC file found for threat intelligence...")
        threat_intel(ioc_file)
    else:
        fail_op(f"{ioc_file} - IOC file not found.")

def threat_intel(ioc_file):
    """
    Process the IOCs from the given file and classify them.
    """
    mid_op(f"Checking [{ioc_file}] and extracting key elements...")
    
    # Check if the file is empty
    if os.stat(ioc_file).st_size == 0:
        fail_op(f"{ioc_file} is empty. No data to process.")
        return

    df = pd.read_csv(ioc_file, na_values="-")
    ioc_types = {"IP": [], "Domain": [], "URL": [], "Hash": [], "Unknown IOC": []}

    for column in df.columns:
        for value in df[column].dropna().unique():
            value = str(value).strip()
            matched = False

            if IP_REGEX.match(value):
                ioc_types["IP"].append((column, value))
                matched = True
            elif any(regex.match(value) for regex in [MD5_REGEX, SHA1_REGEX, SHA256_REGEX, SHA512_REGEX]):
                ioc_types["Hash"].append((column, value))
                matched = True
            elif value.startswith(("http://", "https://")):
                ioc_types["URL"].append((column, value))
                matched = True
            elif DOMAIN_REGEX.match(value):
                ioc_types["Domain"].append((column, value))
                matched = True

            if not matched:
                ioc_types["Unknown IOC"].append((column, value))

    for ioc_type, values in ioc_types.items():
        for column, ioc in values:
            redis_result = check_redis(ioc_type, ioc)
            if redis_result in ["True", "False"]:
                label = "Malicious" if redis_result == "True" else "Benign"
                success_op(f"{ioc_type}:{column} - {ioc} -> Redis Status - {label}")
                df["Threat Label"] = label
                df.to_csv("final_data.csv", index=False)
            else:
                threat_res = query_threat_api(ioc_type, column, ioc)
                if threat_res in ["True", "False"]:
                    label = "Malicious" if threat_res == "True" else "Benign"
                    success_op(f"{ioc_type}:{column} - {ioc} -> Threat Intel Status - {label}")
                    df["Threat Label"] = label
                    df.to_csv("final_data.csv", index=False)
                # else:
                #     fail_op("Coming Soon...")

def check_redis(ioc_type, ioc_value):
    """
    Check if the IOC is present in Redis.
    """
    r = redis.Redis(host="localhost", port=6379, decode_responses=True)
    if r.ping():
        key = f"{ioc_type}:{ioc_value}"
        result = r.get(key)
        return result if result else "Unknown"
    else:
        fail_op("You need to start Redis before reading IOCs from Redis storage.")

def store_redis(ioc_type, ioc_value, result):
    """
    Store the IOC result in Redis.
    """
    r = redis.Redis(host="localhost", port=6379, decode_responses=True)
    if r.ping():
        key = f"{ioc_type}:{ioc_value}"
        r.set(key, result)
        success_op("Redis updated.")

def query_threat_api(ioc_type, column, ioc_value):
    """
    Query the threat intelligence APIs for the given IOC.
    """
    # mid_op(f"{ioc_type}:{column} - '{ioc_value}' not found in Redis. Threat API in progress...")
    if ioc_type == "IP":
        mid_op(f"{ioc_type}:{column} - '{ioc_value}' not found in Redis. Threat API in progress...")
        return handle_ip(ioc_value)
    elif ioc_type == "Domain":
        mid_op(f"{ioc_type}:{column} - '{ioc_value}' not found in Redis. Threat API in progress...")
        return handle_domain(ioc_value)
    elif ioc_type == "URL":
        mid_op(f"{ioc_type}:{column} - '{ioc_value}' not found in Redis. Threat API in progress...")
        return handle_url(ioc_value)
    elif ioc_type == "Hash":
        mid_op(f"{ioc_type}:{column} - '{ioc_value}' not found in Redis. Threat API in progress...")
        return handle_hash(ioc_value)
    else:
        # fail_op("Unknown IOC type.")
        return "Error"

def handle_ip(ioc_value):
    """
    Handle IP type IOC by querying AbuseIPDB and AlienVault OTX.
    """
    result = abuse_ipdb(ioc_value)
    if result == "True":
        store_redis("IP", ioc_value, result)
        res = alien_otx("IP", ioc_value)
        if res == "True":
            success_op("Malicious on AbuseIPDB and AlienVault OTX.")
            return "True"
        else:
            success_op("Found malicious only on AbuseIPDB and safe on AlienVault OTX.")
            return "True"
    elif result == "False":
        res = alien_otx("IP", ioc_value)
        store_redis("IP", ioc_value, result)
        if res == "True":
            success_op("Found safe on AlienVault OTX and malicious on AbuseIPDB.")
            return "True"
        else:
            success_op("Found safe on both AbuseIPDB and AlienVault OTX.")
            return "False"
    else:
        fail_op("Error processing IP.")
        return "Error"

def handle_domain(ioc_value):
    """
    Handle Domain type IOC by querying AlienVault OTX.
    """
    result = alien_otx("Domain", ioc_value)
    if result == "True":
        success_op("Found malicious on AlienVault OTX.")
        store_redis("Domain", ioc_value, result)
        return "True"
    elif result == "False":
        success_op("Found safe on AlienVault OTX.")
        store_redis("Domain", ioc_value, result)
        return "False"
    else:
        fail_op("Error fetched from API call.")
        return "Error"

def handle_url(ioc_value):
    """
    Handle URL type IOC by querying URL Haus and AlienVault OTX.
    """
    result = url_haus("URL", ioc_value)
    if result == "True":
        store_redis("URL", ioc_value, result)
        res = alien_otx("URL", ioc_value)
        if res == "True":
            success_op("Found malicious on both URL Haus and Alien OTX.")
            return "True"
        elif res == "False":
            success_op("Found malicious on URL Haus and safe on Alien OTX.")
            return "False"
        else:
            fail_op("Error processing on URL Haus.")
            return "Error"
    elif result == "False":
        success_op("Found safe on URL Haus and now checking on Alien OTX.")
        store_redis("URL", ioc_value, result)
        res = alien_otx("URL", ioc_value)
        if res == "True":
            success_op("Found malicious on Alien OTX and safe on URL Haus.")
            return "True"
        elif res == "False":
            success_op("Found safe on both URL Haus and Alien OTX.")
            return "False"
        else:
            fail_op("Error processing on Alien OTX.")
            return "Error"
    else:
        fail_op("Error processing URL.")
        return "Error"

def handle_hash(ioc_value):
    """
    Handle Hash type IOC by querying Threat Fox and SSL Blacklist.
    """
    result = threat_fox_hash("Hash", ioc_value)
    if result == "True":
        store_redis("Hash", ioc_value, result)
        res = ssl_check(ioc_value)
        if res == "True":
            success_op("Hash found malicious on both Threat Fox and SSL Blacklist.")
            return "True"
        elif res == "False":
            success_op("Hash found malicious on SSL Blacklist and safe on Threat Fox.")
            return "False"
        else:
            fail_op("Error processing on Threat Fox.")
            return "Error"
    elif result == "False":
        success_op("Hash found safe on Threat Fox and now checking on SSL Blacklist.")
        res = ssl_check(ioc_value)
        if res == "True":
            success_op("Hash found malicious on SSL Blacklist and safe on Threat Fox.")
            store_redis("Hash", ioc_value, result)
            return "True"
        elif res == "False":
            success_op("Hash found safe on both Threat Fox and SSL Blacklist.")
            store_redis("Hash", ioc_value, result)
            return "False"
        else:
            fail_op("Error processing on SSL Blacklist.")
            return "Error"
    else:
        fail_op("Error processing hash.")
        return "Error"

def abuse_ipdb(ioc_val):
    """
    Query AbuseIPDB for the given IP address.
    """
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ioc_val}"
    headers = {"Key": ipdb, "Accept": "application/json"}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        confidence_score = data["data"]["abuseConfidenceScore"]
        return "True" if confidence_score > 50 else "False"
    else:
        return f"Error: {response.status_code}, {response.text}"

def alien_otx(ioc_type, ioc_val):
    """
    Query AlienVault OTX for the given IOC.
    """
    new_ioc_type = {"IP": "IPv4", "Domain": "domain", "URL": "url"}.get(ioc_type, ioc_type)
    url = f"https://otx.alienvault.com/api/v1/indicators/{new_ioc_type}/{ioc_val}"
    headers = {"X-OTX-API-KEY": otx, "Accept": "application/json"}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        return "True" if "pulse_info" in data and data["pulse_info"]["count"] > 0 else "False"
    else:
        return f"Error: {response.status_code}, {response.text}"

def url_haus(ioc_type, ioc_val):
    """
    Query URL Haus for the given URL.
    """
    url = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
    response = requests.get(url=url, headers={"Accept": "application/json"}, params={"query": ioc_val})
    if response.status_code == 200:
        data = response.text
        return "True" if ioc_val in data else "False"
    else:
        return f"Error: {response.status_code}, {response.text}"

def threat_fox_hash(ioc_type, ioc_val):
    """
    Query Threat Fox for the given hash.
    """
    url = "https://threatfox-api.abuse.ch/api/v1/"
    payload = {"query": "search_ioc", "search_term": ioc_val}
    response = requests.post(url, json=payload)
    if response.status_code == 200:
        data = response.json()
        return "True" if "data" in data and len(data["data"]) > 0 and data['query_status'] != 'no_result' else "False"
    else:
        return f"Error: {response.status_code}, {response.text}"

def download_ssl_blacklist():
    """
    Download the SSL Blacklist from abuse.ch.
    """
    url = "https://sslbl.abuse.ch/blacklist/sslblacklist.csv"
    response = requests.get(url)
    if response.status_code == 200:
        with open("sslblacklist.csv", "wb") as file:
            file.write(response.content)
        print("✅ SSL Blacklist downloaded successfully.")
    else:
        print(f"❌ Failed to download SSL Blacklist: {response.status_code}")

def ssl_check(ioc_val):
    """
    Check if the given hash is in the SSL Blacklist.
    """
    curent_dir = pathlib.Path(__file__).parent
    check_dir = pathlib.Path(f"{curent_dir}/../sslblacklist.csv").resolve()
    if not os.path.exists(check_dir):
        print("❌ Blacklist file not found. Downloading now...")
        download_ssl_blacklist()
    with open(check_dir, mode='r', encoding='utf-8') as file:
        csv_reader = csv.reader(file)
        for row in csv_reader:
            if row and row[1] == ioc_val:
                return "True"
    return "False"