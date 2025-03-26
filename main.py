import os
import pathlib
import subprocess
import pyfiglet
from termcolor import colored
import argparse
import modules.ioc_extractor as ioc_extractor
import csv, json
from modules.message_log import success_op, mid_op, fail_op

def display_banner():
    """
    Display the banner for the AI Log Analyser.
    """
    banner = pyfiglet.figlet_format("AI Log Analyser")
    print(colored(banner, "green"))
    print(colored("-cyberpands", "red"))

def check_zeek():
    """
    Check if Zeek is installed.
    """
    command = ["which", "zeek"]
    result = subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if result == 0:
        success_op("Zeek checked and is installed.")
        input_file()
    else:
        fail_op("Zeek not installed.")

def input_file():
    """
    Take pcap file as input from the user.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("-r", "--read", help="Read pcap file", required=True)
    args = parser.parse_args()
    result = args.read
    if os.path.exists(result):
        mid_op("Zeek pcap process initialized...")
        zeek_pcap_process(result)
    else:
        fail_op("File does not exist!")

def zeek_pcap_process(pcap_file):
    """
    Process the pcap file using Zeek and generate log files.
    """
    log_folder_name = 'zeek_logs'
    os.makedirs(log_folder_name, exist_ok=True)
    success_op("zeek_log folder created and copying the pcap file...")

    command2 = ['cp', pcap_file, log_folder_name]
    current_file_path = pathlib.Path.cwd()
    path = pathlib.Path(f'{current_file_path}/{log_folder_name}/{pcap_file}')
    if path.exists():
        fail_op(f"pcap file already exists in {log_folder_name} folder.")
    else:
        subprocess.call(command2, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        success_op("pcap file copied and waiting for zeek command to run...")

    command3 = ["zeek", "-C", "-r", f"{log_folder_name}/{pcap_file}", "LogAscii::use_json=T"]
    cmd3_res = subprocess.call(command3)
    if cmd3_res == 0:
        success_op(f"Log files generated for processing in {log_folder_name} folder.")
        for file in current_file_path.glob("*.log"):
            file.rename(current_file_path / log_folder_name / file.name)
        zeek_json_to_csv(log_folder_name)
    else:
        fail_op("Error processing pcap file.")

def zeek_json_to_csv(logs_folder):
    """
    Convert Zeek log files from JSON to CSV format.
    """
    root_folder = pathlib.Path.cwd()
    process_files = pathlib.Path(f"{root_folder}/{logs_folder}").glob("*.log")
    mid_op("Converting logs into csv...")
    try:
        for filename in process_files:
            with open(filename) as f:
                for line in f.readlines():
                    json_data = json.loads(line)
                    headers = json_data.keys()
                    with open(f"./{logs_folder}/{filename.name[:-4]}.csv", "w+") as csv_file:
                        writer = csv.DictWriter(csv_file, fieldnames=headers)
                        writer.writeheader()
                        writer.writerow(json_data)
        success_op("Successfully converted logs into csv for next phase.")
        ioc_extractor.ioc_extract(logs_folder)
    except Exception as e:
        fail_op(f"Error converting log file into csv: {e}")

def main():
    """
    Main function to run the AI Log Analyser.
    """
    display_banner()
    check_zeek()

if __name__ == '__main__':
    main()
