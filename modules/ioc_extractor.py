import pathlib
import pandas as pd
import os
from modules.message_log import success_op, fail_op, mid_op

def data_ext(file_val, data_col):
    """
    Extract specified columns from the given CSV file.
    """
    final_data = pd.read_csv(file_val, na_values="-")
    for col in data_col:
        if col not in final_data.columns:
            final_data[col] = "-"
    final_data = final_data[data_col]
    return final_data

def process_file(filename):
    """
    Process a single log file based on its name and extract relevant data.
    """
    file_mapping = {
        "conn.csv": ['id.orig_h', 'id.resp_h', 'id.resp_p', 'proto', 'orig_bytes', 'resp_bytes'],
        "dns.csv": ['query', 'answers'],
        "http.csv": ['host', 'uri', 'referrer', 'user_agent', 'method'],
        "ssl.csv": ["issuer", "ja3"],
        "files.csv": ['md5', 'sha256', 'mime_type'],
        "weird.csv": ['name', 'id.orig_h', 'if.resp_h'],
        "dpd.csv": ['proto', 'id.orig_h', 'if.resp_h'],
        "ocsp.csv": ['certStatus', 'issuerNameHash', 'issuerKeyHash'],
        "x509.csv": ['certificate.issuer', 'certificate.subject', 'fingerprint'],
        "kerberos.csv": ['client', 'server', 'service'],
        "ntlm.csv": ['username', 'client', 'server'],
        "rdp.csv": ['id.orig_h', 'id.resp_h', 'username'],
        "smb.csv": ['id.orig_h', 'id.resp_h', 'filename'],
        "ftp.csv": ['filename', 'id.orig_h', 'if.resp_h'],
        "modbus.csv": ['function_code', 'id.orig_h', 'if.resp_h'],
        "analyzer.csv": ['alert_type', 'id.orig_h', 'if.resp_h', 'description'],
        "intel.csv": ['indicator', 'indicator_type'],
        "notice.csv": ['cause', 'id.orig_h', 'if.resp_h', 'failure_reason']
    }

    if filename.name in file_mapping:
        required_cols = file_mapping[filename.name]
        extracted_data = data_ext(filename, required_cols)
        if filename.name == "dns.csv":
            extracted_data = extracted_data.map(lambda x: x.strip("[]'") if isinstance(x, str) else x)
        return extracted_data
    return None

def ioc_extract(log_folder_name):
    """
    Extract IOCs from the specified log folder and save them to a CSV file.
    """
    root_folder = pathlib.Path(__file__).parent
    process_files = pathlib.Path(f"{root_folder}/../{log_folder_name}").glob("*.csv")
    df_list = []
    ioc_file = "extracted_iocs.csv"
    ioc_file_extract = pathlib.Path(f"{root_folder}/../{ioc_file}").resolve()
    
    with open(ioc_file_extract, "w+") as f:
        for filename in process_files:
            if os.path.exists(filename):
                extracted_data = process_file(filename)
                if extracted_data is not None:
                    df_list.append(extracted_data)
            else:
                print("File path does not exist")
        
        if df_list:
            df_final = pd.concat(df_list, axis=1, join="inner").drop_duplicates()
            df_final.to_csv(f, index=False)
            success_op("Successfully extracted IOCs")
    
    import modules.threat_intel as threat_intel
    threat_intel.check_api_key(ioc_file_extract)

# The module can now be imported and used in other scripts