# Credit to Ricardo P for this script

import sys
import requests
import argparse
import os
import csv
import time
from pathlib import Path
from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC
from veracode_api_signing.credentials import get_credentials

headers = {
    "User-Agent": "Findings extractor",
    "Content-Type": "application/json"
}

def print_help():
    print("""extractfindings.py -t <target_folder> [-a] [-u] [-d]
        Extracts SAST findings (High/Very High) for all access app profiles on the Veracode platform into a folder""")
    print("Optional arguments: ")
    print(" -u: to extract findings from app profiles")
    print(" -d: to output debug-level logs")
    sys.exit()

def get_api_base():
    api_key_id, api_key_secret = get_credentials()
    if api_key_id.startswith("vera01"):
        return "https://api.veracode.eu/"
    else:
        return "https://api.veracode.com/"

def handle_throttling():
    print("429 returned, waiting 1 minute")
    time.sleep(60)

def has_more_pages(body):
    return body["page"]["number"]+1 < body["page"]["total_pages"]

def get_all_applications(api_base, page, verbose):
    print(f"Getting applications - page {page}")
    path = f"{api_base}appsec/v1/applications?page={page}"

    if verbose:
        print(f"Calling API at {path}")

    response = requests.get(path, auth=RequestsAuthPluginVeracodeHMAC(), headers=headers)

    body = response.json()
    if verbose:
        print(f"status code {response.status_code}")
        if body:
            print(body)
    if response.status_code == 200:
        print(f"Successfully obtained applications page {page}")
        if "_embedded" in body and "applications" in body["_embedded"]:
            applications = body["_embedded"]["applications"]
            if has_more_pages(body):
                return applications + get_all_applications(api_base, page+1, verbose)
            else:
                return applications
        return []
    elif response.status_code == 429:
        handle_throttling()
        return get_all_applications(api_base, page, verbose)
    else:
        print(f"Unable to obtain application list: {response.status_code}")
        return []

def get_findings_for_app(application, page, api_base, verbose):
    print(f"Getting findings for application {application['profile']['name']} - page {page}")
    path = f"{api_base}appsec/v2/applications/{application['guid']}/findings?scan_type=Static&severity_gte=4&page={page}"

    if verbose:
        print(f"Calling API at {path}")

    response = requests.get(path, auth=RequestsAuthPluginVeracodeHMAC(), headers=headers)

    body = response.json()
    if verbose:
        print(f"status code {response.status_code}")
        if body:
            print(body)
    if response.status_code == 200:
        print(f"Successfully obtained findings page {page}")
        if "_embedded" in body and "findings" in body["_embedded"]:
            findings = body["_embedded"]["findings"]
            if has_more_pages(body):
                return findings + get_findings_for_app(application, page+1, api_base, verbose)
            else:
                return findings
        return []
    elif response.status_code == 429:
        handle_throttling()
        return get_findings_for_app(application, page, api_base, verbose)
    else:
        print(f"Unable to obtain findings: {response.status_code}")
        return []

def parse_finding(finding):
    if finding['finding_status']['status'] == 'CLOSED':
        return None
    
    finding_row = { 'CWEID': finding['finding_details']['cwe']['id'],
                    'CWEDetail': finding['finding_details']['cwe']['name'],
                    'CWESeverity': finding['finding_details']['severity'],
                    'FindingStatus': finding['finding_status']['status'],
                    'FindingStatus': finding['finding_status']['resolution_status'],
                    'FindingID': finding['finding_details']['finding_category']['id']
                }
    return finding_row

def get_flaws_for_application_findings(application, api_base, verbose):
    base_findings = get_findings_for_app(application, 0, api_base, verbose)
    parsed_list = []
    for finding in base_findings:
        parsed_finding=parse_finding(finding)
        if parsed_finding:
            parsed_list.append(parsed_finding)

    return parsed_list

def save_to_excel(findings, folder, file_name):
    Path(folder).mkdir(parents=True, exist_ok=True)
    file_name = file_name.replace("\\", " ").replace("/", " ")

    if findings:
        with open(os.path.join(folder, file_name), 'w', newline='') as csvfile:
            csv_writer = csv.writer(csvfile)

            csv_writer.writerow(findings[0].keys())
            for entry in findings:
                csv_writer.writerow(entry.values())
            print(f"File {file_name} saved")
    else:
        print(f"No findings for {file_name}, skipping it")

def save_all_upload_scans(api_base, targetFolder, verbose):
    for application in get_all_applications(api_base, 0, verbose):
        save_to_excel(get_flaws_for_application_findings(application, api_base, verbose), os.path.join(targetFolder), application["profile"]["name"] + '.csv')

def main():
    try:        

        parser = argparse.ArgumentParser(
        description='This script will parse all available Agent/Upload SCA results and save the results to CSV files.'
                    ' This will also save the EPSS info for the findings')
        
        parser.add_argument('-t', '--target', help='Folder to save results')
        parser.add_argument('-d', '--debug', action='store_true', help='Set to enable verbose logging')

        args = parser.parse_args()

        targetFolder = args.target
        verbose = args.debug

        api_base = get_api_base() 
        save_all_upload_scans(api_base, targetFolder, verbose)

    except requests.RequestException as e:
        print("An error occurred!")
        print(e)
        sys.exit(1)


if __name__ == "__main__":
    main()
