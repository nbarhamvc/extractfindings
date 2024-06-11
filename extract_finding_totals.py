# Credit to Ricardo P for this script

import sys
import requests
import argparse
import csv
import time
import os.path
from pathlib import Path
from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC
from veracode_api_signing.credentials import get_credentials
import xml.dom.minidom as xml

json_header = {
    "User-Agent": "Findings extractor",
    "Content-Type": "application/json"
}

xml_header = {
    "User-Agent": "Bulk application creation - python script",
    "Content-Type": "application/xml"
}

def print_help():
    print("""extractfindings.py -t <target_folder> [-a] [-u] [-d]
        Extracts SAST findings (High/Very High) for all access app profiles on the Veracode platform into a folder""")
    print("Optional arguments: ")
    print(" -u: to extract findings from app profiles")
    print(" -d: to output debug-level logs")
    sys.exit()

def get_rest_api_base():
    api_key_id, api_key_secret = get_credentials()
    if api_key_id.startswith("vera01"):
        return "https://api.veracode.eu/"
    else:
        return "https://api.veracode.com/"
    
def get_xml_api_base():
    api_key_id, api_key_secret = get_credentials()
    if api_key_id.startswith("vera01"):
        return "https://analysiscenter.veracode.eu/api/5.0/"
    else:
        return "https://analysiscenter.veracode.com/api/5.0/"

def handle_throttling():
    print("429 returned, waiting 1 minute")
    time.sleep(60)

def has_more_pages(body):
    return body["page"]["number"]+1 < body["page"]["total_pages"]

def get_all_applications(rest_api_base, page, verbose):
    print(f"Getting applications - page {page}")
    path = f"{rest_api_base}appsec/v1/applications?page={page}"

    if verbose:
        print(f"Calling API at {path}")

    response = requests.get(path, auth=RequestsAuthPluginVeracodeHMAC(), headers=json_header)

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
                return applications + get_all_applications(rest_api_base, page+1, verbose)
            else:
                return applications
        return []
    elif response.status_code == 429:
        handle_throttling()
        return get_all_applications(rest_api_base, page, verbose)
    else:
        print(f"Unable to obtain application list: {response.status_code}")
        return []

def get_findings_for_app(application, page, rest_api_base, verbose):
    print(f"Getting findings for application {application['profile']['name']} - page {page}")
    path = f"{rest_api_base}appsec/v2/applications/{application['guid']}/findings?scan_type=Static&severity_gte=4&page={page}"

    if verbose:
        print(f"Calling API at {path}")

    response = requests.get(path, auth=RequestsAuthPluginVeracodeHMAC(), headers=json_header)

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
                return findings + get_findings_for_app(application, page+1, rest_api_base, verbose)
            else:
                return findings
        return []
    elif response.status_code == 429:
        handle_throttling()
        return get_findings_for_app(application, page, rest_api_base, verbose)
    else:
        print(f"Unable to obtain findings: {response.status_code}")
        return []

def get_latest_scan_name(xml_api_base, application, verbose):
    print(f"Getting latest scan for application {application['profile']['name']}")
    path = f"{xml_api_base}getbuildlist.do?app_id={application['id']}"

    if verbose:
        print(f"Calling API at {path}")

    response = requests.get(path, auth=RequestsAuthPluginVeracodeHMAC(), headers=xml_header)

    body = response.content
    if verbose:
        print(f"status code {response.status_code}")
        if body:
            print(body)
    if response.status_code == 200:
        print(f"Successfully obtained application info")
        document = xml.parseString(body)
        if document.childNodes:
            builds = document.childNodes[0].getElementsByTagName("build")
            if builds:
                return builds[0].getAttribute("version")
        return ""
    elif response.status_code == 429:
        handle_throttling()
        return get_latest_scan_name(xml_api_base, application, verbose)
    else:
        print(f"Unable to obtain application information: {response.status_code}")
        return ""

def get_application_results(application, rest_api_base, xml_api_base, verbose):
    base_findings = get_findings_for_app(application, 0, rest_api_base, verbose)
    total_open_very_high = 0
    total_open_high = 0
    total_closed_very_high = 0
    total_closed_high = 0

    for finding in base_findings:
        if finding['finding_status']['status'] == "OPEN":
            if finding['finding_details']['severity'] == 5:
                total_open_very_high += 1
            elif finding['finding_details']['severity'] == 4:
                total_open_high += 1
        else:
            if finding['finding_details']['severity'] == 5:
                total_closed_very_high += 1
            elif finding['finding_details']['severity'] == 4:
                total_closed_high += 1

    return {
        'Application Name': application["profile"]["name"],
        'Very High Findings (Open)': total_open_very_high,
        'High Findings (Open)': total_open_high,
        'Very High Findings (Closed)': total_closed_very_high,
        'High Findings (Closed)': total_closed_high,
        'Last Scan Name': get_latest_scan_name(xml_api_base, application, verbose)
    }

def save_to_excel(applications, file_name):
    directory = os.path.dirname(file_name)
    if not os.path.exists(directory):
        os.makedirs(directory)
    if applications:
        with open(file_name, 'w', newline='') as csvfile:
            csv_writer = csv.writer(csvfile)

            csv_writer.writerow(applications[0].keys())
            for entry in applications:
                csv_writer.writerow(entry.values())
            print(f"File {file_name} saved")
    else:
        print(f"ERROR: No findings found")

def save_all_upload_scans(rest_api_base, xml_api_base, target_file, verbose):
    _, extension = os.path.splitext(target_file)
    if not extension or extension.lower() != ".csv":
        print(f"ERROR: File name '{target_file}' needs to be a CSV file.")
        sys.exit(-1)

    applications = []
    for application in get_all_applications(rest_api_base, 0, verbose):
        applications.append(get_application_results(application, rest_api_base, xml_api_base, verbose))

    save_to_excel(applications, target_file)

def main():
    try:        

        parser = argparse.ArgumentParser(
        description='This script will create an excel file with a summary of all your SAST scans')
        
        parser.add_argument('-t', '--target', help='CSV file to save results')
        parser.add_argument('-d', '--debug', action='store_true', help='Set to enable verbose logging')

        args = parser.parse_args()

        target_file = args.target
        verbose = args.debug

        rest_api_base = get_rest_api_base() 
        xml_api_base = get_xml_api_base()
        save_all_upload_scans(rest_api_base, xml_api_base, target_file, verbose)

    except requests.RequestException as e:
        print("An error occurred!")
        print(e)
        sys.exit(1)


if __name__ == "__main__":
    main()
