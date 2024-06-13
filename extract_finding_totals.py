# Credit to Ricardo P for this script

import sys
import requests
import argparse
import csv
import time
import os.path
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
    print("""extractfindings.py -t <target_file(.csv)> [-d] [-s] [-d]
        Gets count of ALL findings for all available application profiles, including latest scan names and dates, and saves it to <target_file>""")
    print("Optional arguments: ")
    print(" -d: set to enable fetching of DAST results")
    print(" -s: set to enable fetching of SCA results")
    print(" -v: to output verbose logs")
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

def get_findings_for_app_and_scan_type(application, page, rest_api_base, scan_type, verbose):
    print(f"Getting findings for application {application['profile']['name']} - page {page}")
    path = f"{rest_api_base}appsec/v2/applications/{application['guid']}/findings?scan_type={scan_type}&page={page}"

    if verbose:
        print(f"Calling API at {path}")

    response = requests.get(path, auth=RequestsAuthPluginVeracodeHMAC(), headers=json_header)

    body = response.json()
    if verbose:
        print(f"status code {response.status_code}")
        if body:
            print(body)
    if response.status_code == 200:
        print(f"Successfully obtained {scan_type} findings page {page}")
        if "_embedded" in body and "findings" in body["_embedded"]:
            findings = body["_embedded"]["findings"]
            if has_more_pages(body):
                return findings + get_findings_for_app_and_scan_type(application, page+1, rest_api_base, scan_type, verbose)
            else:
                return findings
        return []
    elif response.status_code == 429:
        handle_throttling()
        return get_findings_for_app_and_scan_type(application, page, rest_api_base, scan_type, verbose)
    else:
        print(f"Unable to obtain {scan_type} findings: {response.status_code}")
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

def get_findings_totals(application, rest_api_base, scan_type, verbose):
    findings = get_findings_for_app_and_scan_type(application, 0, rest_api_base, scan_type, verbose)
    findings_totals = {
        "open": {
            "very_high": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "very_low": 0,
            "informational": 0
        },
        "closed": {
            "very_high": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "very_low": 0,
            "informational": 0
        }
    }

    for finding in findings:
        open_or_closed = "open" if finding['finding_status']['status'] == "OPEN" else "closed"
        severity = ''
        match finding['finding_details']['severity']:
            case 5:
                severity = 'very_high'
            case 4:
                severity = 'high'
            case 3:
                severity = 'medium'
            case 2:
                severity = 'low'
            case 1:
                severity = 'very_low'
            case 0:
                severity = 'informational'
        findings_totals[open_or_closed][severity] += 1

    return findings_totals

def parse_custom_fields(custom_fields_node):
    custom_fields_dict = {}
    if custom_fields_node:
        for custom_field in custom_fields_node:
            custom_fields_dict[custom_field["name"]] = custom_field["value"]

    return custom_fields_dict

def get_application_results(application, rest_api_base, xml_api_base, custom_field_list, is_dast, is_sca, verbose):
    sast_totals = get_findings_totals(application, rest_api_base, "STATIC", verbose)
    if is_dast:
        dast_totals = get_findings_totals(application, rest_api_base, "DYNAMIC", verbose)
    if is_sca: 
        sca_totals = get_findings_totals(application, rest_api_base, "SCA", verbose)

    scans = application["scans"]
    latest_sast_scan = ''
    latest_dast_scan = ''
    for scan in scans:
        scan_date = scan["modified_date"]
        if scan["scan_type"] == "DYNAMIC":
            latest_dast_scan = scan_date
        else:
            latest_sast_scan = scan_date

    results = {
        'Application Name': application["profile"]["name"],
        'Application ID': application["id"],
        'Application GUID': application["guid"],

    }

    if custom_field_list and "custom_fields" in application["profile"]:
        custom_fields_dict = parse_custom_fields(application["profile"]["custom_fields"])
        for custom_field in custom_field_list:
            if custom_field in custom_fields_dict:
                results[custom_field] = custom_fields_dict[custom_field]
            else:
                results[custom_field] = ''

    results.update({        
        'Latest SAST Scan Name': get_latest_scan_name(xml_api_base, application, verbose),
        'Latest SAST Scan Date': latest_sast_scan
    })
    if is_dast:
        results['Latest DAST Scan Date'] = latest_dast_scan

    results.update({        
            'SAST - Very High Findings (Open)': sast_totals["open"]["very_high"],
            'SAST - High Findings (Open)': sast_totals["open"]["high"],
            'SAST - Medium Findings (Open)': sast_totals["open"]["medium"],
            'SAST - Low Findings (Open)': sast_totals["open"]["low"],
            'SAST - Very Low Findings (Open)': sast_totals["open"]["very_low"],
            'SAST - Informational Findings (Open)': sast_totals["open"]["informational"],

            'SAST - Very High Findings (Closed)': sast_totals["open"]["very_high"],
            'SAST - High Findings (Closed)': sast_totals["open"]["high"],
            'SAST - Medium Findings (Closed)': sast_totals["open"]["medium"],
            'SAST - Low Findings (Closed)': sast_totals["open"]["low"],
            'SAST - Very Low Findings (Closed)': sast_totals["open"]["very_low"],
            'SAST - Informational Findings (Closed)': sast_totals["open"]["informational"], 
        })
    if is_dast:
        results.update({
            'DAST - Very High Findings (Open)': dast_totals["open"]["very_high"],
            'DAST - High Findings (Open)': dast_totals["open"]["high"],
            'DAST - Medium Findings (Open)': dast_totals["open"]["medium"],
            'DAST - Low Findings (Open)': dast_totals["open"]["low"],
            'DAST - Very Low Findings (Open)': dast_totals["open"]["very_low"],
            'DAST - Informational Findings (Open)': dast_totals["open"]["informational"],

            'DAST - Very High Findings (Closed)': dast_totals["open"]["very_high"],
            'DAST - High Findings (Closed)': dast_totals["open"]["high"],
            'DAST - Medium Findings (Closed)': dast_totals["open"]["medium"],
            'DAST - Low Findings (Closed)': dast_totals["open"]["low"],
            'DAST - Very Low Findings (Closed)': dast_totals["open"]["very_low"],
            'DAST - Informational Findings (Closed)': dast_totals["open"]["informational"]   
        })
    if is_sca:
        results.update({
            'SCA - Very High Findings (Open)': sca_totals["open"]["very_high"],
            'SCA - High Findings (Open)': sca_totals["open"]["high"],
            'SCA - Medium Findings (Open)': sca_totals["open"]["medium"],
            'SCA - Low Findings (Open)': sca_totals["open"]["low"],
            'SCA - Very Low Findings (Open)': sca_totals["open"]["very_low"],
            'SCA - Informational Findings (Open)': sca_totals["open"]["informational"],

            'SCA - Very High Findings (Closed)': sca_totals["open"]["very_high"],
            'SCA - High Findings (Closed)': sca_totals["open"]["high"],
            'SCA - Medium Findings (Closed)': sca_totals["open"]["medium"],
            'SCA - Low Findings (Closed)': sca_totals["open"]["low"],
            'SCA - Very Low Findings (Closed)': sca_totals["open"]["very_low"],
            'SCA - Informational Findings (Closed)': sca_totals["open"]["informational"]   
        })

    return results

def save_to_excel(applications, file_name):
    directory = os.path.dirname(file_name)
    if directory and not os.path.exists(directory):
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

def save_all_scan_results(rest_api_base, xml_api_base, target_file, custom_fields, is_dast, is_sca, verbose):
    _, extension = os.path.splitext(target_file)
    if not extension or extension.lower() != ".csv":
        print(f"ERROR: File name '{target_file}' needs to be a CSV file.")
        sys.exit(-1)

    custom_field_list = []
    if custom_fields:
        for custom_field in custom_fields.split(","):
            custom_field_list.append(custom_field.strip())

    applications = []
    for application in get_all_applications(rest_api_base, 0, verbose):
        applications.append(get_application_results(application, rest_api_base, xml_api_base, custom_field_list, is_dast, is_sca, verbose))

    save_to_excel(applications, target_file)

def main():
    try:        

        parser = argparse.ArgumentParser(
        description='This script will create an excel file with a summary of all your SAST scans')
        
        parser.add_argument('-t', '--target', help='CSV file to save results')
        parser.add_argument('-d', '--dast', action='store_true', help='Set to enable fetching of DAST results')
        parser.add_argument('-s', '--sca', action='store_true', help='Set to enable fetching of SCA results')
        parser.add_argument('-c', '--customfields', help='Comma-delimited list of custom fields to fetch')
        parser.add_argument('-v', '--verbose', action='store_true', help='Set to enable verbose logging')

        args = parser.parse_args()

        target_file = args.target
        is_dast = args.dast
        is_sca = args.sca
        custom_fields = args.customfields
        verbose = args.verbose

        rest_api_base = get_rest_api_base() 
        xml_api_base = get_xml_api_base()
        save_all_scan_results(rest_api_base, xml_api_base, target_file, custom_fields, is_dast, is_sca, verbose)

    except requests.RequestException as e:
        print("An error occurred!")
        print(e)
        sys.exit(1)


if __name__ == "__main__":
    main()
