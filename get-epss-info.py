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
    "User-Agent": "EPSS info extractor",
    "Content-Type": "application/json"
}


def print_help():
    print("""get-epss-info.py -t <target_folder> [-a] [-u] [-d]
        Saves the EPSS info for all findings available at the Veracode platform into a folder located at <target_folder>
""")
    print("Optional arguments: ")
    print(" -a: to extract information from all SCA agent scans")
    print(" -u: to extract information from all SCA upload scans")
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

def get_all_workspaces(api_base, page, verbose):
    print(f"Getting workspaces - page {page}")
    path = f"{api_base}srcclr/v3/workspaces?page={page}"

    if verbose:
        print(f"Calling API at {path}")

    response = requests.get(path, auth=RequestsAuthPluginVeracodeHMAC(), headers=headers)

    body = response.json()
    if verbose:
        print(f"status code {response.status_code}")
        if body:
            print(body)
    if response.status_code == 200:
        print(f"Successfully obtained workspace page {page}")
        if "_embedded" in body and "workspaces" in body["_embedded"]:
            workspaces = body["_embedded"]["workspaces"]
            if has_more_pages(body):
                return workspaces + get_all_workspaces(api_base, page+1, verbose)
            else:
                return workspaces
        return []
    elif response.status_code == 429:
        handle_throttling()
        return get_all_workspaces(api_base, page, verbose)
    else:
        print(f"Unable to obtain workspace list: {response.status_code}")
        return []
    
def get_all_projects_for_workspace(api_base, page, workspace, verbose):
    print(f"Getting projects for workspace {workspace['name']} - page {page}")
    path = f"{api_base}srcclr/v3/workspaces/{workspace['id']}/projects?page={page}"

    if verbose:
        print(f"Calling API at {path}")

    response = requests.get(path, auth=RequestsAuthPluginVeracodeHMAC(), headers=headers)

    body = response.json()
    if verbose:
        print(f"status code {response.status_code}")
        if body:
            print(body)
    if response.status_code == 200:
        print(f"Successfully obtained project page {page}")
        if "_embedded" in body and "projects" in body["_embedded"]:
            projects = body["_embedded"]["projects"]
            if has_more_pages(body):
                return projects + get_all_projects_for_workspace(api_base, page+1, workspace, verbose)
            else:
                return projects
        return []
    elif response.status_code == 429:
        handle_throttling()
        return get_all_projects_for_workspace(api_base, page, workspace, verbose)
    else:
        print(f"Unable to obtain project list: {response.status_code}")
        return []


def get_epss_for_application_findings_internal(application, page, api_base, verbose):
    print(f"Getting findings for application {application['profile']['name']} - page {page}")
    path = f"{api_base}appsec/v2/applications/{application['guid']}/findings?scan_type=SCA&page={page}"

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
                return findings + get_epss_for_application_findings_internal(application, page+1, api_base, verbose)
            else:
                return findings
        return []
    elif response.status_code == 429:
        handle_throttling()
        return get_epss_for_application_findings_internal(application, page, api_base, verbose)
    else:
        print(f"Unable to obtain findings: {response.status_code}")
        return []

def get_epss_for_agent_issues_internal(workspace, project, page, api_base, verbose):
    print(f"Getting SCA issues for workspace {workspace['name']} & project {project['name']} - page {page}")
    path = f"{api_base}srcclr/v3/workspaces/{workspace['id']}/projects/{project['id']}/issues?page={page}"

    if verbose:
        print(f"Calling API at {path}")

    response = requests.get(path, auth=RequestsAuthPluginVeracodeHMAC(), headers=headers)

    body = response.json()
    if verbose:
        print(f"status code {response.status_code}")
        if body:
            print(body)
    if response.status_code == 200:
        print(f"Successfully obtained issues page {page}")
        if "_embedded" in body and "issues" in body["_embedded"]:
            findings = body["_embedded"]["issues"]
            if has_more_pages(body):
                return findings + get_epss_for_agent_issues_internal(workspace, project, page+1, api_base, verbose)
            else:
                return findings
        return []
    elif response.status_code == 429:
        handle_throttling()
        return get_epss_for_agent_issues_internal(workspace, project, page, api_base, verbose)
    else:
        print(f"Unable to obtain findings: {response.status_code}")
        return []


def parse_epss(exploitability):
    epss_status = exploitability['epss_status'] 
    if epss_status == 'match found':
        return {'epss_score': exploitability['epss_score'],
                'epss_percentile': exploitability['epss_percentile'],
                'epss_model_version': exploitability['epss_model_version']}
    return {'epss_score': epss_status ,
            'epss_percentile': epss_status,
            'epss_model_version': epss_status}

def parse_cwe(finding_details):
    if ("cwe" in finding_details):
        return f"CWE-{finding_details['cwe']['id']} - {finding_details['cwe']['name']}"
    return "unavailable"

def parse_finding(finding):
    finding_row = { 'Description': finding['description'], 
                    'Status': finding['finding_status']['status'],
                    'First Found Date': finding['finding_status']['first_found_date'],
                    'Component File Name': finding['finding_details']['component_filename'],
                    'Component Version': finding['finding_details']['version'],
                    'CWE': parse_cwe(finding['finding_details']),
                    'CVE': finding['finding_details']['cve']['name'],
                    'CVSS 2': finding['finding_details']['cve']['cvss'],
                    'CVSS 3': f"{finding['finding_details']['cve']['cvss3']['score']} ({finding['finding_details']['cve']['cvss3']['severity']})" }
    epss = parse_epss(finding['finding_details']['cve']['exploitability'])
    finding_row['EPSS Score'] = epss['epss_score']
    finding_row['EPSS Percentile'] = epss['epss_percentile']
    finding_row['EPSS Model Version'] = epss['epss_model_version']
    return finding_row

def get_epss_for_application_findings(application, api_base, verbose):
    base_findings = get_epss_for_application_findings_internal(application, 1, api_base, verbose)
    parsed_list = []
    for finding in base_findings:
        parsed_list.append(parse_finding(finding))

    return parsed_list

def get_issue_optional_field(root, field_to_find):
    if field_to_find in root:
        return root[field_to_find]
    return "unavailable"

def parse_issue(issue):
    vulnerability = issue['vulnerability']
    issue_row = { 'Title': get_issue_optional_field(vulnerability, 'title'), 
                  'Status': issue['issue_status'],
                  'First Found Date': issue['created_date'],
                  'Library Name': issue['library']['name'],
                  'Library ID': issue['library']['id'],
                  'Library Version': issue['library']['version'],
                  'CWE': get_issue_optional_field(vulnerability, "cwe_id"),
                  'CVE': get_issue_optional_field(vulnerability, "cve"),
                  'CVSS 2': get_issue_optional_field(vulnerability, 'cvss2_score'),
                  'CVSS 3': get_issue_optional_field(vulnerability, 'cvss3_score') }
    if 'exploitability' in vulnerability:
        epss = parse_epss(vulnerability['exploitability'])
    else:
        epss = parse_epss({'epss_status': "unavailable"})
    issue_row['EPSS Score'] = epss['epss_score']
    issue_row['EPSS Percentile'] = epss['epss_percentile']
    issue_row['EPSS Model Version'] = epss['epss_model_version']
    return issue_row
    

def get_epss_for_agent_issues(workspace, project, api_base, verbose):
    base_issues = get_epss_for_agent_issues_internal(workspace, project, 1, api_base, verbose)
    parsed_list = []
    for issue in base_issues:
        if issue['issue_type'] == "vulnerability":
            parsed_list.append(parse_issue(issue))

    return parsed_list

def save_epss_info(findings, folder, file_name):
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
        save_epss_info(get_epss_for_application_findings(application, api_base, verbose), os.path.join(targetFolder), application["profile"]["name"] + '.csv')

def save_all_agent_scans(api_base, targetFolder, verbose):
    for workspace in get_all_workspaces(api_base, 0, verbose):
        for project in get_all_projects_for_workspace(api_base, 0, workspace, verbose):
            save_epss_info(get_epss_for_agent_issues(workspace, project, api_base, verbose), os.path.join(targetFolder, workspace['name']), project['name'] + '.csv')

def main():
    try:        

        parser = argparse.ArgumentParser(
        description='This script will parse all available Agent/Upload SCA results and save the results to CSV files.'
                    ' This will also save the EPSS info for the findings')
        
        parser.add_argument('-t', '--target', help='Folder to save results')
        parser.add_argument('-a', '--agent', action='store_true', help='Set to import results from Agent-based SCA')
        parser.add_argument('-u', '--upload', action='store_true', help='Set to import results from Upload and Sca SCA')
        parser.add_argument('-d', '--debug', action='store_true', help='Set to enable verbose logging')

        args = parser.parse_args()

        targetFolder = args.target
        isAgentScan = args.agent
        isUploadScan = args.upload
        verbose = args.debug

        api_base = get_api_base()
        if not isAgentScan and not isUploadScan:
            print_help()
        else:
            if isUploadScan:
                save_all_upload_scans(api_base, targetFolder, verbose)
            if isAgentScan:
                save_all_agent_scans(api_base, targetFolder, verbose)

    except requests.RequestException as e:
        print("An error occurred!")
        print(e)
        sys.exit(1)


if __name__ == "__main__":
    main()
