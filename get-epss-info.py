import sys
import requests
import getopt
import os
from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC

from veracode_api_signing.credentials import get_credentials

api_base = "https://api.veracode.{instance}/"
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

def update_api_base():
    api_key_id, api_key_secret = get_credentials()
    if api_key_id.startswith("vera01"):
        api_base = api_base.replace("{intance}", "eu", 1)
    else:
        api_base = api_base.replace("{intance}", "com", 1)

def save_all_upload_scans(targetFolder, verbose):
    for application in get_all_applications(verbose):
        save_epss_info(get_epss_for_application_findings(application), os.path.join(targetFolder, application['name'] + '.xls'), verbose)

def save_all_agent_scans(targetFolder, verbose):
    for workspace in get_all_workspaces(verbose):
        for project in get_all_projects_for_workspace(workspace):
            save_epss_info(get_epss_for_agent_issue(workspace, project), os.path.join(targetFolder, workspace['name'], project['name'] + '.xls'), verbose)

def main(argv):
    try:
        verbose = False
        isUploadScan = False
        isAgentScan = False
        targetFolder = None

        opts, args = getopt.getopt(argv, "hdaut:",
                                   ["help", "debug", "target"])
        for opt, arg in opts:
            if opt in ('-h', '--help'):
                print_help()
            elif opt in ('-d', '--debug'):
                verbose = True
            elif opt == 'a':
                isAgentScan = True
            elif opt == 'u':
                isUploadScan = True
            elif opt in ('-t', '--target'):
                targetFolder = arg


        update_api_base()
        if not isAgentScan and not isUploadScan:
            print_help()
        else:
            if isUploadScan:
                save_all_upload_scans(targetFolder, verbose)
            if isAgentScan:
                save_all_agent_scans(targetFolder, verbose)

    except requests.RequestException as e:
        print("An error occurred!")
        print(e)
        sys.exit(1)


if __name__ == "__main__":
    main(sys.argv[1:])
