# Veracode-Get-EPSS-Info

Gets all the SCA findings available to the user, including EPSS scores and percentiles:

*Note*: This script requires Python 3!

## Setup

Clone this repository:

    git clone https://github.com/cadonuno/Veracode-Get-EPSS-Info

Install dependencies:

    cd Veracode-Get-EPSS-Info
    pip install -r requirements.txt

(Optional) Save Veracode API credentials in `~/.veracode/credentials`

    [default]
    veracode_api_key_id = <YOUR_API_KEY_ID>
    veracode_api_key_secret = <YOUR_API_KEY_SECRET>

## Run

If you have saved credentials as above you can run:

    python get-epss-info.py (arguments)

Otherwise you will need to set environment variables:

    export VERACODE_API_KEY_ID=<YOUR_API_KEY_ID>
    export VERACODE_API_KEY_SECRET=<YOUR_API_KEY_SECRET>
    python get-epss-info.py (arguments)

Arguments supported include:
- `-t`, `--target` - (mandatory) Folder to save results.
- `-a`, `--agent` - Set to import results from Agent-based SCA.
- `-u`, `--upload` - Set to import results from Upload and Sca SCA.
- `-d`, `--debug` Set to enable verbose logging.

At least one of the 2 import options need to be set: -a (--agent) or -u (--upload)