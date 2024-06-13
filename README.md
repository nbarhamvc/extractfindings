**Credit to Ricardo P for this script**

Gets count of ALL findings for all available application profiles. Also includes latest scan names and dates.

*Note*: This script requires Python 3!

## Setup

Clone this repository:

    git clone https://github.com/nbarhamvc/extractfindings

Install dependencies:

    cd extractfindings
    pip install -r requirements.txt

(Optional) Save Veracode API credentials in `~/.veracode/credentials`

    [default]
    veracode_api_key_id = <YOUR_API_KEY_ID>
    veracode_api_key_secret = <YOUR_API_KEY_SECRET>

## Run

If you have saved credentials as above you can run:

    py extract_finding_totals.py (arguments)

Otherwise you will need to set environment variables:

    export VERACODE_API_KEY_ID=<YOUR_API_KEY_ID>
    export VERACODE_API_KEY_SECRET=<YOUR_API_KEY_SECRET>
    py extract_finding_totals.py (arguments)

Arguments supported include:
- `-t`, `--target` - (mandatory) File to save results - must be .csv.
- `-d`, `--dast` Set to enable fetching of DAST results.
- `-s`, `--sca` Set to enable fetching of SCA results.
- `-c`, `--custom` Comma-delimited list of custom fields to fetch.
- `-v`, `--verbose` Set to enable verbose logging.

## Results
The results will be saved to a .csv file.  
