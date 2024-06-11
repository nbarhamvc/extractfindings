Gets count of High/Very High SAST findings per applciation profile, including scan name and application profile name:

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

    python Veracodeextractfindings.py (arguments)

Otherwise you will need to set environment variables:

    export VERACODE_API_KEY_ID=<YOUR_API_KEY_ID>
    export VERACODE_API_KEY_SECRET=<YOUR_API_KEY_SECRET>
    python Veracodeextractfindings.py (arguments)

Arguments supported include:
- `-t`, `--target` - (mandatory) Folder to save results.
- `-d`, `--debug` Set to enable verbose logging.

## Results
The results will be saved to .csv files.  

- Results will be saved using the following format:

`<target_folder>/<application_name>.csv`
