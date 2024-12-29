# CVE Query Tool

This tool retrieves Common Vulnerabilities and Exposures (CVE) data from the National Vulnerability Database (NVD) API and stores it in a local cache for efficient retrieval. The results are then exported to an Excel spreadsheet.

## Features

* **Efficient CVE Retrieval:** Queries the NVD API for CVE information.
* **Local Caching:** Stores CVE data in a local SQLite database to reduce API calls and improve performance.
* **Excel Export:** Exports the retrieved CVE data to an Excel spreadsheet for analysis and reporting.
* **Rate Limiting:** Implements throttling to avoid exceeding the NVD API rate limits.
* **Error Handling:** Includes robust error handling and logging for debugging and troubleshooting.
* **Retry Mechanism:** Retries failed CVE lookups due to temporary errors.

## Requirements

* Python 3.7 or higher
* Required Python packages:
    * pandas
    * aiosqlite
    * aiohttp
    * openpyxl

## Installation

1. Install the required packages:
```bash
pip install -r requirements.txt
```


## Usage
Obtain an NVD API Key:
Register for an account on the NVD website.
Generate an API key in your account settings.

Prepare the CVE Input File:

Create a text file named cve_list.txt in the input directory.

List the CVE numbers you want to query, one per line, with a header row.
```text
CVE ID
CVE-2023-1234
CVE-2023-5678
```


Run the script:
```bash
python cve_query.py --api_key <your_api_key> --cve_file input/cve_list.txt
```


Replace <your_api_key> with your actual NVD API key.
If you don't provide the --api_key or --cve_file arguments, the script will prompt you to enter them.

Output:
The script will create an Excel file named cve_data_<timestamp>.xlsx in the output directory containing the retrieved CVE data.

A log file named cve_query_<timestamp>.log will be created in the logs directory for debugging and troubleshooting.
