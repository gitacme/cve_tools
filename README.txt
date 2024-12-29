CVE Query Tool
This tool retrieves Common Vulnerabilities and Exposures (CVE) data from the National Vulnerability Database (NVD) API and stores it in a local cache for efficient retrieval. The results are then exported to an Excel spreadsheet.

Features:
Efficient CVE Retrieval
Local Caching
Excel Export
Rate Limiting
Error Handling
Retry Mechanism

Requirements:
Python 3.7 or higher
Required Python packages: pandas, aiosqlite, aiohttp, openpyxl

Installation:
Install the required packages: pip install -r requirements.txt

Usage:
Obtain an NVD API Key: Register for an account on the NVD website and generate an API key.
Prepare the CVE Input File: Create a text file named 'cve_list.txt' in the 'input' directory and list the CVE numbers you want to query, one per line, with a header row.

Run the script: python cve_query.py --api_key <your_api_key> --cve_file input/cve_list.txt

Output: The script will create an Excel file in the 'output' directory and a log file in the 'logs' directory.
