# CVE Query Script - Version 1.3.1
# Copyright 2024 Steve Fink
# This script queries its local caching database for the CVE information
# If the CVE info is not cached locally, it will query the NVD API for CVE data.
# It then stores results in the local cache, and outputs all the results to Excel.

import pandas as pd
import aiosqlite
import asyncio
import aiohttp
from datetime import datetime
import logging
import os
import argparse
from openpyxl import load_workbook
from openpyxl.styles import Font

# Ensure directory structure exists
os.makedirs('database', exist_ok=True)
os.makedirs('input', exist_ok=True)
os.makedirs('output', exist_ok=True)
os.makedirs('logs', exist_ok=True)

# Set up logging
log_dir = "logs"
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

# Use the same timestamp for both log and Excel files for correlation
timestamp = datetime.now().strftime("%m%d%Y_%H%M")
log_filename = f"{log_dir}/cve_query_{timestamp}.log"
logging.basicConfig(
    filename=log_filename,
    level=logging.DEBUG,  # Set the log level (e.g., INFO, WARNING, ERROR, DEBUG)
    format="%(asctime)s - %(levelname)s - %(message)s"
)

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)  # Log INFO and above to console
console_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
logging.getLogger().addHandler(console_handler)

# List to track CVEs that encounter 403 or 503 errors
retry_cves = []
failed_cves = []

# Function to handle multiple date formats
def parse_published_date(date_str):
    date_formats = [
        "%Y-%m-%dT%H:%M:%S.%fZ",  # Full format with fractional seconds and 'Z'
        "%Y-%m-%dT%H:%M:%S.%f",   # Without 'Z'
        "%Y-%m-%dT%H:%M:%S",      # No fractional seconds
        "%Y-%m-%d"                # Just the date
    ]
    for fmt in date_formats:
        try:
            return datetime.strptime(date_str, fmt)
        except ValueError:
            continue
    raise ValueError(f"Date format not supported: {date_str}")

# Function to query the cache database for CVEs
async def query_cache_all(conn, cve_numbers):
    cve_data_list = []
    remaining_cves = []
    try:
        async with conn.execute("SELECT * FROM cve_data WHERE cve_id IN ({})".format(
                ','.join(['?'] * len(cve_numbers))), cve_numbers) as cursor:
            async for row in cursor:
                cve_data_list.append({
                    "CVE Number": row[0],
                    "CVE Description": row[1],
                    "Date Published": row[2],
                    "Age (Days)": row[3],
                    "CVSS 3.1 Score": row[4]
                })
                print(f"Using cached data for {row[0]}")
                logging.info(f"Using cached data for {row[0]}")
    except Exception as e:
        logging.error(f"An error occurred while querying the cache: {e}")
    
    # Determine CVEs that are not in the cache
    cached_cve_ids = {cve_data["CVE Number"] for cve_data in cve_data_list}
    remaining_cves = [cve for cve in cve_numbers if cve not in cached_cve_ids]
    
    return cve_data_list, remaining_cves

# Function to insert CVE data into the cache
async def insert_into_cache(conn, cve_data):
    try:
        await conn.execute("""
            INSERT OR REPLACE INTO cve_data (cve_id, description, published_date, cve_age, severity)
            VALUES (?, ?, ?, ?, ?)
        """, (cve_data['CVE Number'], cve_data['CVE Description'], cve_data['Date Published'], cve_data['Age (Days)'], cve_data['CVSS 3.1 Score']))
        await conn.commit()
    except Exception as e:
        logging.error(f"An error occurred while inserting into cache: {e}")

# Async function to search for a CVE using the NVD API
async def search_cve(session, cve_number, api_key):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_number}"
    headers = {"apiKey": api_key}
    
    timeout = aiohttp.ClientTimeout(total=10)
    try:
        async with session.get(url, headers=headers, timeout=timeout) as response:
            if response.status == 503:
                print(f"Service unavailable for {cve_number}. HTTP Status: 503")
                logging.warning(f"Service unavailable for {cve_number}. HTTP Status: 503")
                retry_cves.append(cve_number)  # Track for retry
                return None
            elif response.status == 403:
                print(f"Rate limit exceeded for {cve_number}. HTTP Status: 403")
                logging.warning(f"Rate limit exceeded for {cve_number}. HTTP Status: 403")
                retry_cves.append(cve_number)  # Track for retry
                return None
            elif response.status == 404:
                print(f"Failed to fetch data for {cve_number}. HTTP Status: 404")
                logging.warning(f"Failed to fetch data for {cve_number}. HTTP Status: 404")
                failed_cves.append(cve_number)  # Track failed CVEs
                return None
            elif response.status != 200:
                print(f"Failed to fetch data for {cve_number}. HTTP Status: {response.status}")
                logging.warning(f"Failed to fetch data for {cve_number}. HTTP Status: {response.status}")
                failed_cves.append(cve_number)  # Track failed CVEs
                return None

            data = await response.json()
            results = data.get("vulnerabilities", [])
            if not results:
                print(f"No data available in NVD for {cve_number}")
                logging.info(f"No data available in NVD for {cve_number}")
                failed_cves.append(cve_number)  # Track failed CVEs
                return None

            cve_data_raw = results[0]["cve"]
            cve_id = cve_data_raw.get("id", "N/A")
            description = cve_data_raw.get("descriptions", [{}])[0].get("value", "N/A")
            published_date = cve_data_raw.get("published", "N/A")
            cve_age = (datetime.now() - parse_published_date(published_date)).days if published_date != "N/A" else "N/A"

            # Handling multiple CVSS versions, including the new CVSS v4.0
            metrics = cve_data_raw.get("metrics", {})
            severity = "N/A"
            if "cvssMetricV40" in metrics:
                severity = metrics["cvssMetricV40"][0].get("cvssData", {}).get("baseScore", "N/A")
            elif "cvssMetricV31" in metrics:
                severity = metrics["cvssMetricV31"][0].get("cvssData", {}).get("baseScore", "N/A")
            elif "cvssMetricV30" in metrics:
                severity = metrics["cvssMetricV30"][0].get("cvssData", {}).get("baseScore", "N/A")
            elif "cvssMetricV2" in metrics:
                severity = metrics["cvssMetricV2"][0].get("cvssData", {}).get("baseScore", "N/A")

            cve_data = {
                "CVE Number": cve_id,
                "CVE Description": description,
                "Date Published": published_date,
                "Age (Days)": cve_age,
                "CVSS 3.1 Score": severity
            }

            print(f"Fetched data from NVD for {cve_number}")
            logging.info(f"Fetched data from NVD for {cve_number}")
            return cve_data
    except aiohttp.ClientError as e:
        print(f"Network error occurred while fetching CVE-{cve_number}: {str(e)}")
        logging.error(f"Network error occurred while fetching CVE-{cve_number}: {str(e)}")
        failed_cves.append(cve_number)  # Track failed CVEs
    except Exception as e:
        print(f"An error occurred while fetching CVE-{cve_number}: {str(e)}")
        logging.error(f"An error occurred while fetching CVE-{cve_number}: {str(e)}")
        failed_cves.append(cve_number)  # Track failed CVEs
    return None

# Function to save data to Excel
def save_to_excel(data):
    filename = f"output/cve_data_{timestamp}.xlsx"  # Ensure synchronized timestamp for Excel
    df = pd.DataFrame(data)
    df.to_excel(filename, index=False)

    # Load the workbook to apply formatting
    workbook = load_workbook(filename)
    worksheet = workbook.active

    # Set font to Calibri and make headers bold
    header_font = Font(name='Calibri', bold=True)
    for cell in worksheet[1]:
        cell.font = header_font

    # Save the formatted workbook
    workbook.save(filename)
    print(f"Data successfully saved to {filename}")
    logging.info(f"Data successfully saved to {filename}")

    # Log failed CVEs if any
    if failed_cves:
        logging.error(f"Failed CVE lookups: {', '.join(failed_cves)}")
        print(f"Failed CVE lookups: {', '.join(failed_cves)}")

# Throttling function to manage rate limits
async def throttle_requests():
    print("Sleeping for 15 seconds to avoid rate limiting...")
    logging.info("Sleeping for 15 seconds to avoid rate limiting...")
    await asyncio.sleep(15)

# Main async function to handle querying both cache and NVD, with rate limiting
async def query_cves(cve_numbers, api_key, conn):
    # Query cache for all CVEs first
    cached_cve_data, remaining_cves = await query_cache_all(conn, cve_numbers)

    all_cve_data = cached_cve_data
    async with aiohttp.ClientSession() as session:
        total_cves = len(remaining_cves)
        for index, cve_number in enumerate(remaining_cves, start=1):
            # Query NVD for CVEs not in cache
            print(f"Querying NVD for {cve_number} ({index} out of {total_cves})")
            logging.info(f"Querying NVD for {cve_number} ({index} out of {total_cves})")
            cve_data = await search_cve(session, cve_number, api_key)
            if cve_data:
                all_cve_data.append(cve_data)
                await insert_into_cache(conn, cve_data)

            # Throttle requests by waiting between them (rate limit checking)
            if index % 22 == 0 and index > 0:
                await throttle_requests()

    return all_cve_data

# Function to retry CVEs that encountered errors
async def retry_failed_cves(api_key, conn):
    if retry_cves:
        print("Retrying failed CVEs due to errors...")
        logging.info("Retrying failed CVEs due to errors...")
        async with aiohttp.ClientSession() as session:
            total_retries = len(retry_cves)
            for index, cve_number in enumerate(retry_cves, start=1):
                print(f"Retrying NVD query for {cve_number} ({index} out of {total_retries})")
                logging.info(f"Retrying NVD query for {cve_number} ({index} out of {total_retries})")
                cve_data = await search_cve(session, cve_number, api_key)
                if cve_data:
                    await insert_into_cache(conn, cve_data)
                # Throttle requests by waiting between them (rate limit checking)
                if index % 22 == 0 and index > 0:
                    await throttle_requests()

# Function to read CVE numbers from a text file
def read_cve_file(file_path):
    try:
        with open(file_path, "r") as file:
            lines = file.readlines()
            return [line.strip() for line in lines[1:]]  # Skip header
    except FileNotFoundError:
        print(f"CVE file not found: {file_path}")
        logging.error(f"CVE file not found: {file_path}")
        raise
    except Exception as e:
        print(f"An error occurred while reading the CVE file: {e}")
        logging.error(f"An error occurred while reading the CVE file: {e}")
        raise

# Main async function to initialize the cache and handle CVE queries
async def main_async(api_key, cve_file):
    cve_numbers = read_cve_file(cve_file)
    try:
        conn = await aiosqlite.connect('database/cve_cache.db')
        await conn.execute('''
            CREATE TABLE IF NOT EXISTS cve_data (
                cve_id TEXT PRIMARY KEY,
                description TEXT,
                published_date TEXT,
                cve_age INTEGER,
                severity TEXT
            )
        ''')
        await conn.commit()

        print("Querying CVEs...")
        logging.info("Querying CVEs...")
        results = await query_cves(cve_numbers, api_key, conn)
        await retry_failed_cves(api_key, conn)  # Retry failed CVEs
    finally:
        await conn.close()
    return results

# Main function to run the script
def main():
    parser = argparse.ArgumentParser(description="CVE Query Script")
    parser.add_argument('--api_key', type=str, help='NVD API key for querying CVEs')
    parser.add_argument('--cve_file', type=str, help='Path to the CVE input file')
    args = parser.parse_args()

    #api_key = "put_your_API_key_here" uncomment and comment out the line below
    api_key = args.api_key if args.api_key else input("Enter your NVD API key: ")
    cve_file = args.cve_file if args.cve_file else input("Enter the path to the CVE input file: ")

    try:
        print("Starting CVE query process...")
        logging.info("Starting CVE query process...")
        results = asyncio.run(main_async(api_key, cve_file))

        # Save results to Excel
        if results:
            save_to_excel(results)
        else:
            print("No valid CVE data found.")
            logging.info("No valid CVE data found.")
    except Exception as e:
        print(f"An error occurred: {e}")
        logging.error(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
