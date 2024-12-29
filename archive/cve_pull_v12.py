# CVE Query Script - Last 90 Days CVE Pull - Version 1.0.0
# Copyright 2024 Steve Fink
# This script pulls the last 90 days of CVE data from the NVD API,
# adds it to the local caching database, and outputs results to Excel.

import pandas as pd
import aiosqlite
import asyncio
import aiohttp
from datetime import datetime, timedelta
import logging
import os
import argparse
from openpyxl import load_workbook
from openpyxl.styles import Font

# Ensure directory structure exists
os.makedirs('database', exist_ok=True)
os.makedirs('output', exist_ok=True)
os.makedirs('logs', exist_ok=True)

# Set up logging
log_dir = "logs"
timestamp = datetime.now().strftime("%m%d%Y_%H%M")
log_filename = f"{log_dir}/cve_pull_{timestamp}.log"
logging.basicConfig(
    filename=log_filename,
    level=logging.DEBUG,  # Set to DEBUG for detailed logging
    format="%(asctime)s - %(levelname)s - %(message)s"
)

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)  # Log INFO and above to console
console_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
logging.getLogger().addHandler(console_handler)

# API Endpoint for querying CVEs by date range
BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

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

# Function to query NVD API by date range
async def query_nvd_api_by_date_range(session, start_date, end_date, api_key):
    url = f"{BASE_URL}?pubStartDate={start_date}T00:00:00.000Z&pubEndDate={end_date}T23:59:59.999Z"
    headers = {"apiKey": api_key}
    timeout = aiohttp.ClientTimeout(total=30)
    try:
        async with session.get(url, headers=headers, timeout=timeout) as response:
            if response.status != 200:
                logging.warning(f"Failed to fetch data. HTTP Status: {response.status}")
                return None
            data = await response.json()
            return data.get("vulnerabilities", [])
    except aiohttp.ClientError as e:
        logging.error(f"Network error occurred while fetching CVEs: {str(e)}")
    return []

# Function to insert CVE data into the cache
async def insert_into_cache(conn, cve_data):
    try:
        await conn.execute("""
            INSERT OR REPLACE INTO cve_data (cve_id, description, published_date, cve_age, severity)
            VALUES (?, ?, ?, ?, ?)
        """, (cve_data['CVE Number'], cve_data['CVE Name'], cve_data['Date Published'], cve_data['Age (Days)'], cve_data['CVSS 3.1 Score']))
        await conn.commit()
    except Exception as e:
        logging.error(f"An error occurred while inserting into cache: {e}")

# Function to save data to Excel
def save_to_excel(data):
    filename = f"output/cve_data_90_days_{timestamp}.xlsx"  # Ensure synchronized timestamp for Excel
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

# Main async function to query CVEs from the last 90 days and add to cache
async def main_async(api_key, start_date=None, end_date=None):
    # Determine date range
    if not start_date or not end_date:
        end_date = datetime.now()
        start_date = end_date - timedelta(days=90)
    else:
        start_date = datetime.strptime(start_date, "%Y-%m-%d")
        end_date = datetime.strptime(end_date, "%Y-%m-%d")

    start_date_str = start_date.strftime("%Y-%m-%d")
    end_date_str = end_date.strftime("%Y-%m-%d")

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

        async with aiohttp.ClientSession() as session:
            print(f"Querying CVEs from {start_date_str} to {end_date_str}...")
            logging.info(f"Querying CVEs from {start_date_str} to {end_date_str}...")
            vulnerabilities = await query_nvd_api_by_date_range(session, start_date_str, end_date_str, api_key)

            all_cve_data = []
            for item in vulnerabilities:
                cve_data_raw = item.get("cve", {})
                cve_id = cve_data_raw.get("id", "N/A")
                description = cve_data_raw.get("descriptions", [{}])[0].get("value", "N/A")
                published_date = cve_data_raw.get("published", "N/A")
                cve_age = (datetime.now() - parse_published_date(published_date)).days if published_date != "N/A" else "N/A"

                # Handling multiple CVSS versions
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
                    "CVE Name": description,
                    "Date Published": published_date,
                    "Age (Days)": cve_age,
                    "CVSS 3.1 Score": severity
                }
                all_cve_data.append(cve_data)

                # Insert into cache
                await insert_into_cache(conn, cve_data)

            # Save results to Excel
            if all_cve_data:
                save_to_excel(all_cve_data)
            else:
                print("No CVE data found for the specified date range.")
                logging.info("No CVE data found for the specified date range.")
    finally:
        await conn.close()

# Main function to run the script
def main():
    parser = argparse.ArgumentParser(description="CVE Pull Script for Last 90 Days")
    parser.add_argument('--api_key', type=str, help='NVD API key for querying CVEs')
    parser.add_argument('--start_date', type=str, help='Start date for CVE data pull (format: YYYY-MM-DD)')
    parser.add_argument('--end_date', type=str, help='End date for CVE data pull (format: YYYY-MM-DD)')
    args = parser.parse_args()

    api_key = args.api_key if args.api_key else input("Enter your NVD API key: ")
    start_date = args.start_date
    end_date = args.end_date

    try:
        print("Starting CVE pull process...")
        logging.info("Starting CVE pull process...")
        asyncio.run(main_async(api_key, start_date, end_date))
    except Exception as e:
        print(f"An error occurred: {e}")
        logging.error(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
