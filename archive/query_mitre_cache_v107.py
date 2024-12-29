"""
Version: 1.0.7
Description: Python script to query CVEs from the NVD API with local SQLite caching,
error handling for rate limiting, and Excel output generation. Handles both cache-first
queries and API queries with rate limiting. Now includes proper thread handling, improved
date parsing, and timestamped log files in the 'logs/' directory.
"""

import pandas as pd
import aiosqlite
import asyncio
import aiohttp
import logging
import os
from datetime import datetime
import time

# Create 'logs/' directory if not exists
if not os.path.exists("logs"):
    os.makedirs("logs")

# Set up logging with a timestamped filename
timestamp = datetime.now().strftime("%m%d%Y_%H%M")
log_filename = f"logs/cve_query_{timestamp}.log"
logging.basicConfig(filename=log_filename, level=logging.INFO, 
                    format="%(asctime)s - %(levelname)s - %(message)s")

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

# Async function to initialize the SQLite database
async def init_db():
    conn = await aiosqlite.connect('cve_cache.db')
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
    return conn

# Async function to check if CVE is in the cache
async def is_cve_in_cache(conn, cve_id):
    async with conn.execute("SELECT * FROM cve_data WHERE cve_id = ?", (cve_id,)) as cursor:
        return await cursor.fetchone()

# Async function to insert CVE data into cache
async def insert_cve_into_cache(conn, cve_data):
    await conn.execute('''
        INSERT OR REPLACE INTO cve_data (cve_id, description, published_date, cve_age, severity)
        VALUES (?, ?, ?, ?, ?)
    ''', (cve_data['CVE Number'], cve_data['CVE Name'], cve_data['Date Published'], cve_data['Age (Days)'], cve_data['CVSS 3.1 Score']))
    await conn.commit()

# Async function to search for a CVE using the correct NVD API URL
async def search_cve_async(cve_number, api_key, session, conn, total_cves, index):
    # Print progress
    print(f"Querying NVD for {index} out of {total_cves}: {cve_number}")
    logging.info(f"Querying NVD for {index} out of {total_cves}: {cve_number}")

    # Check if CVE is in the cache
    cached_cve = await is_cve_in_cache(conn, cve_number)
    if cached_cve:
        print(f"Using cached data for {cve_number}")
        logging.info(f"Using cached data for {cve_number}")
        return {
            "CVE Number": cached_cve[0],
            "CVE Name": cached_cve[1],
            "Date Published": cached_cve[2],
            "Age (Days)": cached_cve[3],
            "CVSS 3.1 Score": cached_cve[4]
        }

    # Correct API URL with 'cves' (plural)
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_number}"

    # Pass the API key in the header
    headers = {
        'apiKey': api_key
    }

    # Add timeout to ensure we don't wait indefinitely for a response
    timeout = aiohttp.ClientTimeout(total=15)  # 15-second timeout
    try:
        async with session.get(url, headers=headers, timeout=timeout) as response:
            if response.status == 404:
                print(f"Failed to fetch data for {cve_number}. HTTP Status: 404 (Not Found)")
                logging.error(f"Failed to fetch data for {cve_number}. HTTP Status: 404")
                return None
            elif response.status == 403:
                print(f"Rate limit reached for {cve_number}. HTTP Status: 403")
                logging.error(f"Rate limit reached for {cve_number}. HTTP Status: 403")
                return None
            elif response.status != 200:
                print(f"Failed to fetch data for {cve_number}. HTTP Status: {response.status}")
                logging.error(f"Failed to fetch data for {cve_number}. HTTP Status: {response.status}")
                return None

            try:
                data = await response.json()
            except aiohttp.ContentTypeError:
                print(f"Failed to parse JSON for {cve_number}")
                logging.error(f"Failed to parse JSON for {cve_number}")
                return None

            # Extract necessary data
            results = data.get('vulnerabilities', [])
            if not results:
                print(f"No vulnerabilities found for {cve_number}")
                logging.error(f"No vulnerabilities found for {cve_number}")
                return None

            cve_data_raw = results[0]['cve']
            cve_id = cve_data_raw['id']
            description = cve_data_raw['descriptions'][0]['value'] if 'descriptions' in cve_data_raw else 'N/A'
            published_date = cve_data_raw['published'] if 'published' in cve_data_raw else 'N/A'
            try:
                parsed_published_date = parse_published_date(published_date)
                cve_age = (datetime.now() - parsed_published_date).days if published_date != 'N/A' else 'N/A'
            except ValueError as e:
                print(f"Error parsing date for {cve_number}: {e}")
                logging.error(f"Error parsing date for {cve_number}: {e}")
                return None

            severity = cve_data_raw['metrics']['cvssMetricV31'][0]['cvssData']['baseScore'] if 'cvssMetricV31' in cve_data_raw['metrics'] else 'N/A'

            # Prepare CVE data
            cve_data = {
                "CVE Number": cve_id,
                "CVE Name": description,
                "Date Published": published_date,
                "Age (Days)": cve_age,
                "CVSS 3.1 Score": severity
            }

            # Insert into cache
            await insert_cve_into_cache(conn, cve_data)

            return cve_data
    except Exception as e:
        print(f"An error occurred while fetching CVE-{cve_number}: {e}")
        logging.error(f"An error occurred while fetching CVE-{cve_number}: {e}")
        return None

# Function to run queries asynchronously with rate limiting and caching
async def query_cves_in_parallel(cve_numbers, api_key, conn):
    total_cves = len(cve_numbers)
    async with aiohttp.ClientSession() as session:
        tasks = []
        for index, cve_number in enumerate(cve_numbers, start=1):
            # Throttle requests by waiting between them (rate limit checking)
            if index % 50 == 0 and index > 0:
                print("Sleeping for 15 seconds to avoid rate limiting...")
                logging.info("Sleeping for 15 seconds to avoid rate limiting...")
                await asyncio.sleep(15)

            task = asyncio.ensure_future(search_cve_async(cve_number, api_key, session, conn, total_cves, index))
            tasks.append(task)

        results = await asyncio.gather(*tasks, return_exceptions=True)  # Ensure all tasks are completed
        return results

# Function to read CVE numbers from a text file and skip the header
def read_cve_file(file_path):
    with open(file_path, 'r') as file:
        lines = file.readlines()
        return [line.strip() for line in lines[1:]]  # Skip the first line (header)

# Function to save data to Excel and apply Calibri font with bold headers
def save_to_excel(data):
    # Get the current date and time
    timestamp = datetime.now().strftime("%m%d%Y_%H%M")
    filename = f"cve_data_{timestamp}.xlsx"

    # Save the data to Excel using pandas
    df = pd.DataFrame(data)
    df.to_excel(filename, index=False)
    print(f"Data successfully saved to {filename}")
    logging.info(f"Data successfully saved to {filename}")

# Main async function for querying CVEs and saving results
async def main_async(api_key, cve_file):
    cve_numbers = read_cve_file(cve_file)
    conn = await init_db()
    results = await query_cves_in_parallel(cve_numbers, api_key, conn)
    return results

def main():
    api_key = '8da76f9f-b219-4b4a-80eb-0f22f07836a6'  # Replace with your actual API key
    cve_file = input("Enter the path to the CVE file (one CVE per line): ")

    try:
        results = asyncio.run(main_async(api_key, cve_file))

        # Process the results and save to Excel
        filtered_results = [result for result in results if isinstance(result, dict)]  # Filter out None and exceptions
        if filtered_results:
            save_to_excel(filtered_results)
        else:
            print("No valid CVE data found.")
            logging.info("No valid CVE data found.")
    except Exception as e:
        print(f"An error occurred: {e}")
        logging.error(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
