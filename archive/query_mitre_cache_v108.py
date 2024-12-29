"""
Version: 1.0.8
Description: Python script to query CVEs from the NVD API with local SQLite caching,
error handling for rate limiting, and Excel output generation. Handles both cache-first
queries and API queries with rate limiting. Now includes proper thread handling, improved
date parsing, and timestamped log files in the 'logs/' directory.
"""

import pandas as pd
import aiosqlite
import asyncio
import aiohttp
from datetime import datetime
import logging
import os

# Set up logging
log_dir = "logs"
if not os.path.exists(log_dir):
    os.makedirs(log_dir)
log_filename = f"{log_dir}/cve_query_{datetime.now().strftime('%m%d%Y_%H%M')}.log"
logging.basicConfig(filename=log_filename, level=logging.INFO, format="%(asctime)s - %(message)s")

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
async def query_cache(conn, cve_number):
    async with conn.execute("SELECT * FROM cve_data WHERE cve_id = ?", (cve_number,)) as cursor:
        row = await cursor.fetchone()
        if row:
            logging.info(f"Using cached data for {cve_number}")
            return {
                "CVE Number": row[0],
                "CVE Name": row[1],
                "Date Published": row[2],
                "Age (Days)": row[3],
                "CVSS 3.1 Score": row[4]
            }
    return None

# Function to insert CVE data into the cache
async def insert_into_cache(conn, cve_data):
    await conn.execute("""
        INSERT OR REPLACE INTO cve_data (cve_id, description, published_date, cve_age, severity)
        VALUES (?, ?, ?, ?, ?)
    """, (cve_data['CVE Number'], cve_data['CVE Name'], cve_data['Date Published'], cve_data['Age (Days)'], cve_data['CVSS 3.1 Score']))
    await conn.commit()

# Async function to search for a CVE using the NVD API
async def search_cve(session, cve_number, api_key):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_number}"
    headers = {"apiKey": api_key}
    
    timeout = aiohttp.ClientTimeout(total=10)
    try:
        async with session.get(url, headers=headers, timeout=timeout) as response:
            if response.status == 404:
                logging.info(f"Failed to fetch data for {cve_number}. HTTP Status: 404")
                return None
            elif response.status == 403:
                print(f"Rate limit reached for {cve_number}. HTTP Status: 403")
                logging.error(f"Rate limit reached for {cve_number}. HTTP Status: 403")
                return None
            elif response.status != 200:
                logging.info(f"Failed to fetch data for {cve_number}. HTTP Status: {response.status}")
                return None

            data = await response.json()
            results = data.get("vulnerabilities", [])
            if not results:
                logging.info(f"No vulnerabilities found for {cve_number}")
                return None

            cve_data_raw = results[0]["cve"]
            cve_id = cve_data_raw["id"]
            description = cve_data_raw["descriptions"][0]["value"] if "descriptions" in cve_data_raw else "N/A"
            published_date = cve_data_raw.get("published", "N/A")
            cve_age = (datetime.now() - parse_published_date(published_date)).days if published_date != "N/A" else "N/A"
            severity = cve_data_raw.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore", "N/A")

            cve_data = {
                "CVE Number": cve_id,
                "CVE Name": description,
                "Date Published": published_date,
                "Age (Days)": cve_age,
                "CVSS 3.1 Score": severity
            }

            logging.info(f"Fetched data from NVD for {cve_number}")
            return cve_data
    except Exception as e:
        logging.error(f"An error occurred while fetching CVE-{cve_number}: {str(e)}")
        return None

# Function to save data to Excel
def save_to_excel(data):
    timestamp = datetime.now().strftime("%m%d%Y_%H%M")
    filename = f"cve_data_{timestamp}.xlsx"
    
    df = pd.DataFrame(data)
    df.to_excel(filename, index=False)
    logging.info(f"Data successfully saved to {filename}")

# Main async function to handle querying both cache and NVD, with rate limiting
async def query_cves(cve_numbers, api_key, conn):
    all_cve_data = []
    async with aiohttp.ClientSession() as session:
        for index, cve_number in enumerate(cve_numbers, start=1):
            logging.info(f"Checking cache for {cve_number}")
            cached_data = await query_cache(conn, cve_number)
            if cached_data:
                all_cve_data.append(cached_data)
                continue
            
            # If not cached, query NVD
            logging.info(f"Querying NVD for {cve_number} ({index} out of {len(cve_numbers)})")
            cve_data = await search_cve(session, cve_number, api_key)
            if cve_data:
                all_cve_data.append(cve_data)
                await insert_into_cache(conn, cve_data)

            # Throttle requests by waiting between them (rate limit checking)
            if index % 22 == 0 and index > 0:
                logging.info("Sleeping for 15 seconds to avoid rate limiting...")
                await asyncio.sleep(15)

    return all_cve_data

# Function to read CVE numbers from a text file
def read_cve_file(file_path):
    with open(file_path, "r") as file:
        lines = file.readlines()
        return [line.strip() for line in lines[1:]]  # Skip the header

# Main async function
async def main_async(api_key, cve_file):
    cve_numbers = read_cve_file(cve_file)
    conn = await aiosqlite.connect("cve_cache.db")
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

    results = await query_cves(cve_numbers, api_key, conn)
    await conn.close()
    return results

# Main function to run the script
def main():
    api_key = "8da76f9f-b219-4b4a-80eb-0f22f07836a6"  # Replace with actual API key
    cve_file = input("Enter the path to the CVE file (one CVE per line): ")

    try:
        results = asyncio.run(main_async(api_key, cve_file))
        if results:
            save_to_excel(results)
        else:
            print("No valid CVE data found.")
            logging.info("No valid CVE data found.")
    except Exception as e:
        logging.error(f"An error occurred: {str(e)}")

if __name__ == "__main__":
    main()