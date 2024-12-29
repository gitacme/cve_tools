import pandas as pd
import aiosqlite
import asyncio
import aiohttp
import time
from datetime import datetime
import logging

# Set up logging for 403 errors
logging.basicConfig(filename="cve_query_errors.log", level=logging.ERROR,
                    format="%(asctime)s - %(message)s")

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

# Exponential backoff for handling rate limit issues
async def exponential_backoff(attempt):
    wait_time = 2 ** attempt
    print(f"Sleeping for {wait_time} seconds to avoid rate limiting...")
    await asyncio.sleep(wait_time)

# Async function to query the NVD API
async def query_nvd(cve_number, api_key, session, conn, total_cves, index):
    # Print progress
    print(f"Querying NVD for {index} out of {total_cves}: {cve_number}")

    # Check if CVE is in the cache
    cached_cve = await is_cve_in_cache(conn, cve_number)
    if cached_cve:
        print(f"Using cached data for {cve_number}")
        return {
            "CVE Number": cached_cve[0],
            "CVE Name": cached_cve[1],
            "Date Published": cached_cve[2],
            "Age (Days)": cached_cve[3],
            "CVSS 3.1 Score": cached_cve[4]
        }

    # API URL
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_number}"

    # Pass the API key in the header
    headers = {
        'apiKey': api_key
    }

    attempt = 0
    max_attempts = 5
    timeout = aiohttp.ClientTimeout(total=10)  # 10-second timeout

    while attempt < max_attempts:
        async with session.get(url, headers=headers, timeout=timeout) as response:
            if response.status == 403:
                print(f"Failed to fetch data for {cve_number}. HTTP Status: 403 (Rate limited)")
                logging.error(f"CVE: {cve_number} - Rate limited with 403")
                await exponential_backoff(attempt)
                attempt += 1
                continue  # Retry after sleep
            elif response.status != 200:
                print(f"Failed to fetch data for {cve_number}. HTTP Status: {response.status}")
                return None

            try:
                data = await response.json()
            except aiohttp.ContentTypeError:
                print(f"Failed to parse JSON for {cve_number}")
                return None

            # Extract necessary data
            results = data.get('vulnerabilities', [])
            if not results:
                print(f"No vulnerabilities found for {cve_number}")
                return None

            cve_data_raw = results[0]['cve']
            cve_id = cve_data_raw['id']
            description = cve_data_raw['descriptions'][0]['value'] if 'descriptions' in cve_data_raw else 'N/A'
            published_date = cve_data_raw['published'] if 'published' in cve_data_raw else 'N/A'
            cve_age = (datetime.now() - datetime.strptime(published_date, "%Y-%m-%dT%H:%M:%S.%fZ")).days if published_date != 'N/A' else 'N/A'
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

    print(f"Max retry attempts reached for {cve_number}")
    logging.error(f"CVE: {cve_number} - Max retry attempts reached")
    return None

# Function to save data to Excel
def save_to_excel(data):
    # Get the current date and time
    timestamp = datetime.now().strftime("%m%d%Y_%H%M")
    filename = f"cve_data_{timestamp}.xlsx"

    # Save the data to Excel using pandas
    df = pd.DataFrame(data)
    df.to_excel(filename, index=False)
    print(f"Data successfully saved to {filename}")

# Function to read CVE numbers from a text file and skip the header
def read_cve_file(file_path):
    with open(file_path, 'r') as file:
        lines = file.readlines()
        return [line.strip() for line in lines[1:]]  # Skip the first line (header)

# Main async function for querying CVEs and saving results
async def main_async(api_key, cve_file):
    cve_numbers = read_cve_file(cve_file)
    conn = await init_db()
    async with aiohttp.ClientSession() as session:
        total_cves = len(cve_numbers)
        tasks = []
        for index, cve_number in enumerate(cve_numbers, start=1):
            task = asyncio.ensure_future(query_nvd(cve_number, api_key, session, conn, total_cves, index))
            tasks.append(task)
            # Sleep only for API queries, not cached results
            if not await is_cve_in_cache(conn, cve_number):
                await asyncio.sleep(1)  # Sleep for 1 second between requests

        results = await asyncio.gather(*tasks, return_exceptions=True)
        return results

# Main function
def main():
    api_key = '8da76f9f-b219-4b4a-80eb-0f22f07836a6'  # Replace with your actual API key
    cve_file = input("Enter the path to the CVE file (one CVE per line): ")

    try:
        results = asyncio.run(main_async(api_key, cve_file))

        # Process the results and save to Excel
        filtered_results = [result for result in results if isinstance(result, dict)]
        if filtered_results:
            save_to_excel(filtered_results)
        else:
            print("No valid CVE data found.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
