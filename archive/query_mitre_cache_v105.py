import asyncio
import aiohttp
import aiosqlite
import pandas as pd
from datetime import datetime
import logging
import threading

# Version: 1.0.5

# Set up logging
logging.basicConfig(filename='query_mitre_log.txt', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Async function to initialize SQLite database
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

# Async function to insert CVE data into the cache
async def insert_cve_into_cache(conn, cve_data):
    await conn.execute('''
        INSERT OR REPLACE INTO cve_data (cve_id, description, published_date, cve_age, severity)
        VALUES (?, ?, ?, ?, ?)
    ''', (cve_data['CVE Number'], cve_data['CVE Name'], cve_data['Date Published'], 
          cve_data['Age (Days)'], cve_data['CVSS 3.1 Score']))
    await conn.commit()

# Async function to handle fetching a CVE from NVD and caching the result
async def fetch_and_cache_cve(cve_number, api_key, session, conn):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_number}"
    headers = {'apiKey': api_key}
    timeout = aiohttp.ClientTimeout(total=10)
    
    try:
        async with session.get(url, headers=headers, timeout=timeout) as response:
            if response.status == 404:
                logging.warning(f"Failed to fetch data for {cve_number}. HTTP Status: 404")
                print(f"Failed to fetch data for {cve_number}. HTTP Status: 404")
                return None
            elif response.status == 403:
                logging.warning(f"Failed to fetch data for {cve_number}. HTTP Status: 403 (Rate limited)")
                print(f"Failed to fetch data for {cve_number}. HTTP Status: 403")
                return None
            elif response.status != 200:
                logging.error(f"Failed to fetch data for {cve_number}. HTTP Status: {response.status}")
                return None
            
            data = await response.json()
            results = data.get('vulnerabilities', [])
            if not results:
                logging.info(f"No vulnerabilities found for {cve_number}")
                return None

            # Process the CVE data
            cve_data_raw = results[0]['cve']
            cve_id = cve_data_raw['id']
            description = cve_data_raw['descriptions'][0]['value'] if 'descriptions' in cve_data_raw else 'N/A'
            published_date = cve_data_raw['published'] if 'published' in cve_data_raw else 'N/A'
            try:
                published_date_parsed = datetime.strptime(published_date, "%Y-%m-%dT%H:%M:%S.%fZ")
            except ValueError:
                published_date_parsed = datetime.strptime(published_date, "%Y-%m-%dT%H:%M:%S")
            cve_age = (datetime.now() - published_date_parsed).days if published_date != 'N/A' else 'N/A'
            severity = cve_data_raw['metrics']['cvssMetricV31'][0]['cvssData']['baseScore'] if 'cvssMetricV31' in cve_data_raw['metrics'] else 'N/A'

            # Prepare the CVE data for cache
            cve_data = {
                "CVE Number": cve_id,
                "CVE Name": description,
                "Date Published": published_date,
                "Age (Days)": cve_age,
                "CVSS 3.1 Score": severity
            }

            await insert_cve_into_cache(conn, cve_data)
            return cve_data
    except Exception as e:
        logging.error(f"An error occurred while fetching {cve_number}: {e}")
        return None

# Async function to query CVEs with caching logic
async def query_cves(cve_numbers, api_key, conn):
    async with aiohttp.ClientSession() as session:
        tasks = []
        for index, cve_number in enumerate(cve_numbers, start=1):
            print(f"Querying NVD for {index} out of {len(cve_numbers)}: {cve_number}")
            # Check cache first
            cached_cve = await is_cve_in_cache(conn, cve_number)
            if cached_cve:
                print(f"Using cached data for {cve_number}")
                logging.info(f"Using cached data for {cve_number}")
                continue
            tasks.append(fetch_and_cache_cve(cve_number, api_key, session, conn))
        return await asyncio.gather(*tasks)

# Function to read CVE numbers from a text file and skip the header
def read_cve_file(file_path):
    with open(file_path, 'r') as file:
        lines = file.readlines()
        return [line.strip() for line in lines[1:]]  # Skip the first line (header)

# Function to save data to Excel
def save_to_excel(data):
    timestamp = datetime.now().strftime("%m%d%Y_%H%M")
    filename = f"cve_data_{timestamp}.xlsx"
    df = pd.DataFrame(data)
    df.to_excel(filename, index=False)
    print(f"Data successfully saved to {filename}")

# Function to run everything asynchronously
async def main_async(api_key, cve_file):
    cve_numbers = read_cve_file(cve_file)
    conn = await init_db()
    results = await query_cves(cve_numbers, api_key, conn)
    return results

# Main function
def main():
    api_key = 'a8da76f9f-b219-4b4a-80eb-0f22f07836a6'  # Replace with your actual API key
    cve_file = input("Enter the path to the CVE file (one CVE per line): ")
    try:
        results = asyncio.run(main_async(api_key, cve_file))
        filtered_results = [result for result in results if result]
        if filtered_results:
            save_to_excel(filtered_results)
        else:
            print("No valid CVE data found.")
    except Exception as e:
        logging.error(f"An error occurred: {e}")
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
