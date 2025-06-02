import requests
import time
from dotenv import load_dotenv
import os

load_dotenv()
API_KEY = os.getenv('VT_API_KEY')
INPUT_FILE = 'hashes.txt'
OUTPUT_FILE = 'results.txt'
RATE_LIMIT = 4  # Free account limit: 4 requests/minute
SLEEP_TIME = 60  # Seconds to wait between batches

API_URL = 'https://www.virustotal.com/api/v3/files/{}'
HEADERS = {'x-apikey': API_KEY}

def read_hashes(file_path):
    with open(file_path, 'r') as f:
        return [line.strip() for line in f if line.strip()]

def check_hash(file_hash):
    url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
    headers = {
        'x-apikey': API_KEY
    }

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            results = data.get('data', {}).get('attributes', {}).get('last_analysis_results', {})

            # Try to find Palo Alto Networks or WildFire verdicts
            palo_verdict = None
            for vendor, verdict in results.items():
                vendor_lower = vendor.lower()
                if 'palo' in vendor_lower or 'wildfire' in vendor_lower:
                    palo_verdict = {
                        'vendor': vendor,
                        'category': verdict.get('category'),
                        'result': verdict.get('result')
                    }
                    break

            return {
                'hash': file_hash,
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'undetected': stats.get('undetected', 0),
                'harmless': stats.get('harmless', 0),
                'palo_alto_vendor': palo_verdict['vendor'] if palo_verdict else 'Not listed',
                'palo_alto_detected': palo_verdict['category'] if palo_verdict else 'N/A',
                'palo_alto_result': palo_verdict['result'] if palo_verdict else 'N/A'
            }

        elif response.status_code == 404:
            return {'hash': file_hash, 'error': 'Not found'}
        else:
            return {'hash': file_hash, 'error': f'Status {response.status_code}: {response.text}'}
    except Exception as e:
        return {'hash': file_hash, 'error': str(e)}

def main():
    hashes = read_hashes(INPUT_FILE)
    results = []

    for i in range(0, len(hashes), RATE_LIMIT):
        batch = hashes[i:i+RATE_LIMIT]

        for file_hash in batch:
            result = check_hash(file_hash)
            results.append(result)
            print(result)

        if i + RATE_LIMIT < len(hashes):
            print(f"Sleeping {SLEEP_TIME}s to respect rate limits...")
            time.sleep(SLEEP_TIME)

    with open(OUTPUT_FILE, 'w') as out_file:
        for res in results:
            out_file.write(str(res) + '\n')

    print(f"\nResults saved to {OUTPUT_FILE}")

if __name__ == '__main__':
    main()
