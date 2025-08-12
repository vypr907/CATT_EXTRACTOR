import urllib.request
import json
import time
import pandas as pd
from io import StringIO
import ssl

# Disable SSL verification (not recommended for production)
# Note: This is insecure and should only be used in trusted environments.
context = ssl.create_default_context();
context.check_hostname = False;
context.verify_mode = ssl.CERT_NONE

# Configuration - #Operational Suite
NESSUS_OP_URL = "https://172.21.110.29:1241"
USERNAME = "nessus"
PASSWORD_OP = "PaaNT3chRefre$h" 
# - #Test Suite
NESSUS_IT_URL = "https://172.22.110:1241"
PASSWORD_IT = "PaaNT3st$uiTe"

# Scan IDs
SCAN_ID = 596  # PAAN RHEL 8 FTPS DISA STIG Scan

# Step 1: Authenticate and get token
login_data = json.dumps({'username': USERNAME, 'password': PASSWORD_OP}).encode('utf-8')
req = urllib.request.Request(f'{NESSUS_OP_URL}/session', data=login_data, headers={'Content-Type': 'application/json'}, method='POST')
with urllib.request.urlopen(req, context=context) as response:
    token = json.loads(response.read().decode('utf-8'))['token']

# Step 2: Request export of the scan in CSV format (latest history by default)
export_data = json.dumps({'format': 'csv'}).encode('utf-8')
req = urllib.request.Request(f'{NESSUS_URL}/scans/{SCAN_ID}/export', data=export_data, headers={'X-Cookie': f'token={token}', 'Content-Type': 'application/json'}, method='POST')
with urllib.request.urlopen(req, context=context) as response:
    export_response = json.loads(response.read().decode('utf-8'))
    file_id = export_response['file']

# Step 3: Check export status until ready
while True:
    req = urllib.request.Request(f'{NESSUS_URL}/scans/{SCAN_ID}/export/{file_id}/status', headers={'X-Cookie': f'token={token}'})
    with urllib.request.urlopen(req, context=context) as response:
        status = json.loads(response.read().decode('utf-8'))['status']
    if status == 'ready':
        break
    time.sleep(5)

# Step 4: Download the CSV file
req = urllib.request.Request(f'{NESSUS_URL}/scans/{SCAN_ID}/export/{file_id}/download', headers={'X-Cookie': f'token={token}'})
with urllib.request.urlopen(req, context=context) as response:
    csv_content = response.read().decode('utf-8')

# Step 5: Load CSV into pandas DataFrame
df = pd.read_csv(StringIO(csv_content))

# Step 6: Filter for Cat II findings (assuming 'Severity' column with value 'Medium')
# Note: In Tenable, Cat II typically maps to Medium severity vulnerabilities.
cat_ii_df = df[df['Severity'].str.strip().str.lower() == 'medium']

# Step 7: Export to Excel
cat_ii_df.to_excel('nessus_cat_ii_findings.xlsx', index=False)

print('Cat II findings exported to nessus_cat_ii_findings.xlsx')