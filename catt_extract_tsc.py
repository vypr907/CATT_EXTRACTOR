import urllib.request
import json
import pandas as pd

# Configuration - Replace with your details
SC_URL = 'https://your-security-center-server'  # e.g., https://192.168.1.200
USERNAME = 'your_username'
PASSWORD = 'your_password'
# Optional: Add more filters, e.g., for a specific scan or repository

# Step 1: Authenticate and get token
login_data = json.dumps({'username': USERNAME, 'password': PASSWORD}).encode('utf-8')
req = urllib.request.Request(f'{SC_URL}/token', data=login_data, headers={'Content-Type': 'application/json'}, method='POST')
with urllib.request.urlopen(req) as response:
    token = json.loads(response.read().decode('utf-8'))['response']['token']

# Step 2: Query for vulnerabilities (filter by severity = 2 for Medium/Cat II)
query_data = json.dumps({
    'type': 'vuln',
    'query': {
        'type': 'vuln',
        'tool': 'listvuln',  # Use 'listvuln' for detailed vulnerability list
        'sourceType': 'cumulative',  # Or 'patched'/'individual' as needed
        'filters': [
            {'id': 'severity', 'filterName': 'severity', 'operator': '=', 'value': '2'}  # 2 = Medium
        ]
    },
    'sourceType': 'cumulative',
    'startOffset': 0,
    'endOffset': 10000  # Adjust for pagination if more results
}).encode('utf-8')

req = urllib.request.Request(f'{SC_URL}/analysis', data=query_data, headers={'X-SecurityCenter': token, 'Content-Type': 'application/json'}, method='POST')
with urllib.request.urlopen(req) as response:
    vulns_response = json.loads(response.read().decode('utf-8'))['response']['results']

# Step 3: Convert results to DataFrame (flatten if needed)
# Assuming 'results' is a list of dicts with vuln details
df = pd.DataFrame(vulns_response)

# Step 4: Export to Excel
df.to_excel('sc_cat_ii_findings.xlsx', index=False)

print('Cat II findings exported to sc_cat_ii_findings.xlsx')