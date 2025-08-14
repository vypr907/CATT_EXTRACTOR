"""
Nessus Cat II Compliance Extractor

This script extracts Category II (Cat II) failed compliance findings from Tenable Nessus scans.
It supports processing multiple scans from different environments (OP - Operational, IT - Test),
each with its own Nessus server configuration, exporting to separate Excel workbooks per environment.
The code follows DRY principles with reusable functions for authentication, export, parsing, etc.

Run the script with a command-line argument for the environment:
python catt_extract_nessus.py OP  or IT

Configurations are loaded from .env with suffixes (_OP, _IT).
Scan IDs are defined in the script but can be moved to .env if needed.

Dependencies:
- python-dotenv (for loading .env)
- pandas (for DataFrame and Excel handling)
- xlsxwriter (Excel engine)
- Built-in: urllib.request, json, time, xml.etree.ElementTree, ssl, os, argparse
"""

from dotenv import load_dotenv
import os
import urllib.request
import json
import time
import pandas as pd
import xml.etree.ElementTree as ET
from io import StringIO
import ssl # For SSL bypass

# Disable SSL verification (not recommended for production)
# Note: This is insecure and should only be used in trusted environments.
context = ssl.create_default_context();
context.check_hostname = False;
context.verify_mode = ssl.CERT_NONE

# XML namespace for compliance tags
NS = {'cm': 'http://www.nessus.org/cm'}


def authenticate(url: str, username: str, password: str) -> str:
    """
    Authenticate to a Nessus server and return the session token.

    Args:
        url (str): Nessus server URL.
        username (str): Username for authentication.
        password (str): Password for authentication.

    Returns:
        str: Session token.

    Raises:
        ValueError: If authentication fails or credentials are missing.
    """
    if not all([url, username, password]):
        raise ValueError("Missing required configuration: url, username, password")

    login_data = json.dumps({'username': username, 'password': password}).encode('utf-8')
    req = urllib.request.Request(f'{url}/session', data=login_data,
                                 headers={'Content-Type': 'application/json'}, method='POST')
    try:
        with urllib.request.urlopen(req, context=CONTEXT) as response:
            token = json.loads(response.read().decode('utf-8'))['token']
            return token
    except Exception as e:
        raise ValueError(f"Authentication failed: {e}")


def request_export(url: str, scan_id: int, token: str) -> int:
    """
    Request export of a scan in .nessus (XML) format.

    Args:
        url (str): Nessus server URL.
        scan_id (int): The ID of the scan to export.
        token (str): Session token.

    Returns:
        int: File ID of the export.

    Raises:
        RuntimeError: If export request fails.
    """
    export_data = json.dumps({'format': 'nessus'}).encode('utf-8')  # Add 'history_id' if needed
    req = urllib.request.Request(f'{url}/scans/{scan_id}/export', data=export_data,
                                 headers={'X-Cookie': f'token={token}', 'Content-Type': 'application/json'},
                                 method='POST')
    try:
        with urllib.request.urlopen(req, context=CONTEXT) as response:
            export_response = json.loads(response.read().decode('utf-8'))
            return export_response['file']
    except Exception as e:
        raise RuntimeError(f"Export request failed for scan {scan_id}: {e}")


def wait_for_export_ready(url: str, scan_id: int, file_id: int, token: str) -> None:
    """
    Poll until the export is ready.

    Args:
        url (str): Nessus server URL.
        scan_id (int): Scan ID.
        file_id (int): Export file ID.
        token (str): Session token.

    Raises:
        TimeoutError: If export takes too long.
    """
    start_time = time.time()
    while True:
        req = urllib.request.Request(f'{url}/scans/{scan_id}/export/{file_id}/status',
                                     headers={'X-Cookie': f'token={token}'})
        with urllib.request.urlopen(req, context=CONTEXT) as response:
            status = json.loads(response.read().decode('utf-8'))['status']
        if status == 'ready':
            return
        if time.time() - start_time > 300:  # 5-minute timeout
            raise TimeoutError(f"Export timed out for scan {scan_id}, file {file_id}")
        time.sleep(5)

# Step 4: Download the .nessus file
req = urllib.request.Request(f'{NESSUS_OP_URL}/scans/{SCAN_ID}/export/{file_id}/download', headers={'X-Cookie': f'token={token}'})
with urllib.request.urlopen(req, context=context) as response:
    nessus_content = response.read().decode('utf-8')

# Step 5: Parse the .nessus XML content
root = ET.fromstring(nessus_content)
ns = {'cm': 'http://www.nessus.org/cm'}

# List to hold extracted data
data = []

for report_host in root.findall('.//ReportHost'):
    host_name = report_host.get('name')  #IP or hostname
    for report_item in report_host.findall('ReportItem'):
        result_elem = report_item.find('cm:compliance-result', ns)
        if result_elem is not None and result_elem.text == 'FAILED':
            reference_elem = report_item.find('cm:compliance-reference', ns)
            if reference_elem is not None and reference_elem.text and ('CAT: II' in reference_elem.text or 'CAT|II' in reference_elem.text):
                # Extract relevant fields (customize as needed)
                full_check_name = report_item.find('cm:compliance-check-name', ns).text if report_item.find('cm:compliance-check-name', ns) is not None else ''

                # Split the check name into STIG ID and Description
                if ' - ' in full_check_name:
                    stig_id, description = full_check_name.split(' - ', 1)
                else:
                    stig_id = full_check_name
                    description = ''

                actual_value = report_item.find('cm:compliance-actual-value', ns).text if report_item.find('cm:compliance-actual-value', ns) is not None else ''
                policy_value = report_item.find('cm:compliance-policy-value', ns).text if report_item.find('cm:compliance-policy-value', ns) is not None else ''
                audit_file = report_item.find('cm:compliance-audit-file', ns).text if report_item.find('cm:compliance-audit-file', ns) is not None else ''
                see_also = report_item.find('cm:compliance-see-also', ns).text if report_item.find('cm:compliance-see-also', ns) is not None else ''
                solution = report_item.find('cm:compliance-solution', ns).text if report_item.find('cm:compliance-solution', ns) is not None else ''
                info = report_item.find('cm:compliance-info', ns).text if report_item.find('cm:compliance-info', ns) is not None else ''
                
                data.append({
                    'Host': host_name,
                    'Plugin ID': report_item.get('pluginID'),
                    'STIG ID': stig_id.strip(),
                    'Description': description.strip(),
                    'Full Check Name': full_check_name,
                    'Result': 'FAILED',
                    'Reference': reference_elem.text,
                    'Actual Value': actual_value,
                    'Policy Value': policy_value,
                    'Audit File': audit_file,
                    'See Also': see_also,
                    'Solution': solution,
                    'Info': info,
                    # Add more fields like description = report_item.find('description').text if needed
                })

# Step 6: Convert to DataFram and export to Excel
if data:
    df = pd.DataFrame(data)
    df.to_excel('nessus_cat_ii_findings.xlsx', index=False)
    print('Cat II findings exported to nessus_cat_ii_findings.xlsx')
else:
    print('No Cat II findings found.')