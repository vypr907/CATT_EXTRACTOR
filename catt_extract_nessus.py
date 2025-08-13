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
import ssl
import argparse

# Load environment variables from .env
load_dotenv()

# Optional: SSL bypass context (use only if cert not trusted; less secure)
CONTEXT = ssl.create_default_context()
CONTEXT.check_hostname = False
CONTEXT.verify_mode = ssl.CERT_NONE

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


def download_nessus(url: str, scan_id: int, file_id: int, token: str) -> bytes:
    """
    Download the .nessus XML file.

    Args:
        url (str): Nessus server URL.
        scan_id (int): Scan ID.
        file_id (int): Export file ID.
        token (str): Session token.

    Returns:
        bytes: Raw XML content.

    Raises:
        RuntimeError: If download fails.
    """
    req = urllib.request.Request(f'{url}/scans/{scan_id}/export/{file_id}/download',
                                 headers={'X-Cookie': f'token={token}'})
    try:
        with urllib.request.urlopen(req, context=CONTEXT) as response:
            return response.read()
    except Exception as e:
        raise RuntimeError(f"Download failed for scan {scan_id}, file {file_id}: {e}")


def parse_nessus_content(nessus_content: bytes) -> ET.Element:
    """
    Parse the .nessus XML content into an ElementTree root.

    Args:
        nessus_content (bytes): Raw XML bytes.

    Returns:
        ET.Element: Root of the XML tree.

    Raises:
        ValueError: If parsing fails.
    """
    try:
        return ET.fromstring(nessus_content)
    except ET.ParseError as e:
        raise ValueError(f"XML parsing failed: {e}")


def extract_cat_ii_data(root: ET.Element) -> list[dict]:
    """
    Extract Cat II failed compliance data from the XML root.

    Args:
        root (ET.Element): XML root element.

    Returns:
        list[dict]: List of dictionaries with extracted data.
    """
    data = []
    for report_host in root.findall('.//ReportHost'):
        host_name = report_host.get('name', 'Unknown')
        for report_item in report_host.findall('ReportItem'):
            result_elem = report_item.find('cm:compliance-result', NS)
            if result_elem is not None and result_elem.text == 'FAILED':
                reference_elem = report_item.find('cm:compliance-reference', NS)
                if reference_elem is not None and reference_elem.text and \
                   ('CAT: II' in reference_elem.text or 'CAT|II' in reference_elem.text):
                    full_check_name = report_item.find('cm:compliance-check-name', NS).text or ''
                    # Split check name
                    if ' - ' in full_check_name:
                        stig_id, description = full_check_name.split(' - ', 1)
                    else:
                        stig_id = full_check_name
                        description = ''
                    # Extract other fields
                    actual_value = report_item.find('cm:compliance-actual-value', NS).text or ''
                    policy_value = report_item.find('cm:compliance-policy-value', NS).text or ''
                    audit_file = report_item.find('cm:compliance-audit-file', NS).text or ''
                    see_also = report_item.find('cm:compliance-see-also', NS).text or ''
                    solution = report_item.find('cm:compliance-solution', NS).text or ''
                    info = report_item.find('cm:compliance-info', NS).text or ''
                    data.append({
                        'Host': host_name,
                        'Plugin ID': report_item.get('pluginID', ''),
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
                    })
    return data


def process_environment(env_config: dict) -> None:
    """
    Process scans for a given environment configuration.

    Args:
        env_config (dict): Dictionary with 'url', 'username', 'password', 'scan_ids', 'output_file'.
    """
    url = env_config['url']
    username = env_config['username']
    password = env_config['password']
    scan_ids = env_config['scan_ids']
    output_file = env_config['output_file']

    token = authenticate(url, username, password)
    with pd.ExcelWriter(output_file, engine='xlsxwriter') as writer:
        for scan_id in scan_ids:
            try:
                file_id = request_export(url, scan_id, token)
                wait_for_export_ready(url, scan_id, file_id, token)
                nessus_content = download_nessus(url, scan_id, file_id, token)
                root = parse_nessus_content(nessus_content)
                data = extract_cat_ii_data(root)
                # Get scan name from <Report> element
                report_elem = root.find('Report')
                if report_elem is not None:
                    scan_name = report_elem.get('name', f'Scan_{scan_id}')
                else:
                    # Fallback if <Report> is not found
                    scan_name = f'Scan_{scan_id}'
                # Ensure sheet name is within Excel limits
                invalid_chars = r'[\\/:*?"<>|]'
                sheet_name = ''.join(c for c in scan_name if c not in invalid_chars)[:31]
                # Create a new sheet for each scan
                if data:
                    df = pd.DataFrame(data)
                    df.to_excel(writer, sheet_name=sheet_name, index=False)
                    print(f'Added sheet for Scan "{scan_name}" in {output_file}')
                else:
                    print(f'No Cat II failed compliance findings for Scan "{scan_name}"; skipping sheet.')
            except Exception as e:
                print(f'Error processing Scan ID {scan_id}: {e}')
    print(f'Export complete for environment {env_config["env"]}: {output_file}')


def main() -> None:
    """
    Main function to parse arguments and process the selected environment.
    """
    parser = argparse.ArgumentParser(description='Extract Cat II findings from Nessus scans by environment.')
    parser.add_argument('environment', choices=['OP', 'IT'], help='Environment to process: OP (Operational) or IT (Test)')
    args = parser.parse_args()

    env = args.environment

    # Environment-specific configurations
    # Scan IDs are hardcoded here; move to .env if needed (e.g., as comma-separated string and split)
    configs = {
        'OP': {
            'env': 'OP',
            'url': os.getenv('NESSUS_OP_URL'),
            'username': os.getenv('NESSUS_USERNAME'),
            'password': os.getenv('NESSUS_OP_PASSWORD'),
            'scan_ids': [1182, 1048, 1054, 1059, 1067],  # Replace with OP-specific scan IDs
            'output_file': 'nessus_cat_ii_findings_OP.xlsx'
        },
        'IT': {
            'env': 'IT',
            'url': os.getenv('NESSUS_IT_URL'),
            'username': os.getenv('NESSUS_USERNAME'),
            'password': os.getenv('NESSUS_IT_PASSWORD'),
            'scan_ids': [101, 102, 103],  # Replace with IT-specific scan IDs
            'output_file': 'nessus_cat_ii_findings_IT.xlsx'
        }
    }

    if env not in configs:
        raise ValueError(f"Invalid environment: {env}")

    process_environment(configs[env])


if __name__ == '__main__':
    main()