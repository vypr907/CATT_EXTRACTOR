import subprocess
import os
import json
import xml.etree.ElementTree as ET
from typing import Any, Dict, Optional

class TSCWindowsCAC:
    def __init__(self, base_url: str, ps_cert_picker: str, ca_bundle: Optional[str] = None):
        """
        Windows-native Tenable SC client using CAC cert.

        :param base_url: Base URL of Tenable SC
        :param ps_cert_picker: Path to your cert_picker.ps1 script
        :param ca_bundle: Optional path to a PEM bundle if custom roots are needed
        """
        self.base_url = base_url.rstrip("/")
        self.ps_cert_picker = ps_cert_picker
        self.ca_bundle = ca_bundle

        # Launch cert picker and read thumbprint
        self.thumbprint = self._pick_cert()
        print(f"[INFO] Using CAC cert thumbprint: {self.thumbprint}")

    def _pick_cert(self) -> str:
        """Run the PowerShell cert picker and read the exported XML thumbprint."""
        # Run picker
        subprocess.run([
            "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
            "-File", self.ps_cert_picker
        ], check=True)

        # Read exported XML (default temp path)
        xml_path = os.path.join(os.environ['TEMP'], 'cac_cert_info.xml')
        if not os.path.exists(xml_path):
            raise FileNotFoundError(f"Cert picker did not export XML to {xml_path}")

        # Parse thumbprint
        tree = ET.parse(xml_path)
        root = tree.getroot()
        ns = {'ps': 'http://schemas.microsoft.com/powershell/2004/04'}

        thumbprint = None
        for prop in root.findall('.//ps:Property', ns):
            if prop.get('Name') == 'Thumbprint':
                thumbprint = prop.find('ps:Value', ns).text
        if not thumbprint:
            raise ValueError("Thumbprint not found in exported XML")
        return thumbprint

    def _call(self, path: str, method: str = "GET",
              body: Optional[Dict[str, Any]] = None,
              query: Optional[Dict[str, Any]] = None,
              headers: Optional[Dict[str, str]] = None) -> Any:
        """Internal: call PowerShell helper (tsc_cac_native.ps1) with mTLS using selected cert."""
        # Assuming you already have tsc_cac_native.ps1 in same folder as picker
        ps_native = os.path.join(os.path.dirname(self.ps_cert_picker), "tsc_cac_native.ps1")
        args = [
            "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
            "-File", ps_native,
            "-BaseUrl", self.base_url,
            "-Path", path,
            "-Method", method,
            "-Thumbprint", self.thumbprint
        ]
        if body is not None:
            args += ["-BodyJson", json.dumps(body)]
        if query:
            qlit = "@{ " + "; ".join(f"{k}='{v}'" for k, v in query.items()) + " }"
            args += ["-Query", qlit]
        if headers:
            hlit = "@{ " + "; ".join(f"{k}='{v}'" for k, v in headers.items()) + " }"
            args += ["-Headers", hlit]
        if self.ca_bundle:
            args += ["-CaBundlePath", self.ca_bundle]

        proc = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if proc.returncode != 0:
            raise RuntimeError(f"PowerShell call failed (rc={proc.returncode}).\nSTDERR:\n{proc.stderr}")

        out = proc.stdout.strip()
        if not out:
            return None
        try:
            return json.loads(out)
        except json.JSONDecodeError:
            return out

    # ------------------ Convenience methods ------------------

    def system(self) -> Any:
        """Get /rest/system info."""
        return self._call("/rest/system", "GET")

    def list_scan_results(self, fields: Optional[str] = None, filters: Optional[Dict[str, Any]] = None) -> Any:
        """List scan results."""
        query = {}
        if fields:
            query["fields"] = fields
        if filters:
            query.update(filters)
        return self._call("/rest/scanResult", "GET", query=query or None)

    def get_scan_result(self, result_id: int) -> Any:
        """Get a single scan result by ID."""
        return self._call(f"/rest/scanResult/{result_id}", "GET")

    def start_vuln_export(self, query_id: int, format: str = "csv") -> Any:
        """Start a vulnerability export job (adjust endpoint as needed)."""
        body = {"query_id": query_id, "format": format}
        return self._call("/rest/vulnerability/export", "POST", body=body)

# ---------------- Example usage ----------------
if __name__ == "__main__":
    BASE_URL = "https://sccv03.csp.noaa.gov"
    PICKER_SCRIPT = r"G:\My Drive\CATT_EXTRACTOR\cert_picker.ps1"  # adjust path
    CA_BUNDLE = None  # optional PEM bundle if needed

    tsc = TSCWindowsCAC(BASE_URL, PICKER_SCRIPT, ca_bundle=CA_BUNDLE)

    print("== /rest/system ==")
    print(json.dumps(tsc.system(), indent=2))

    print("\n== /rest/scanResult (first page) ==")
    results = tsc.list_scan_results(fields="id,name,status,repository,createdTime")
    print(json.dumps(results, indent=2))
