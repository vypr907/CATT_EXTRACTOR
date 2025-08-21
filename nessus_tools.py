import os
import glob
import pandas as pd
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path
from typing import List


class NessusParser:
    '''
    Parses a Nessus XML file and extracts relevant information.
    This class is designed to handle Nessus XML files, extracting findings
    and exporting them to an Excel file.
    '''
    def __init__(self, filepath):
        self.filepath = filepath
        self.tree = None
        self.root = None
        self._load()

    def _load(self):
        '''
        Loads the XML file and parses it into an ElementTree object.
        '''
        try:
            self.tree = ET.parse(self.filepath)
            self.root = self.tree.getroot()
        except Exception as e:
            raise RuntimeError(f"Failed to load XML file {self.filepath}: {e}")

    def get_cat_findings(self, cat_lvl=("II",)):
        '''
        Extract findings that match any of the requested CAT levels.
        Args:
            cat_lvl (tuple|list): e.g., ("II",) or ("I", "II", "III")   
        '''
        findings = []
        cat_lvl = [f"CAT:{lvl.upper()}" for lvl in cat_lvl]

        for report in self.root.findall(".//Report"):
            for item in report.findall(".//ReportItem"):
                plugin_id = item.get("pluginID")
                severity = item.get("severity")
                plugin_name = item.get("pluginName")
                
                # Collect cross-references
                refs = []
                for child in item:
                    if child.tag.lower() in ['xref', 'cross-reference']:
                        refs.append(child.text)

                # Look for CAT in cross-references
                if any(ref and any(cl in ref for cl in cat_lvl) for ref in refs):
                    findings.append({
                        "Plugin ID": plugin_id,
                        "Severity": severity,
                        "Plugin Name": plugin_name,
                        "Cross References": "; ".join(refs)
                    })

        return pd.DataFrame(findings)
    
class NessusToExcelExporter:
    '''Exports findings to an Excel file.'''
    def __init__(self, input_folder, output_file, cat_lvl=("II",)):
        self.input_folder = input_folder
        self.output_file = output_file
        self.cat_lvl = cat_lvl
        self.files = glob.glob(os.path.join(input_folder, '*.nessus'))

    def run(self):
        '''Process all files and export CAT:II findings to Excel.'''
        if not self.files:
            print(f"No Nessus files found in {self.input_folder}")
            return
        
        with pd.ExcelWriter(self.output_file, engine='openpyxl') as writer:
            for filepath in self.files:
                try:
                    parser = NessusParser(filepath)
                    df = parser.get_cat_findings()
                    
                    if not df.empty:
                        # Use filename as sheet name, limited to 31 characters
                        sheet_name = os.path.splitext(os.path.basename(filepath))[0][:31]
                        df.to_excel(writer, sheet_name=sheet_name, index=False)
                        print(f"✅ Processed {filepath}, found {len(df)} findings (CAT {','.join(self.cat_lvl)}")
                    else:
                        print(f"ℹ️ No CAT {','.join(self.cat_lvl)} findings in {filepath}")
                except Exception as e:
                    print(f"❌ Error processing {filepath}: {e}")
                    continue

        print(f"\n🎉 Finished! Findings (CAT {','.join(self.cat_lvl)}) saved in {self.output_file}")

class NessusExtractor:
    '''
    Extracts .nessus files from Tenable Security Center ZIP scan downloads
    into a single folder.
    '''

    def __init__(self, source_folder: str, destination_folder: str):
        self.source_folder = Path(source_folder)
        self.destination_folder = Path(destination_folder)
        self.destination_folder.mkdir(parents=True, exist_ok=True)

    def extract_all(self) -> List[Path]:
        '''
        Extract all .nessus files from ZIPs in the source folder.
        Returns a list of extracted file paths.
        '''
        extracted_files = []

        for zip_path in self.source_folder.glob("*.zip"):
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                for file in zip_ref.namelist():
                    if file.endswith('.nessus'):
                        extracted_path = self.destination_folder / Path(file).name
                        with zip_ref.open(file) as src, open(extracted_path, 'wb') as dst:
                            dst.write(src.read())
                        extracted_files.append(extracted_path)
                        print(f"[+] Extracted {file} from {zip_path.name}to {extracted_path}")
                    else:
                        print(f"Skipping {file} (not a .nessus file)")
        return extracted_files