import os
import glob
import pandas as pd
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path
from typing import List
import tkinter as tk
from tkinter import filedialog


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
        print(f"⚙️  Parsing Nessus files...")
        print(f"⚙️  Extracting findings for CAT levels: {cat_lvl}")

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
            any_written = False
            print(f"⚙️  Processing Nessus files in {self.input_folder}...")

            for filepath in self.files:
                try:
                    parser = NessusParser(filepath)
                    df = parser.get_cat_findings()
                    
                    if not df.empty:
                        # Use filename as sheet name, limited to 31 characters
                        sheet_name = os.path.splitext(os.path.basename(filepath))[0][:31]
                        df.to_excel(writer, sheet_name=sheet_name, index=False)
                        print(f"✅  Processed {filepath}, found {len(df)} findings (CAT {','.join(self.cat_lvl)}")
                    else:
                        print(f"ℹ️  No CAT {','.join(self.cat_lvl)} findings in {filepath}")
                except Exception as e:
                    print(f"❌ Error processing {filepath}: {e}")
                    continue
            if not any_written:
                placeholder_df = pd.DataFrame(
                    {
                        "Message": [
                            f"No CAT {','.join(self.cat_lvl)} findings found in any file."
                        ]
                    }
                )
                placeholder_df.to_excel(writer, sheet_name="No_Findings", index=False)
                print("⚠️  No findings found in any file. Wrote placeholder sheet")

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
        print(f"⚙️  NessusExtractor initialized...")

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
    

class NessusWorkflow:
    '''
    Orchestrates the Nessus workflow. Extraction, Parsing, and Exporting.
    '''

    def __init__(self, input_folder, output_file, cat_lvls=("II",)):
        self.input_folder = Path(input_folder).resolve()
        self.output_file = Path(output_file).resolve()
        self.cat_lvls = cat_lvls

    def run(self):
        print(f"📂 Starting Nessus workflow...")
        # Step 1: Extract .nessus files from ZIP files if required
        zip_files = list(self.input_folder.glob("*.zip"))
        if zip_files: #only extract if zips are present
            print(f"📦 Found {len(zip_files)} ZIP files to extract. Extracting from {self.input_folder}...")
            extracted_folder = self.input_folder / "extracted_nessus"
            extracted_folder.mkdir(exist_ok=True)
            extractor = NessusExtractor(self.input_folder, extracted_folder)
            extractor.extract_all()
            self.input_folder = extracted_folder
        else:
            print(f"ℹ️ No ZIP files found in {self.input_folder}, skipping extraction.")

        # Step 2: Export CAT findings to Excel
        print(f"📑 Processing Nessus files in {self.input_folder}...")
        exporter = NessusToExcelExporter(self.input_folder, self.output_file, self.cat_lvls)
        exporter.run()

        print(f"✅ Finished processing Nessus files in {self.input_folder}")
        print(f"✅ Exported CAT findings to {self.output_file}")
        print(f"✅ All done!")

def pick_folders_gui():
    root = tk.Tk()
    root.withdraw()

    input_folder = filedialog.askdirectory(
        title="Select the folder containing the Nessus XML files"
    )
    if not input_folder:
        print("❌ No folder selected. Exiting.")
        exit(1)

    output_file = filedialog.asksaveasfilename(
        title="Save Excel File As",
        defaultextension=".xlsx",
        filetypes=[("Excel Files", "*.xlsx")],
        initialfile="CATT_Extracted_Data.xlsx",
    )
    if not output_file:
        print("❌ No file selected. Exiting.")
        exit(1)
    
    return input_folder, output_file