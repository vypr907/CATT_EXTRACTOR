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

    def get_cat_findings(self, cat_lvls=("II",)):
        '''
        Extract findings that match any of the requested CAT levels,
        and include the host associated with the finding.
        Args:
            cat_lvls (tuple|list): e.g., ("II",) or ("I", "II", "III")   
        '''
        print(f"⚙️  Parsing Nessus files...")
        print(f"⚙️  Extracting findings for CAT levels: {cat_lvls}")

        findings = []
        cat_lvls = [f"CAT|{lvl.upper()}" for lvl in cat_lvls]

        for report in self.root.findall(".//Report"):
            for host in report.findall(".//ReportHost"):
                hostname = host.get("name", "UNKNOWN")

                for item in host.findall(".//ReportItem"):
                    plugin_id = item.get("pluginID")
                    severity = item.get("severity")
                    plugin_name = item.get("pluginName")
                    description = item.findtext("description", default="").strip()

                    # ----- Compliance findings ---
                    compliance_ref = (item.findtext("{*}compliance-reference") or "").strip()
                    compliance_result = (item.findtext("{*}compliance-result") or "").strip()

                    # Only process FAILED compliance results
                    if compliance_result != "FAILED":
                        continue

                    # Check if any requested CAT level is presnt in the compliance result
                    for cat_lvl in cat_lvls:
                        if cat_lvl in compliance_ref.upper():
                            findings.append({
                                "Hostname": hostname,
                                "Plugin ID": plugin_id,
                                "Severity": severity,
                                "Result": compliance_result,
                                "Plugin Name": plugin_name,
                                "Description": description.strip(),
                                "CAT": cat_lvl.split("|")[1],
                                "Compliance Reference": compliance_ref.strip(),
                            })


        if findings:
            return pd.DataFrame(findings)
        else:
            return pd.DataFrame(columns=[
                "Hostname",
                "Plugin ID",
                "Severity",
                "Result",
                "Plugin Name",
                "Description",
                "CAT",
                "Cross References",
                "Compliance Reference",
                "Compliance Result"
            ])

    
class NessusToExcelExporter:
    '''Exports findings to an Excel file.'''
    def __init__(self, input_folder, output_file, cat_lvls=("II",)):
        self.input_folder = input_folder
        self.output_file = output_file
        self.cat_lvls = cat_lvls
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
                    df = parser.get_cat_findings(cat_lvls=self.cat_lvls)
                    
                    if not df.empty:
                        # Use filename as sheet name, limited to 31 characters
                        sheet_name = os.path.splitext(os.path.basename(filepath))[0][:31]
                        df.to_excel(writer, sheet_name=sheet_name, index=False)
                        print(f"✅  Processed {filepath}, found {len(df)} findings (CAT {','.join(self.cat_lvls)}")
                    else:
                        print(f"ℹ️  No CAT {','.join(self.cat_lvls)} findings in {filepath}")
                except Exception as e:
                    print(f"❌ Error processing {filepath}: {e}")
                    continue
            if not any_written:
                placeholder_df = pd.DataFrame(
                    {
                        "Message": [
                            f"No CAT {','.join(self.cat_lvls)} findings found in any file."
                        ]
                    }
                )
                placeholder_df.to_excel(writer, sheet_name="No_Findings", index=False)
                print("⚠️  No findings found in any file. Wrote placeholder sheet")

        print(f"\n🎉 Finished! Findings (CAT {','.join(self.cat_lvls)}) saved in {self.output_file}")

class NessusExtractor:
    '''
    Extracts .nessus files from Tenable Security Center ZIP scan downloads
    into a single folder, renaming them based on the ZIP filename.
    '''

    def __init__(self, source_folder: str, destination_folder: str):
        self.source_folder = Path(source_folder)
        self.destination_folder = Path(destination_folder)
        self.destination_folder.mkdir(parents=True, exist_ok=True)

    def extract_all(self) -> List[Path]:
        '''
        Extract all .nessus files from ZIPs in the source folder.
        Rename them based on the ZIP filename.
        Returns a list of extracted file paths.
        '''
        print(f"⚙️  NessusExtractor initialized...")

        extracted_files = []

        for zip_path in self.source_folder.glob("*.zip"):
            # Derive friendly name from ZIP filename
            zip_stem = zip_path.stem # e.g., "PAAN_OP_WIN10_DISA"
            friendly_name = zip_stem
            # Remove "PAAN_" prefix and "_DISA" suffix if present
            if friendly_name.startswith("PAAN_"):
                friendly_name = friendly_name[len("PAAN_"):]
            if friendly_name.endswith("_DISA"):
                friendly_name = friendly_name[:-len("_DISA")]
            friendly_name += ".nessus" # final filename

            # Rename the extracted file to the friendly name
            extracted_path = self.destination_folder / friendly_name
            
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                for file in zip_ref.namelist():
                    if file.endswith('.nessus'):
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