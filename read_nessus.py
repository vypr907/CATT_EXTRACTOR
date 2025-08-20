import os
import glob
import pandas as pd
import xml.etree.ElementTree as ET
import argparse
import tkinter as tk
from tkinter import filedialog


class NessusXMLParser:
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

    def get_cat2_findings(self):
        '''Extract findings with CAT:II in cross references.'''
        findings = []

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

                # Look for CAT: II in cross-references
                if any(ref and "CAT:II" in ref for ref in refs):
                    findings.append({
                        "plugin_id": plugin_id,
                        "severity": severity,
                        "plugin_name": plugin_name,
                        "refs": "; ".join(refs)
                    })

        return pd.DataFrame(findings)
    
class NessusToExcelExporter:
    '''Exports findings to an Excel file.'''
    def __init__(self, input_folder, output_file):
        self.input_folder = input_folder
        self.output_file = output_file
        self.files = glob.glob(os.path.join(input_folder, '*.nessus'))

    def run(self):
        '''Process all files and export CAT:II findings to Excel.'''
        if not self.files:
            print(f"No Nessus files found in {self.input_folder}")
            return
        
        with pd.ExcelWriter(self.output_file, engine='openpyxl') as writer:
            for filepath in self.files:
                try:
                    parser = NessusXMLParser(filepath)
                    df = parser.get_cat2_findings()
                    
                    if not df.empty:
                        # Use filename as sheet name, limited to 31 characters
                        sheet_name = os.path.splitext(os.path.basename(filepath))[0][:31]
                        df.to_excel(writer, sheet_name=sheet_name, index=False)
                        print(f"✅ Processed {filepath}, found {len(df)} CAT: II findings")
                    else:
                        print(f"ℹ️ No CAT: II findings in {filepath}")
                except Exception as e:
                    print(f"❌ Error processing {filepath}: {e}")
                    continue

        print(f"\n🎉 Finished! CAT: II findings saved in {self.output_file}")

    def pick_folders_gui():
        '''Fallback to GUI dialogs if no CLI args are provided'''
        root = tk.Tk()
        root.withdraw()

        input_folder = filedialog.askdirectory(
            title="Select Folder Containing .nessus Files"
        )
        if not input_folder:
            print("❌ No folder selected, exiting.")
            exit(1)

        output_file = filedialog.asksaveasfilename(
            title="Save CAT: II findings to Excel",
            defaultextension=".xlsx",
            filetypes=[("Excel Files", "*.xlsx")],
        )
        if not output_file:
            print("❌ No output file selected, exiting.")
            exit(1)

        return input_folder, output_file