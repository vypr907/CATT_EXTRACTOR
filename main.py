import argparse
import tkinter as tk
from tkinter import filedialog
from nessus_tools import NessusToExcelExporter
from nessus_tools import NessusExtractor

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

def main():
    parser = argparse.ArgumentParser(
        description="Extract CATT data from Nessus scan files and save to an Excel file."
    )
    parser.add_argument("--input","-i", help="Input folder containing .nessus or .zip files")
    parser.add_argument("--output","-o", help="Output file path for the Excel file")
    parser.add_argument(
        "--cat", "-c", nargs="+", default=["II"],
        help="CAT levels to extract (e.g., --cat II or --cat I II III)"
    )
    parser.add_argument(
        "--unzip", "-u", action="store_true",
        help="Unzip the .zip files in the input folder before extracting CATT data"
    )

    args = parser.parse_args()
    
    if args.input and args.output:
        input_folder = args.input
        output_file = args.output
        cat_lvl = args.cat
    else:
        input_folder, output_file = pick_folders_gui()
        cat_lvl = ["II"]

    # Step 1: If requested, unzip all Nessus files first
    if args.unzip:
        print(f"📦 Extracting all ZIPs from {input_folder}...")
        extractor = NessusExtractor(input_folder)
        extracted_folder = input_folder / "extracted_nessus"
        extracted_folder.mkdir(exist_ok=True)

        extractor.extract_all(extracted_folder)
        input_folder = extracted_folder  # update to point exporter to extracted files

    # Step 2: Export Nessus CAT findings to Excel
    print(f"📑 Processing Nessus files in {input_folder}...")
    exporter = NessusToExcelExporter(input_folder, output_file, cat_lvl)
    exporter.run()
    print(f"✅ Done!")
    print(f"✅ Data saved to {output_file}")


if __name__ == "__main__":
    main()
# g:\My Drive\CATT_EXTRACTOR\main.py