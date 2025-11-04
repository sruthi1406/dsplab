import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import pandas as pd
import re
import os
import requests
from io import StringIO

# ------------------- PII Patterns -------------------
PII_PATTERNS = {
    "Email": r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+',
    "Phone": r'\b\d{10}\b',
    "Aadhaar": r'\b\d{4}\s?\d{4}\s?\d{4}\b',
    "PAN": r'[A-Z]{5}\d{4}[A-Z]{1}',
    "Name": r'\b[A-Z][a-z]+ [A-Z][a-z]+\b'
}

class PIIDetectorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("PII Data Identifier & Classifier")
        self.root.geometry("1000x650")
        self.root.configure(bg="#e8eef2")

        # ---------------- Header Section ----------------
        header_frame = tk.Frame(root, bg="#2b3a67", height=70)
        header_frame.pack(fill='x')

        tk.Label(
            header_frame,
            text="🔒 PII Data Identifier & Classifier",
            font=("Verdana", 20, "bold"),
            fg="white",
            bg="#2b3a67"
        ).pack(pady=15)

        # ---------------- Input Section ----------------
        input_frame = tk.Frame(root, bg="#e8eef2")
        input_frame.pack(pady=20)

        tk.Label(input_frame, text="Enter dataset URL (optional):", 
                 font=("Arial", 12, "bold"), bg="#e8eef2", fg="#333").grid(row=0, column=0, padx=10, pady=5)

        self.url_entry = tk.Entry(input_frame, font=("Arial", 12), width=55, relief="groove", bd=2)
        self.url_entry.grid(row=0, column=1, padx=10, pady=5)

        btn_frame = tk.Frame(input_frame, bg="#e8eef2")
        btn_frame.grid(row=1, column=0, columnspan=2, pady=10)

        tk.Button(btn_frame, text="Load from URL", command=self.load_from_url,
                  bg="#0078d7", fg="white", font=("Arial", 11, "bold"), width=15, relief="flat").pack(side="left", padx=10)

        tk.Button(btn_frame, text="Upload Local File", command=self.upload_file,
                  bg="#28a745", fg="white", font=("Arial", 11, "bold"), width=15, relief="flat").pack(side="left", padx=10)

        # ---------------- Separator ----------------
        ttk.Separator(root, orient="horizontal").pack(fill="x", padx=40, pady=10)

        # ---------------- Results Section ----------------
        result_frame = tk.LabelFrame(root, text="Analysis Report", 
                                     font=("Arial", 12, "bold"), bg="#fdfdfd", fg="#2b3a67", padx=10, pady=10)
        result_frame.pack(fill="both", expand=True, padx=30, pady=10)

        self.text_area = tk.Text(result_frame, wrap="word", font=("Courier New", 11),
                                 height=20, bg="#f8fafc", fg="#111", relief="flat", padx=10, pady=10)
        self.text_area.pack(fill='both', expand=True)

    # ------------------- Detect from URL (In Transit) -------------------
    def load_from_url(self):
        url = self.url_entry.get().strip()
        if not url.startswith("http"):
            messagebox.showerror("Invalid URL", "Please enter a valid URL (starting with http/https).")
            return
        try:
            response = requests.get(url)
            response.raise_for_status()
            if url.endswith(".csv"):
                df = pd.read_csv(StringIO(response.text), nrows=100)
                self.analyze_structured_data(df, "In Transit")
            else:
                text = response.text
                self.analyze_unstructured_data(text, "In Transit")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to fetch data: {e}")

    # ------------------- Detect from Local File (At Rest) -------------------
    def upload_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("CSV files","*.csv"),("Text files","*.txt")])
        if not file_path:
            return
        
        ext = os.path.splitext(file_path)[1].lower()
        try:
            if ext == ".csv":
                data = pd.read_csv(file_path, nrows=100)
                self.analyze_structured_data(data, "At Rest")
            elif ext == ".txt":
                with open(file_path, "r", encoding="utf-8") as f:
                    text = f.read()
                self.analyze_unstructured_data(text, "At Rest")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read file: {e}")

    # ------------------- Structured Data Analysis -------------------
    def analyze_structured_data(self, df, state):
        result = ["✅ Data Type: Structured"]
        result.append(f"✅ Data State: {state}")
        result.append("⚙️ Data is currently being processed → In Use")

        pii_found = False
        for col in df.columns:
            col_data = df[col].astype(str).str.cat(sep=' ')
            for key, pattern in PII_PATTERNS.items():
                if re.search(pattern, col_data):
                    result.append(f"⚠️ PII Detected: {key} found in column '{col}'")
                    pii_found = True
        
        if not pii_found:
            result.append("✔️ No PII Detected in structured dataset.")
        
        self.display_result(result)

    # ------------------- Unstructured Data Analysis -------------------
    def analyze_unstructured_data(self, text, state):
        result = ["✅ Data Type: Unstructured"]
        result.append(f"✅ Data State: {state}")
        result.append("⚙️ Data is currently being processed → In Use")

        pii_found = False
        for key, pattern in PII_PATTERNS.items():
            matches = re.findall(pattern, text)
            if matches:
                result.append(f"⚠️ PII Detected: {key} ({len(matches)} instances)")
                pii_found = True
        
        if not pii_found:
            result.append("✔️ No PII Detected in unstructured data.")
        
        self.display_result(result)

    def display_result(self, lines):
        self.text_area.delete("1.0", tk.END)
        self.text_area.insert(tk.END, "\n".join(lines))

if __name__ == "__main__":
    root = tk.Tk()
    app = PIIDetectorApp(root)
    root.mainloop()
