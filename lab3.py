import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import random
import time

# Mock file system for simulation
mock_files = {
    "documents": ["resume.docx", "report.pdf", "notes.txt"],
    "downloads": ["game.exe", "setup.zip", "song.mp3"],
    "pictures": ["photo1.jpg", "holiday.png", "family.bmp"]
}

infected_files = []


class VirusSimulator:
    def __init__(self, master):
        self.master = master
        master.title("Virus Simulation Tool")
        master.geometry("950x650")
        master.configure(bg="#f8f9fa")

        # Title bar
        title_frame = tk.Frame(master, bg="#660000")
        title_frame.pack(fill="x")
        ttk.Label(
            title_frame,
            text="🦠 Virus Simulation Tool (Educational & Safe)",
            font=("Segoe UI", 20, "bold"),
            foreground="white",
            background="#660000"
        ).pack(pady=10)

        # Buttons
        btn_frame = tk.Frame(master, bg="#f8f9fa")
        btn_frame.pack(pady=15)

        ttk.Button(btn_frame, text="🧪 Simulate Infection", command=self.simulate_infection).grid(row=0, column=0, padx=10)
        ttk.Button(btn_frame, text="📂 Simulate Spread", command=self.simulate_spread).grid(row=0, column=1, padx=10)
        ttk.Button(btn_frame, text="🛡️ Detect & Remove", command=self.detect_and_remove).grid(row=0, column=2, padx=10)
        ttk.Button(btn_frame, text="💾 Export Report", command=self.export_report).grid(row=0, column=3, padx=10)

        # Results text area
        self.result_box = tk.Text(master, font=("Consolas", 11), height=25, width=110, bg="white", fg="black")
        self.result_box.pack(padx=15, pady=10, fill="both", expand=True)

        # Data holder
        self.scan_results = []

    def log(self, message):
        """Helper function to log messages into text box"""
        self.result_box.insert(tk.END, message + "\n")
        self.result_box.see(tk.END)
        self.scan_results.append(message)
        self.master.update()

    def simulate_infection(self):
        """Simulate infection of random files"""
        self.log("\n[Simulation] 🔥 Starting infection...\n")
        for folder, files in mock_files.items():
            for file in files:
                if random.choice([True, False]):  # 50% chance
                    infected_files.append(f"{folder}/{file}")
                    self.log(f"⚠️ Infected: {folder}/{file}")
                    time.sleep(0.2)
        if not infected_files:
            self.log("✅ No files were infected.")
        else:
            self.log(f"\n[Simulation] Infection complete. {len(infected_files)} files infected.\n")

    def simulate_spread(self):
        """Simulate virus spreading to new files"""
        self.log("\n[Simulation] 📂 Virus spreading...\n")
        for folder in mock_files.keys():
            new_file = f"newfile_{random.randint(100, 999)}.txt"
            mock_files[folder].append(new_file)
            infected_files.append(f"{folder}/{new_file}")
            self.log(f"⚠️ New infected file created: {folder}/{new_file}")
            time.sleep(0.2)
        self.log("\n[Simulation] Spread complete.\n")

    def detect_and_remove(self):
        """Simulate antivirus detection and removal"""
        if not infected_files:
            self.log("\n🛡️ No infected files found. System is clean.\n")
            return
        self.log("\n[Antivirus] 🔎 Scanning for infections...\n")
        time.sleep(0.5)
        for file in infected_files.copy():
            self.log(f"✅ Removed infection: {file}")
            infected_files.remove(file)
            time.sleep(0.2)
        self.log("\n[Antivirus] System is now clean.\n")

    def export_report(self):
        """Export log report"""
        if not self.scan_results:
            messagebox.showinfo("Export", "No simulation data to export.")
            return
        filename = filedialog.asksaveasfilename(defaultextension=".txt",
                                                filetypes=[("Text files", "*.txt")])
        if not filename:
            return
        try:
            with open(filename, "w", encoding="utf-8") as f:
                for line in self.scan_results:
                    f.write(line + "\n")
            messagebox.showinfo("Export", f"Report exported to {filename}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export report:\n{e}")


if __name__ == "__main__":
    root = tk.Tk()
    app = VirusSimulator(root)
    root.mainloop()
