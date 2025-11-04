import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox, font
from tkinter.ttk import Progressbar, Style
import csv
import time
import time

DICTIONARY = ["1234", "password", "qwerty", "letmein", "admin", "welcome", "pass123", "hello", "abcd"]

def check_strength(password):
    length = len(password)
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)

    score = 0
    if length >= 8:
        score += 1
    if has_lower:
        score += 1
    if has_upper:
        score += 1
    if has_digit:
        score += 1
    if has_special:
        score += 1

    if length >= 12 and score >= 4:
        return "Very Strong"
    elif score >= 4:
        return "Strong"
    elif score >= 3:
        return "Medium"
    else:
        return "Weak"

def dictionary_attack(hash_value, progress, output_text):
    found = False
    output_text.delete("1.0", tk.END)
    for i, word in enumerate(DICTIONARY):
        test_hash = hashlib.sha256(word.encode()).hexdigest()
        progress["value"] = ((i + 1) / len(DICTIONARY)) * 100
        root.update()  # Force a full GUI update
        time.sleep(0.05)  # Add a small delay to make the update visible
        if test_hash == hash_value:
            output_text.insert(tk.END, f"Password Found: {word}\n")
            found = True
            break
    if not found:
        output_text.insert(tk.END, "Password not found in dictionary.\n")

def export_to_csv(passwords):
    if not passwords or (len(passwords) == 1 and not passwords[0]):
        messagebox.showwarning("Warning", "No passwords to export.")
        return
    file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
    if not file_path:
        return
    with open(file_path, mode="w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["Password", "Strength"])
        for pw in passwords:
            writer.writerow([pw, check_strength(pw)])
    messagebox.showinfo("Export", "Report exported successfully!")

def generate_hash():
    password = hash_entry.get().strip()
    if not password:
        messagebox.showwarning("Warning", "Please enter text to hash.")
        return
    
    # Check if the input is a comma-separated list and take the first item
    if ',' in password:
        password = password.split(',')[0].strip()
        
    pw_hash = hashlib.sha256(password.encode()).hexdigest()
    output_text.delete("1.0", tk.END)
    output_text.insert(tk.END, f"Password: {password}\n")
    output_text.insert(tk.END, f"SHA-256 Hash: {pw_hash}\n")

# --- UI Setup ---
root = tk.Tk()
root.title("Dictionary Attack Simulator")
root.geometry("600x550")
root.configure(bg="#2c3e50")
root.minsize(500, 450)

# --- Style Configuration ---
style = Style(root)
style.theme_use('clam')
style.configure("blue.Horizontal.TProgressbar",
                foreground='#3498db',
                background='#3498db',
                troughcolor='#34495e',
                bordercolor='#2c3e50',
                lightcolor='#3498db',
                darkcolor='#3498db')

# --- Fonts and Colors ---
BG_COLOR = "#2c3e50"
FRAME_COLOR = "#34495e"
TEXT_COLOR = "#ecf0f1"
BUTTON_COLOR = "#3498db"
BUTTON_ACTIVE_COLOR = "#2980b9"
ENTRY_BG_COLOR = "#2c3e50"

app_font = font.Font(family="Helvetica", size=12)
title_font = font.Font(family="Helvetica", size=16, weight="bold")

# --- Main Frame ---
main_frame = tk.Frame(root, bg=BG_COLOR, padx=20, pady=20)
main_frame.pack(expand=True, fill=tk.BOTH)

# --- Title ---
title_label = tk.Label(main_frame, text="Dictionary Attack Simulator", font=title_font, bg=BG_COLOR, fg=TEXT_COLOR)
title_label.pack(pady=(0, 20))

# --- Input Frame ---
input_frame = tk.Frame(main_frame, bg=FRAME_COLOR, padx=15, pady=15, relief=tk.RIDGE, borderwidth=2)
input_frame.pack(fill=tk.X, pady=10)

tk.Label(input_frame, text="Enter SHA-256 Hash or Passwords (comma-separated):", font=app_font, bg=FRAME_COLOR, fg=TEXT_COLOR).pack(anchor='w')
hash_entry = tk.Entry(input_frame, width=50, font=app_font, bg=ENTRY_BG_COLOR, fg=TEXT_COLOR, insertbackground=TEXT_COLOR, relief=tk.FLAT, borderwidth=5)
hash_entry.pack(fill=tk.X, pady=5, ipady=5)

# --- Output Frame ---
output_frame = tk.Frame(main_frame, bg=FRAME_COLOR, padx=15, pady=15, relief=tk.RIDGE, borderwidth=2)
output_frame.pack(expand=True, fill=tk.BOTH, pady=10)

tk.Label(output_frame, text="Results:", font=app_font, bg=FRAME_COLOR, fg=TEXT_COLOR).pack(anchor='w')
output_text = tk.Text(output_frame, height=10, width=60, font=app_font, bg=ENTRY_BG_COLOR, fg=TEXT_COLOR, relief=tk.FLAT, borderwidth=5, wrap=tk.WORD, insertbackground=TEXT_COLOR)
output_text.pack(expand=True, fill=tk.BOTH, pady=5)

# --- Progress Bar ---
progress = Progressbar(main_frame, orient=tk.HORIZONTAL, length=300, mode='determinate', style="blue.Horizontal.TProgressbar")
progress.pack(pady=20, fill=tk.X)

# --- Button Frame ---
button_frame = tk.Frame(main_frame, bg=BG_COLOR)
button_frame.pack(fill=tk.X, side=tk.BOTTOM)
button_frame.columnconfigure((0, 1), weight=1)
button_frame.rowconfigure((0, 1), weight=1)

def start_attack():
    hash_val = hash_entry.get().strip()
    if len(hash_val) != 64 or not all(c in '0123456789abcdefABCDEF' for c in hash_val):
        messagebox.showerror("Error", "Invalid SHA-256 hash!")
        return
    dictionary_attack(hash_val.lower(), progress, output_text)

def analyze_passwords():
    passwords = [p.strip() for p in hash_entry.get().split(",") if p.strip()]
    output_text.delete("1.0", tk.END)
    if not passwords:
        output_text.insert(tk.END, "Please enter passwords to analyze.\n")
        return
    for pw in passwords:
        strength = check_strength(pw)
        output_text.insert(tk.END, f"{pw}: {strength}\n")

def export_passwords():
    passwords = [p.strip() for p in hash_entry.get().split(",") if p.strip()]
    export_to_csv(passwords)

# --- Buttons ---
def create_button(parent, text, command, row, col):
    button = tk.Button(parent, text=text, command=command, font=app_font, bg=BUTTON_COLOR, fg="black", 
                       activebackground=BUTTON_ACTIVE_COLOR, activeforeground="black", 
                       relief=tk.FLAT, padx=10, pady=8, width=25)
    button.grid(row=row, column=col, padx=5, pady=5, sticky="ew")
    return button

attack_button = create_button(button_frame, "Start Dictionary Attack", start_attack, 0, 0)
strength_button = create_button(button_frame, "Check Password Strength", analyze_passwords, 0, 1)
export_button = create_button(button_frame, "Export Analysis Report", export_passwords, 1, 0)
hash_button = create_button(button_frame, "Generate SHA-256 Hash", generate_hash, 1, 1)

root.mainloop()