import os
import hashlib
import json
import threading
import time
import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox
from PIL import Image, ImageTk
import logging  # ]logging module

# Configure logging
logging.basicConfig(
    filename='fims_log.txt',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class FileIntegrityMonitorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("File Integrity Monitoring System")

        try:
            img = Image.open("icon.png")
            self.icon = ImageTk.PhotoImage(img)
            self.root.iconphoto(True, self.icon)
        except Exception as e:
            print("Could not load icon:", e)

        # Widgets
        tk.Label(root, text="Directory to Monitor:").grid(row=0, column=0, sticky="w", padx=10, pady=5)

        self.path_entry = tk.Entry(root, width=60)
        self.path_entry.grid(row=1, column=0, padx=10, pady=5)

        tk.Button(root, text="Browse", command=self.browse_directory).grid(row=1, column=1, padx=5)

        self.start_button = tk.Button(root, text="Start Monitoring", command=self.start_monitoring)
        self.start_button.grid(row=2, column=0, pady=5, padx=10, sticky="w")

        self.stop_button = tk.Button(root, text="Stop Monitoring", command=self.stop_monitoring, state=tk.DISABLED)
        self.stop_button.grid(row=2, column=1, pady=5, padx=5)

        self.output = scrolledtext.ScrolledText(root, width=90, height=25, state=tk.DISABLED)
        self.output.grid(row=3, column=0, columnspan=2, padx=10, pady=5)

        self.monitoring = False
        self.thread = None
        self.hashes_file = "file_hashes.json"

    def browse_directory(self):
        path = filedialog.askdirectory()
        if path:
            self.path_entry.delete(0, tk.END)
            self.path_entry.insert(0, path)

    def start_monitoring(self):
        directory = self.path_entry.get()
        if not os.path.isdir(directory):
            messagebox.showerror("Error", "Invalid directory path.")
            return

        self.monitoring = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.append_output(f"\nStarted monitoring: {directory}\n")
        logging.info(f"Started monitoring directory: {directory}")  # <-- Log start of monitoring
        self.thread = threading.Thread(target=self.monitor_directory, args=(directory,), daemon=True)
        self.thread.start()

    def stop_monitoring(self):
        self.monitoring = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.append_output("\nMonitoring stopped.\n")
        logging.info("Monitoring interrupted by user.")  # <-- Log when monitoring stops

    def get_all_files(self, path):
        file_paths = []
        for root, _, files in os.walk(path):
            for file in files:
                full_path = os.path.join(root, file)
                if os.path.isfile(full_path):
                    file_paths.append(full_path)
        return file_paths

    def generate_file_hash(self, filepath):
        try:
            with open(filepath, "rb") as f:
                return hashlib.sha256(f.read()).hexdigest()
        except Exception:
            return None

    def load_hashes(self):
        if os.path.exists(self.hashes_file):
            try:
                with open(self.hashes_file, "r") as f:
                    return json.load(f)
            except Exception:
                # Corrupted file or JSON error, start fresh
                return {}
        return {}

    def save_hashes(self, hashes):
        try:
            with open(self.hashes_file, "w") as f:
                json.dump(hashes, f, indent=4)
        except Exception:
            pass

    def monitor_directory(self, path):
        previous_hashes = self.load_hashes()

        while self.monitoring:
            current_hashes = {}
            added, modified, deleted = [], [], []

            for file in self.get_all_files(path):
                file_hash = self.generate_file_hash(file)
                if file_hash:
                    current_hashes[file] = file_hash

                    if file not in previous_hashes:
                        added.append(file)
                        logging.info(f"Added file: {file}")  # Log added files
                    elif previous_hashes[file] != file_hash:
                        modified.append(file)
                        logging.info(f"Modified file: {file}")  # Log modified files

            for file in previous_hashes:
                if file not in current_hashes:
                    deleted.append(file)
                    logging.info(f"Deleted file: {file}")  #  Log deleted files

            output_text = f"\n[Scan @ {time.strftime('%H:%M:%S')}]\n"
            if added or modified or deleted:
                for f in added:
                    output_text += f"Added: {f}\n"
                for f in modified:
                    output_text += f"Modified: {f}\n"
                for f in deleted:
                    output_text += f"Deleted: {f}\n"
            else:
                output_text += "No changes detected.\n"
                logging.info("No changes detected.")  #  Log when no changes detected

            # Thread-safe GUI update
            self.root.after(0, lambda txt=output_text: self.append_output(txt))

            previous_hashes = current_hashes.copy()
            self.save_hashes(current_hashes)

            for _ in range(10):  # wait 10 seconds
                if not self.monitoring:
                    break
                time.sleep(1)

    def append_output(self, text):
        self.output.configure(state=tk.NORMAL)
        self.output.insert(tk.END, text)
        self.output.see(tk.END)
        self.output.configure(state=tk.DISABLED)

if __name__ == "__main__":
    root = tk.Tk()
    app = FileIntegrityMonitorGUI(root)
    root.geometry("700x600")
    root.mainloop()
