import os
import hashlib
import json
import time
import logging
from pathlib import Path

class FileIntegrityMonitor:
    """
    Monitors the integrity of files within a specified directory by calculating SHA-256 hashes.
    Detects added, modified, or deleted files by comparing current hashes with stored records.
    Logs detected changes with timestamps and provides console feedback during execution.
    """

    def __init__(self, directory, hash_record_file="file_hashes.json", log_file="fims_log.txt", interval=10):
        """
        Initializes the monitor with the directory path to scan, paths for hash record file and log file,
        and the monitoring interval in seconds.
        """
        self.directory = directory
        self.hash_record_file = hash_record_file
        self.interval = interval
        self._setup_logging(log_file)

    def _setup_logging(self, log_file):
        """
        Configures logging to write messages with timestamps to the specified log file.
        """
        logging.basicConfig(
            filename=log_file,
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        logging.info("Logger initialized.")

    def calculate_hash(self, file_path):
        """
        Calculates the SHA-256 hash of the specified file.
        Returns the hexadecimal digest string.
        Returns None if the file cannot be read due to missing file or permissions.
        """
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                # Reads file in chunks of 4096 bytes to handle large files efficiently
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except FileNotFoundError:
            logging.warning(f"File not found during hashing: {file_path}")
            return None
        except Exception as e:
            logging.error(f"Error reading file during hashing {file_path}: {e}")
            return None

    def load_hashes(self):
        """
        Loads stored file hashes from the JSON record file.
        Returns an empty dictionary if the file does not exist or is corrupted.
        """
        if Path(self.hash_record_file).exists():
            try:
                with open(self.hash_record_file, 'r') as f:
                    return json.load(f)
            except json.JSONDecodeError:
                logging.warning("Hash record file corrupted or empty; starting with empty record.")
        return {}

    def save_hashes(self, hashes):
        """
        Saves the current dictionary of file hashes to the JSON record file.
        """
        try:
            with open(self.hash_record_file, 'w') as f:
                json.dump(hashes, f, indent=4)
        except Exception as e:
            logging.error(f"Error saving hash records: {e}")

    def scan_directory(self):
        """
        Recursively scans the monitored directory and calculates SHA-256 hashes for all files,
        excluding the hash record file and log file to prevent false positives.
        """
        current_hashes = {}
        for root, _, files in os.walk(self.directory):
            for filename in files:
                # Skip the hash record file and log file to avoid self-detection loop
                if filename in [os.path.basename(self.hash_record_file), os.path.basename('fims_log.txt')]:
                    continue
                file_path = os.path.join(root, filename)
                file_hash = self.calculate_hash(file_path)
                if file_hash:
                    current_hashes[file_path] = file_hash
        return current_hashes

    def monitor_changes(self):
        """
        Compares current file hashes with previously stored hashes.
        Detects added, modified, and deleted files.
        Logs detected changes and prints a detailed summary to the console.
        """
        print(f"Scanning directory: {self.directory} ...")
        old_hashes = self.load_hashes()
        new_hashes = self.scan_directory()

        modified = []
        added = []
        deleted = []

        # Files present in old record but missing now are considered deleted
        for path, old_hash in old_hashes.items():
            new_hash = new_hashes.get(path)
            if new_hash is None:
                deleted.append(path)
            elif new_hash != old_hash:
                modified.append(path)

        # Files present now but missing in old record are considered added
        for path in new_hashes:
            if path not in old_hashes:
                added.append(path)

        if modified or added or deleted:
            print("Changes detected:")
            logging.info("Changes detected.")
            if modified:
                print(" Modified files:")
                logging.info("Modified files:\n" + "\n".join(modified))
                for f in modified:
                    print("  -", f)
            if added:
                print(" Added files:")
                logging.info("Added files:\n" + "\n".join(added))
                for f in added:
                    print("  -", f)
            if deleted:
                print(" Deleted files:")
                logging.info("Deleted files:\n" + "\n".join(deleted))
                for f in deleted:
                    print("  -", f)
        else:
            print("No changes detected.")
            logging.info("No changes detected.")

        self.save_hashes(new_hashes)

    def start_monitoring(self):
        """
        Starts continuous monitoring of the directory.
        Runs indefinitely until interrupted by the user.
        Prints progress and waits between scans according to the configured interval.
        """
        logging.info(f"Started monitoring directory: {self.directory}")
        print(f"Started monitoring directory: {self.directory}")
        try:
            while True:
                self.monitor_changes()
                print(f"Waiting {self.interval} seconds before next scan...\n")
                time.sleep(self.interval)
        except KeyboardInterrupt:
            print("\nMonitoring interrupted by user.")
            logging.info("Monitoring interrupted by user.")
        except Exception as e:
            print(f"Monitoring stopped due to error: {e}")
            logging.error(f"Monitoring stopped due to error: {e}")


if __name__ == "__main__":
    directory = input("Enter the directory to monitor: ").strip()
    if not os.path.isdir(directory):
        print("Invalid directory. Exiting.")
    else:
        monitor = FileIntegrityMonitor(directory)
        monitor.start_monitoring()
