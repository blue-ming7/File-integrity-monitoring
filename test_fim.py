import unittest
import os
import json
import hashlib
import tempfile
import shutil
from unittest.mock import patch, MagicMock
import time

# GUI class
from fim_gui import FileIntegrityMonitorGUI
import tkinter as tk


class TestFileIntegrityMonitorGUI(unittest.TestCase):
    def setUp(self):
        #  temporary directory with test files
        self.test_dir = tempfile.mkdtemp()
        self.test_file_path = os.path.join(self.test_dir, "testfile.txt")
        with open(self.test_file_path, "w") as f:
            f.write("Hello world!")

        # Tkinter root window but hide it during tests
        self.root = tk.Tk()
        self.root.withdraw()  # Hide the root window during testing

        # Initialize the GUI object
        self.app = FileIntegrityMonitorGUI(self.root)

        # temporary hashes file
        self.app.hashes_file = os.path.join(self.test_dir, "file_hashes.json")

    def tearDown(self):
        # Destroy Tkinter root after tests
        self.root.destroy()
        # Remove temp directory and files
        shutil.rmtree(self.test_dir)

    def test_get_all_files(self):
        files = self.app.get_all_files(self.test_dir)
        self.assertIn(self.test_file_path, files)

    def test_generate_file_hash(self):
        expected_hash = hashlib.sha256(b"Hello world!").hexdigest()
        actual_hash = self.app.generate_file_hash(self.test_file_path)
        self.assertEqual(expected_hash, actual_hash)

    def test_load_and_save_hashes(self):
        hashes = {self.test_file_path: "dummyhash"}
        # Save hashes
        self.app.save_hashes(hashes)
        # Load hashes
        loaded_hashes = self.app.load_hashes()
        self.assertEqual(hashes, loaded_hashes)

    @patch('threading.Thread')
    @patch('tkinter.messagebox.showerror')
    def test_start_monitoring_invalid_directory(self, mock_msgbox, mock_thread):
        self.app.path_entry.delete(0, tk.END)
        self.app.path_entry.insert(0, "/invalid/path")
        self.app.start_monitoring()
        mock_msgbox.assert_called_once_with("Error", "Invalid directory path.")
        self.assertFalse(self.app.monitoring)
        mock_thread.assert_not_called()

    @patch('threading.Thread')
    def test_start_and_stop_monitoring(self, mock_thread):
        # Insert valid directory
        self.app.path_entry.delete(0, tk.END)
        self.app.path_entry.insert(0, self.test_dir)

        # Mock thread start to prevent actual thread creation
        mock_thread.return_value = MagicMock()

        self.app.start_monitoring()
        self.assertTrue(self.app.monitoring)
        self.assertEqual(self.app.start_button['state'], tk.DISABLED)
        self.assertEqual(self.app.stop_button['state'], tk.NORMAL)
        mock_thread.assert_called_once()

        self.app.stop_monitoring()
        self.assertFalse(self.app.monitoring)
        self.assertEqual(self.app.start_button['state'], tk.NORMAL)
        self.assertEqual(self.app.stop_button['state'], tk.DISABLED)


if __name__ == "__main__":
    unittest.main()
