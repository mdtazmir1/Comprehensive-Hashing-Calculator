Comprehensive Hashing Calculator
This tool is a powerful and user-friendly desktop application designed for digital forensics, data integrity verification, and general-purpose hashing tasks. Built with Python and Tkinter, it provides a responsive and efficient user experience.

Key Features (A-Z)
1. Complete Hashing Algorithm Support:

Supports all hashing algorithms available in your system's Python hashlib library (e.g., MD5, SHA-1, SHA-256, SHA-512, BLAKE2, SHAKE, RIPEMD160, and many more).

2. Flexible Input Methods:

Text Input: Directly type or paste any text string to calculate its hashes instantly.

Single File Input: Select any specific file from your system to calculate its hashes.

Directory Input: Select an entire folder or directory to calculate the hashes of all files within it, including subdirectories.

3. Advanced User Interface:

Detailed Results Table: Hash results are displayed in a clean, multi-column list showing Status, File Name, Algorithm, and the Hash Value.

File & Directory Information: When a file or directory is selected, the tool displays its important details, including name, size, and last modification date.

Algorithm Selection: Users can select one or multiple specific hashing algorithms to run, speeding up the process by avoiding unnecessary calculations. Helper buttons like "Select All", "Select Common" (MD5, SHA1, SHA256, SHA512), and "Deselect All" are available.

4. Interactive and User-Friendly Functionality:

Context Menu (Right-Click): Right-click on any result in the list to easily copy the File Name, Algorithm, or Hash Value to the clipboard.

Hash Comparison:

Single Compare: A dedicated section allows you to paste a known hash and compare it against the calculated hashes in the list. The tool highlights any matching row.

Batch Compare (Hash Set): Load a text file containing a list of known hashes (e.g., from NIST NSRL or a virus database). The tool will automatically check all calculated hashes against this list and flag any matches with a "MATCH FOUND" status.

Clear All: A convenient "Clear All" button resets the entire interface, clearing all inputs, results, and file details.

5. Data Export and Management:

File Menu: A functional "File" menu provides access to key features.

Export Results: Export the entire list of calculated hashes to a CSV file for documentation, reporting, or further analysis.

Load Hash Set: Load a set of known hashes from a .txt or .csv file for batch comparison.

6. High-Performance and Responsive Design:

Multithreading: Time-consuming tasks like hashing large files or entire directories are run in a separate background thread. This ensures the user interface remains smooth and responsive at all times.

Live Progress Bar: A progress bar provides real-time feedback on the status of lengthy hashing operations.

Status Updates: A status bar at the bottom of the window keeps the user informed about the application's current state (e.g., "Hashing file...", "Calculation complete.", "Ready.").

These features make the Comprehensive Hashing Calculator a robust and professional-grade utility suitable for both enthusiasts and experts in the field of digital forensics and data integrity.

License
This project is licensed under the MIT License.
