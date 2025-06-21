import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import hashlib
import threading
import os
import datetime
import webbrowser

class HashingCalculatorApp(tk.Tk):
    """
    A comprehensive hashing tool that calculates hashes for text, single files,
    and all files within a directory, with selectable algorithms.
    """
    def __init__(self):
        super().__init__()
        self.title("Comprehensive Hashing Calculator")
        self.geometry("800x950") # Adjusted height for new section

        # --- Style Configuration ---
        style = ttk.Style(self)
        style.theme_use('clam')
        style.configure('TLabel', font=('Helvetica', 10))
        style.configure('TButton', font=('Helvetica', 10, 'bold'))
        style.configure('TEntry', font=('Courier New', 10))
        style.configure('Treeview.Heading', font=('Helvetica', 10, 'bold'))
        style.configure('TLabelFrame.Label', font=('Helvetica', 11, 'bold'))
        style.configure('Match.TLabel', foreground='green', font=('Helvetica', 10, 'bold'))
        style.configure('NoMatch.TLabel', foreground='red', font=('Helvetica', 10, 'bold'))
        style.configure('Found.Treeview', foreground='red')
        # --- NEW: Style for hyperlink ---
        style.configure('Hyperlink.TLabel', foreground='blue', font=('Helvetica', 10, 'underline'))


        self.available_algorithms = sorted(hashlib.algorithms_available)
        self.loaded_hash_set = set()

        self.create_menu()
        self.create_widgets()

    def create_menu(self):
        """Creates the main menu bar for the application."""
        self.menu_bar = tk.Menu(self)
        self.config(menu=self.menu_bar)

        file_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.menu_bar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Load Hash Set...", command=self.load_hash_set)
        file_menu.add_command(label="Export Hashes...", command=self.export_hashes)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.destroy)
        
        # --- NEW: Help menu with About option ---
        help_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.menu_bar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about_window)

    # --- NEW: About Window Function ---
    def show_about_window(self):
        """Displays the 'About' window with creator information."""
        about_window = tk.Toplevel(self)
        about_window.title("About Hashing Calculator")
        about_window.geometry("350x200")
        about_window.resizable(False, False)
        about_window.transient(self) # Keep it on top of the main window

        about_frame = ttk.Frame(about_window, padding="15")
        about_frame.pack(expand=True, fill="both")
        
        ttk.Label(about_frame, text="Comprehensive Hashing Calculator", font=('Helvetica', 12, 'bold')).pack(pady=(0, 10))
        
        # Copyright and Creator Info
        year = datetime.datetime.now().year
        ttk.Label(about_frame, text=f"Copyright © {year}, Md Tazmir").pack()
        ttk.Label(about_frame, text="All rights reserved.").pack()
        
        # Facebook Link
        ttk.Label(about_frame, text="Contact:", font=('Helvetica', 10, 'bold')).pack(pady=(15,0))
        fb_link = ttk.Label(about_frame, text="Facebook: Md Tazmir", style='Hyperlink.TLabel', cursor="hand2")
        fb_link.pack()
        fb_link.bind("<Button-1>", lambda e: webbrowser.open_new("https://www.facebook.com/share/1B2m9DZ4CL/"))


    def create_widgets(self):
        main_frame = ttk.Frame(self, padding="10")
        main_frame.pack(expand=True, fill="both")

        input_frame = ttk.LabelFrame(main_frame, text="Input Data", padding=10)
        input_frame.pack(fill="x", pady=5)
        ttk.Label(input_frame, text="Input Text:").pack(anchor="w")
        self.text_input = tk.Text(input_frame, height=4, width=60, font=('Courier New', 10))
        self.text_input.pack(fill="x", expand=True, pady=(0, 10))
        
        button_frame = ttk.Frame(input_frame)
        button_frame.pack(fill="x")
        ttk.Button(button_frame, text="Calculate from Text", command=self.calculate_text_hashes).pack(side="left", expand=True, fill="x", padx=2)
        ttk.Button(button_frame, text="Calculate from File...", command=self.start_file_hash_thread).pack(side="left", expand=True, fill="x", padx=2)
        ttk.Button(button_frame, text="Calculate from Directory...", command=self.start_directory_hash_thread).pack(side="left", expand=True, fill="x", padx=2)

        # --- Algorithm Selection Section ---
        alg_frame = ttk.LabelFrame(main_frame, text="Algorithm Selection", padding=10)
        alg_frame.pack(fill="x", pady=5)
        list_frame = ttk.Frame(alg_frame); list_frame.pack(fill="x", expand=True)
        self.alg_listbox = tk.Listbox(list_frame, selectmode=tk.MULTIPLE, height=6, exportselection=False)
        for alg in self.available_algorithms: self.alg_listbox.insert(tk.END, alg.upper())
        self.alg_listbox.pack(side="left", fill="both", expand=True)
        alg_scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=self.alg_listbox.yview); alg_scrollbar.pack(side="right", fill="y")
        self.alg_listbox.config(yscrollcommand=alg_scrollbar.set)
        alg_button_frame = ttk.Frame(alg_frame); alg_button_frame.pack(fill="x", pady=5)
        ttk.Button(alg_button_frame, text="Select All", command=self.select_all_algs).pack(side="left", expand=True, fill="x", padx=2)
        ttk.Button(alg_button_frame, text="Select Common", command=self.select_common_algs).pack(side="left", expand=True, fill="x", padx=2)
        ttk.Button(alg_button_frame, text="Deselect All", command=self.deselect_all_algs).pack(side="left", expand=True, fill="x", padx=2)
        self.select_common_algs() # Select common algorithms by default

        self.file_details_frame = ttk.LabelFrame(main_frame, text="File/Directory Details", padding=10)
        self.file_details_frame.pack(fill="x", pady=5)
        self.file_details_label = ttk.Label(self.file_details_frame, text="No file or directory selected.")
        self.file_details_label.pack(anchor="w")

        output_frame = ttk.LabelFrame(main_frame, text="Hash Values", padding=10)
        output_frame.pack(expand=True, fill="both", pady=10)
        columns = ('status', 'file_name', 'algorithm', 'hash_value')
        self.tree = ttk.Treeview(output_frame, columns=columns, show='headings', height=10)
        self.tree.heading('status', text='Status'); self.tree.heading('file_name', text='File Name'); self.tree.heading('algorithm', text='Algorithm'); self.tree.heading('hash_value', text='Hash Value')
        self.tree.column('status', width=80, anchor='center'); self.tree.column('file_name', width=200, anchor='w'); self.tree.column('algorithm', width=100, anchor='w'); self.tree.column('hash_value', width=350, anchor='w')
        self.tree.tag_configure('found', foreground='red', font=('Helvetica', 9, 'bold'))
        scrollbar = ttk.Scrollbar(output_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        self.tree.grid(row=0, column=0, sticky='nsew'); scrollbar.grid(row=0, column=1, sticky='ns')
        output_frame.grid_rowconfigure(0, weight=1); output_frame.grid_columnconfigure(0, weight=1)
        self.tree.bind("<Button-3>", self.show_context_menu)
        
        compare_frame = ttk.LabelFrame(main_frame, text="Compare Single Hash", padding=10)
        compare_frame.pack(fill="x", pady=5)
        ttk.Label(compare_frame, text="Known Hash:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.compare_entry = ttk.Entry(compare_frame, width=50, font=('Courier New', 10))
        self.compare_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        ttk.Button(compare_frame, text="Compare", command=self.compare_hashes).grid(row=0, column=2, padx=10, pady=5)
        self.compare_result_label = ttk.Label(compare_frame, text="")
        self.compare_result_label.grid(row=1, column=1, padx=5, pady=2, sticky="w")
        
        clear_button_frame = ttk.Frame(main_frame)
        clear_button_frame.pack(fill="x", pady=5)
        ttk.Button(clear_button_frame, text="Clear All", command=self.clear_all).pack(side="right")

        status_frame = ttk.Frame(main_frame)
        status_frame.pack(fill="x", pady=(5,0))
        self.status_label = ttk.Label(status_frame, text="Ready.")
        self.status_label.pack(anchor="w")
        self.progress_bar = ttk.Progressbar(status_frame, orient='horizontal', mode='determinate')
        self.progress_bar.pack(fill="x", pady=2)
    
    # --- Algorithm Listbox Helpers ---
    def select_all_algs(self): self.alg_listbox.selection_set(0, tk.END)
    def deselect_all_algs(self): self.alg_listbox.selection_clear(0, tk.END)
    def select_common_algs(self):
        self.deselect_all_algs()
        common = ['MD5', 'SHA1', 'SHA256', 'SHA512']
        for i, item in enumerate(self.alg_listbox.get(0, tk.END)):
            if item in common: self.alg_listbox.selection_set(i)
    def get_selected_algorithms(self):
        selected_indices = self.alg_listbox.curselection()
        if not selected_indices:
            messagebox.showwarning("No Selection", "Please select at least one hashing algorithm.")
            return []
        return [self.alg_listbox.get(i).lower() for i in selected_indices]

    # --- Other Methods (Updated to use selected algorithms) ---
    def calculate_text_hashes(self):
        selected_algs = self.get_selected_algorithms()
        if not selected_algs: return
        self.clear_all(clear_text_input=False)
        input_text = self.text_input.get("1.0", tk.END).strip()
        if not input_text: messagebox.showwarning("Warning", "Input text is empty."); return
        self.status_label.config(text="Calculating hashes for text...")
        try:
            input_bytes = input_text.encode('utf-8')
            for alg in selected_algs:
                hasher = hashlib.new(alg); hasher.update(input_bytes)
                hex_digest = hasher.hexdigest(32) if 'shake' in alg else hasher.hexdigest()
                self.insert_hash_into_tree("", "(From Text Input)", alg.upper(), hex_digest)
            self.status_label.config(text="Calculation complete.")
        except Exception as e: messagebox.showerror("Error", f"Could not calculate hashes: {e}"); self.status_label.config(text="Error.")
        self.run_batch_compare()

    def start_file_hash_thread(self, filepath=None):
        selected_algs = self.get_selected_algorithms()
        if not selected_algs: return
        if not filepath: filepath = filedialog.askopenfilename(title="Select a file to hash")
        if not filepath: return
        self.clear_all()
        self.display_file_details(filepath)
        self.status_label.config(text=f"Hashing file: {os.path.basename(filepath)}...")
        thread = threading.Thread(target=self.calculate_file_hashes, args=(filepath, selected_algs,), daemon=True); thread.start()

    def calculate_file_hashes(self, filepath, selected_algs):
        try:
            hashers = {alg: hashlib.new(alg) for alg in selected_algs}
            file_size = os.path.getsize(filepath)
            bytes_read = 0
            with open(filepath, 'rb') as f:
                while True:
                    chunk = f.read(65536)
                    if not chunk: break
                    for hasher in hashers.values(): hasher.update(chunk)
                    bytes_read += len(chunk)
                    self.master.after(0, self.update_progress, (bytes_read / file_size) * 100)
            self.master.after(0, self.populate_tree, hashers, os.path.basename(filepath))
            self.master.after(0, lambda: self.status_label.config(text="File hashing complete."))
            self.master.after(0, self.run_batch_compare)
        except Exception as e:
            self.master.after(0, lambda: messagebox.showerror("Error", f"Could not hash file: {e}"))
            self.master.after(0, lambda: self.status_label.config(text="Error."))

    def start_directory_hash_thread(self):
        selected_algs = self.get_selected_algorithms()
        if not selected_algs: return
        dirpath = filedialog.askdirectory(title="Select a directory to hash")
        if not dirpath: return
        self.clear_all()
        self.display_file_details(dirpath, is_dir=True)
        thread = threading.Thread(target=self.calculate_directory_hashes, args=(dirpath, selected_algs,), daemon=True); thread.start()

    def calculate_directory_hashes(self, dirpath, selected_algs):
        files_to_hash = [os.path.join(root, name) for root, _, files in os.walk(dirpath) for name in files]
        total_files = len(files_to_hash)
        if total_files == 0: self.master.after(0, lambda: self.status_label.config(text="No files found.")); return
        for i, filepath in enumerate(files_to_hash):
            try:
                self.master.after(0, lambda f=filepath: self.status_label.config(text=f"Hashing ({i+1}/{total_files}): {os.path.basename(f)}"))
                hashers = {alg: hashlib.new(alg) for alg in selected_algs}
                with open(filepath, 'rb') as f:
                    while True:
                        chunk = f.read(65536)
                        if not chunk: break
                        for hasher in hashers.values(): hasher.update(chunk)
                self.master.after(0, self.populate_tree, hashers, os.path.basename(filepath))
                self.master.after(0, self.update_progress, ((i + 1) / total_files) * 100)
            except Exception as e:
                self.master.after(0, self.insert_hash_into_tree, "ERROR", os.path.basename(filepath), "ERROR", str(e))
        self.master.after(0, lambda: self.status_label.config(text="Directory hashing complete."))
        self.master.after(0, self.run_batch_compare)

    # All other helper methods (export, copy, compare, etc.) remain largely the same,
    # just need to be aware of the new column indices.
    # The full, correct code for them is included below for completeness.
    def load_hash_set(self):
        filepath = filedialog.askopenfilename(title="Load Hash Set File", filetypes=[("Text files", "*.txt"), ("CSV files", "*.csv"), ("All files", "*.*")])
        if not filepath: return
        try:
            with open(filepath, 'r') as f: self.loaded_hash_set = {line.strip().lower() for line in f if line.strip()}
            count = len(self.loaded_hash_set)
            self.status_label.config(text=f"Loaded {count} hashes. Comparing against current results...")
            messagebox.showinfo("Success", f"Successfully loaded {count} hashes into the set.")
            self.run_batch_compare()
        except Exception as e: messagebox.showerror("Error", f"Failed to load hash set: {e}")
    def run_batch_compare(self):
        if not self.loaded_hash_set: return
        for row_id in self.tree.get_children():
            values = list(self.tree.item(row_id, 'values'))
            hash_value = values[3].lower()
            if hash_value in self.loaded_hash_set:
                values[0] = "MATCH FOUND"; self.tree.item(row_id, values=values, tags=('found',))
            else:
                values[0] = ""; self.tree.item(row_id, values=values, tags=())
    def export_hashes(self):
        if not self.tree.get_children(): messagebox.showwarning("Export Warning", "There are no hash values to export."); return
        filepath = filedialog.asksaveasfilename(title="Export Hashes", defaultextension=".csv", filetypes=[("CSV files", "*.csv"), ("Text files", "*.txt"), ("All files", "*.*")])
        if not filepath: return
        try:
            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                f.write("Status,File Name,Algorithm,Hash Value\n")
                for row_id in self.tree.get_children(): values = self.tree.item(row_id, 'values'); f.write(f'"{values[0]}","{values[1]}",{values[2]},{values[3]}\n')
            self.status_label.config(text=f"Hashes exported successfully to {os.path.basename(filepath)}")
            messagebox.showinfo("Export Successful", f"Results have been exported to:\n{filepath}")
        except Exception as e: messagebox.showerror("Export Error", f"Failed to export file: {e}")
    def show_context_menu(self, event):
        row_id = self.tree.identify_row(event.y)
        if row_id:
            self.tree.selection_set(row_id)
            context_menu = tk.Menu(self, tearoff=0)
            context_menu.add_command(label="Copy File Name", command=self.copy_file_name)
            context_menu.add_command(label="Copy Algorithm", command=self.copy_algorithm_name)
            context_menu.add_command(label="Copy Hash Value", command=self.copy_hash_value)
            context_menu.tk_popup(event.x_root, event.y_root)
    def copy_to_clipboard(self, text_to_copy):
        self.clipboard_clear(); self.clipboard_append(text_to_copy)
        self.status_label.config(text=f"Copied to clipboard: {text_to_copy[:40]}...")
    def copy_file_name(self):
        selected_item = self.tree.focus();
        if selected_item: self.copy_to_clipboard(self.tree.item(selected_item, 'values')[1])
    def copy_algorithm_name(self):
        selected_item = self.tree.focus()
        if selected_item: self.copy_to_clipboard(self.tree.item(selected_item, 'values')[2])
    def copy_hash_value(self):
        selected_item = self.tree.focus()
        if selected_item: self.copy_to_clipboard(self.tree.item(selected_item, 'values')[3])
    def compare_hashes(self):
        known_hash = self.compare_entry.get().strip().lower()
        if not known_hash: self.compare_result_label.config(text="Please enter a hash.", style=""); return
        found_match = False
        for row_id in self.tree.get_children():
            calculated_hash = self.tree.item(row_id, 'values')[3].lower()
            if known_hash == calculated_hash:
                found_match = True; self.tree.selection_set(row_id); self.tree.focus(row_id); self.tree.see(row_id); break
        if found_match: self.compare_result_label.config(text="MATCH ✔", style="Match.TLabel")
        else: self.compare_result_label.config(text="NO MATCH ❌", style="NoMatch.TLabel")
    def update_progress(self, value): self.progress_bar['value'] = value
    def populate_tree(self, hashers, filename):
        for alg, hasher in sorted(hashers.items()):
            try:
                hex_digest = hasher.hexdigest(32) if 'shake' in alg else hasher.hexdigest()
                self.insert_hash_into_tree("", filename, alg.upper(), hex_digest)
            except TypeError: continue
    def insert_hash_into_tree(self, status, filename, algorithm, hash_value):
        tags = ()
        if self.loaded_hash_set and hash_value.lower() in self.loaded_hash_set:
            status = "MATCH FOUND"; tags = ('found',)
        self.tree.insert('', tk.END, values=(status, filename, algorithm, hash_value), tags=tags)
    def clear_tree(self):
        for item in self.tree.get_children(): self.tree.delete(item)
    def display_file_details(self, path, is_dir=False):
        try:
            if is_dir: details = f"Directory: {os.path.basename(path)}"
            else:
                stats = os.stat(path); size_in_mb = stats.st_size / (1024 * 1024)
                mod_time = datetime.datetime.fromtimestamp(stats.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                details = f"File: {os.path.basename(path)}  |  Size: {size_in_mb:.2f} MB  |  Modified: {mod_time}"
            self.file_details_label.config(text=details)
        except Exception: self.file_details_label.config(text="Could not retrieve details.")
    def clear_all(self, clear_text_input=True):
        if clear_text_input: self.text_input.delete("1.0", tk.END)
        self.clear_tree(); self.compare_entry.delete(0, tk.END)
        self.compare_result_label.config(text="")
        self.file_details_label.config(text="No file or directory selected.")
        self.status_label.config(text="Ready.")
        self.progress_bar['value'] = 0

if __name__ == '__main__':
    app = HashingCalculatorApp()
    app.mainloop()
