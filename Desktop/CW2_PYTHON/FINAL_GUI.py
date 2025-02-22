import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import mysql.connector
import os
import json
from datetime import datetime
import hashlib
import shutil
import threading
import ctypes 
from ttkthemes import ThemedTk
from typing import List, Optional, Dict, Any, Tuple
from recoveryCLI import RecoveryScanner, FileInfo, BackupScanner, TempFileScanner, HiddenFileScanner
import platform

class EnhancedRecoveryGUI:
    def __init__(self):
        
        self.root = ThemedTk(theme="equilux")
        self.root.title("Enhanced File Recovery System")
        self.root.geometry("1000x700")
        # self.root.configure(bg="white")
        self.root.configure(bg="white")
        self.init_database()    
        self.current_user = None
        self.recovery_history = []
        self.files_list = []
        self.current_scanner = None
        self.current_scan_type = None
        
        # Initialize different scanners
        self.temp_scanner = TempFileScanner()
        
        # Navigation history
        self.current_state = {}
        
        self.show_login_frame()
    @staticmethod
    def get_creation_date(file_path):
        """Get the actual creation date of a file."""
        try:
            if platform.system() == "Windows":
                return datetime.fromtimestamp(os.stat(file_path).st_ctime)
            elif platform.system() == "Darwin":  # macOS
                return datetime.fromtimestamp(os.stat(file_path).st_birthtime)
            else:  # Linux (fallback to modified time)
                stat_info = os.stat(file_path)
                return datetime.fromtimestamp(stat_info.st_ctime if hasattr(stat_info, 'st_ctime') else stat_info.st_mtime)
        except Exception:
            return None



    def init_database(self):
        temp_conn = mysql.connector.connect(
            host="localhost",
            user="root",
            password=""
        )
        temp_cursor = temp_conn.cursor()
        temp_cursor.execute("CREATE DATABASE IF NOT EXISTS recovery_system")
        temp_conn.commit()
        temp_cursor.close()
        temp_conn.close()

        self.conn = mysql.connector.connect(
            host="localhost",
            user="root",
            password="",
            database="recovery_system"
        )
        self.cursor = self.conn.cursor()
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(255) UNIQUE,
                password TEXT,
                recovery_history TEXT
            )
        ''')
        self.conn.commit()

    def save_current_state(self):
        if hasattr(self, 'dir_var'):
            current_state = {
                'dir': self.dir_var.get() if hasattr(self, 'dir_var') else "",
                'files_list': self.files_list,
                'current_scanner': self.current_scanner,
                'current_scan_type': self.current_scan_type
            }
            self.current_state = current_state

   
        
    def show_directory_selection_frame(self):
        self.clear_window()
        
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.pack(expand=True, fill="both")
        
        # Top menu frame
        menu_frame = ttk.Frame(main_frame)
        menu_frame.pack(fill=tk.X, pady=(0, 20))
        
        ttk.Label(menu_frame, text=f"Welcome, {self.current_user}!", font=("Helvetica", 16)).pack(side=tk.LEFT)
        ttk.Button(menu_frame, text="Logout", command=self.logout).pack(side=tk.RIGHT, padx=5)
        ttk.Button(menu_frame, text="Delete Account", command=self.delete_account).pack(side=tk.RIGHT, padx=5)
        ttk.Button(menu_frame, text="View History", command=self.show_history).pack(side=tk.RIGHT, padx=5)
        
        # Directory selection frame
        dir_frame = ttk.LabelFrame(main_frame, text="Select Target Directory", padding="20")
        dir_frame.pack(expand=True, fill="both", pady=(20, 20))
        
        self.dir_var = tk.StringVar(value=self.current_state.get('dir', ''))
        ttk.Label(dir_frame, text="Target Directory:", font=("Helvetica", 12)).pack(pady=(20, 10))
        
        entry_frame = ttk.Frame(dir_frame)
        entry_frame.pack(fill=tk.X, pady=10)
        
        ttk.Entry(entry_frame, textvariable=self.dir_var, width=70).pack(side=tk.LEFT, padx=5)
        ttk.Button(entry_frame, text="Browse", command=self.browse_directory).pack(side=tk.LEFT, padx=5)
        
        button_frame = ttk.Frame(dir_frame)
        button_frame.pack(pady=30)
        
        ttk.Button(button_frame, text="Continue", command=self.show_main_frame, style="Accent.TButton", width=15).pack()

    def show_main_frame(self):
        self.save_current_state()
        self.clear_window()
        
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.pack(expand=True, fill="both")
        
        # Top menu frame
        menu_frame = ttk.Frame(main_frame)
        menu_frame.pack(fill=tk.X, pady=(0, 20))
        
        ttk.Label(menu_frame, text=f"Welcome, {self.current_user}!", font=("Helvetica", 16)).pack(side=tk.LEFT)
        ttk.Button(menu_frame, text="Logout", command=self.logout).pack(side=tk.RIGHT, padx=5)
        ttk.Button(menu_frame, text="Delete Account", command=self.delete_account).pack(side=tk.RIGHT, padx=5)
        ttk.Button(menu_frame, text="View History", command=self.show_history).pack(side=tk.RIGHT, padx=5)
        
        # Directory display and back button
        dir_frame = ttk.Frame(main_frame)
        dir_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(dir_frame, text="Current Directory: ").pack(side=tk.LEFT)
        ttk.Label(dir_frame, text=self.dir_var.get() or "Not selected").pack(side=tk.LEFT)
        ttk.Button(dir_frame, text="Change Directory", command=self.show_directory_selection_frame).pack(side=tk.RIGHT)
        
        # Recovery method selection frame
        recovery_frame = ttk.LabelFrame(main_frame, text="Recovery Methods", padding="10")
        recovery_frame.pack(fill=tk.X, pady=(0, 20))
        
        methods = [
            ("Deleted Files Recovery", self.scan_recycle_bin, "recycle_bin"),
            ("Backup File Recovery", self.scan_backups, "backup"),
            ("Temporary File Recovery", self.scan_temp_files, "temp"),
            ("Hidden File Recovery", self.scan_hidden_files, "hidden"),
            # ("All Recovery Methods", self.scan_all, "all")
        ]
        
        for text, command, scan_type in methods:
            btn = ttk.Button(recovery_frame, text=text)
            btn.configure(command=lambda c=command, t=scan_type: self.handle_scan_button(c, t))
            btn.pack(side=tk.LEFT, padx=5)
        
        # Files display frame with checkboxes
        self.files_frame = ttk.Frame(main_frame)
        self.files_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create a frame for the select all checkbox
        select_all_frame = ttk.Frame(self.files_frame)
        select_all_frame.pack(fill=tk.X, pady=(0, 5))
        
        self.select_all_var = tk.BooleanVar(value=False)
        select_all_cb = ttk.Checkbutton(select_all_frame, text="Select All", 
                                       variable=self.select_all_var, 
                                       command=self.toggle_select_all)
        select_all_cb.pack(side=tk.LEFT)
        
        # Create treeview with checkboxes
        columns = ("Select", "Index", "Name", "Size", "Deletion Date", "Type", "Confidence")
        self.tree = ttk.Treeview(self.files_frame, columns=columns, show="headings", selectmode="extended")
        
        for col in columns:
            self.tree.heading(col, text=col)
            if col == "Select":
                self.tree.column(col, width=60, anchor=tk.CENTER)
            elif col == "Index":
                self.tree.column(col, width=60)
            else:
                self.tree.column(col, width=120)
        
        scrollbar = ttk.Scrollbar(self.files_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # File selection tracking
        self.selected_files = {}  # Maps item IDs to their selection state
        self.tree.bind('<ButtonRelease-1>', self.handle_checkbox_click)
        
        # Bottom buttons frame
        buttons_frame = ttk.Frame(main_frame)
        buttons_frame.pack(fill=tk.X, pady=20)
        
        ttk.Button(buttons_frame, text="Recover Selected", command=self.recover_selected).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Refresh", command=self.refresh_current_scan_type).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Clear", command=self.clear_files_list).pack(side=tk.LEFT, padx=5)

    def handle_scan_button(self, scan_command, scan_type):
        self.current_scan_type = scan_type
        scan_command()

    def browse_directory(self):
        directory = filedialog.askdirectory()
        if directory:
            self.dir_var.set(directory)

    def toggle_select_all(self):
        select_all = self.select_all_var.get()
        for item_id in self.tree.get_children():
            self.selected_files[item_id] = select_all
            # Update checkbox display
            current_values = self.tree.item(item_id, "values")
            updated_values = list(current_values)
            updated_values[0] = "☑" if select_all else "☐"
            self.tree.item(item_id, values=updated_values)

    def handle_checkbox_click(self, event):
        region = self.tree.identify_region(event.x, event.y)
        if region == "cell":
            column = self.tree.identify_column(event.x)
            if column == "#1":  # The "Select" column
                item_id = self.tree.identify_row(event.y)
                if item_id:
                    # Toggle selection state
                    self.selected_files[item_id] = not self.selected_files.get(item_id, False)
                    
                    # Update checkbox display
                    current_values = self.tree.item(item_id, "values")
                    updated_values = list(current_values)
                    updated_values[0] = "☑" if self.selected_files[item_id] else "☐"
                    self.tree.item(item_id, values=updated_values)
                    
                    # Update the select all checkbox if needed
                    self.update_select_all_state()

    def update_select_all_state(self):
        # Check if all items are selected
        all_selected = all(self.selected_files.values()) if self.selected_files else False
        self.select_all_var.set(all_selected)

    def scan_recycle_bin(self):
        directory = self.dir_var.get()
        self.current_scanner = RecoveryScanner(directory)
        self.refresh_current_scan()

    def scan_backups(self):
        directory = self.dir_var.get()
        if not directory:
            messagebox.showwarning("Warning", "Please select a directory first")
            return
        self.backup_scanner = BackupScanner(directory)
        backup_files = self.backup_scanner.scan_for_backups()
        if not backup_files:
            self.refresh_files_list([])  # This will show "No files found" message
        else:
            self.refresh_files_list(backup_files)

    # def scan_temp_files(self):
    #     temp_files = self.temp_scanner.scan_temp_files()
    #     if not temp_files:
    #         self.refresh_files_list([])  # This will show "No files found" message
    #     else:
    #         self.refresh_files_list(temp_files)

    def scan_temp_files(self):
        directory = self.dir_var.get()
        if not directory:
            messagebox.showwarning("Warning", "Please select a directory first")
            return
            
        # Create dialog for scan type selection
        dialog = tk.Toplevel(self.root)
        dialog.title("Select Scan Type")
        dialog.geometry("300x150")
        dialog.transient(self.root)  # Make dialog modal
        
        # Center the dialog
        dialog.update_idletasks()
        width = dialog.winfo_width()
        height = dialog.winfo_height()
        x = (dialog.winfo_screenwidth() // 2) - (width // 2)
        y = (dialog.winfo_screenheight() // 2) - (height // 2)
        dialog.geometry(f'{width}x{height}+{x}+{y}')
        
        # Frame for content
        frame = ttk.Frame(dialog, padding="20")
        frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(frame, text="Choose Scan Type:").pack(pady=(0, 10))
        
        scan_result = {'type': None}  # Using dict to store result
        
        def set_scan_type(scan_type):
            scan_result['type'] = scan_type
            dialog.destroy()
        
        ttk.Button(
            frame, 
            text="Scan Current Directory", 
            command=lambda: set_scan_type("directory")
        ).pack(fill=tk.X, pady=5)
        
        ttk.Button(
            frame, 
            text="Scan Entire System", 
            command=lambda: set_scan_type("system")
        ).pack(fill=tk.X, pady=5)
        
        # Wait for dialog to close
        self.root.wait_window(dialog)
        
        if scan_result['type'] is None:  # User closed the dialog
            return
            
        if scan_result['type'] == "system":
            # Existing system-wide scan
            temp_files = self.temp_scanner.scan_temp_files()
        else:
            # New directory-specific scan
            temp_files = self._scan_directory_temp_files(directory)
            
        if not temp_files:
            self.refresh_files_list([])  # This will show "No files found" message
        else:
            self.refresh_files_list(temp_files)

    def _scan_directory_temp_files(self, directory: str) -> List[FileInfo]:
        """Scan for temporary files in a specific directory."""
        temp_files = []
        temp_extensions = ['.tmp', '.temp', '.$$$', '.wbk', '.~*']
        
        try:
            for root, _, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    # Check if file ends with any temp extension
                    if any(file.lower().endswith(ext) for ext in temp_extensions):
                        try:
                            stats = os.stat(file_path)
                            file_info = FileInfo(
                                path=file_path,
                                original_path=file_path,  # Add this line to fix the error
                                original_name=file,
                                size=stats.st_size,
                                modified=datetime.fromtimestamp(stats.st_mtime),
                                recovery_type='temp',
                                confidence=0.9  # High confidence for matching extensions
                            )
                            temp_files.append(file_info)
                        except (OSError, PermissionError):
                            continue
                    
                    # Also check for files that might be temporary based on patterns
                    elif ('temp' in file.lower() or 'tmp' in file.lower()):
                        try:
                            stats = os.stat(file_path)
                            file_info = FileInfo(
                                path=file_path,
                                original_path=file_path,  # Add this line to fix the error
                                original_name=file,
                                size=stats.st_size,
                                modified=datetime.fromtimestamp(stats.st_mtime),
                                recovery_type='temp',
                                confidence=0.7  # Lower confidence for pattern matching
                            )
                            temp_files.append(file_info)
                        except (OSError, PermissionError):
                            continue
                            
        except Exception as e:
            messagebox.showerror("Error", f"Error scanning directory: {str(e)}")
            return []
            
        return temp_files


    def scan_hidden_files(self):
        directory = self.dir_var.get()
        if not directory:
            messagebox.showwarning("Warning", "Please select a directory first")
            return
        self.hidden_scanner = HiddenFileScanner(directory)
        hidden_files = self.hidden_scanner.scan_hidden_files()
        if not hidden_files:
            self.refresh_files_list([])  # This will show "No files found" message
        else:
            self.refresh_files_list(hidden_files)

    def scan_all(self):
        directory = self.dir_var.get()
        if not directory:
            messagebox.showwarning("Warning", "Please select a directory first")
            return
            
        all_files = []
        try:
            scanner = RecoveryScanner(directory)
            recycle_bin_files = scanner.scan_directory()
            all_files.extend(recycle_bin_files)
            print(f"DEBUG: Found {len(recycle_bin_files)} files in Recycle Bin")  # Debugging
        except Exception as e:
            print(f"ERROR: Failed to scan Recycle Bin - {str(e)}")

    # Backup Files
        try:
            backup_scanner = BackupScanner(directory)
            backup_files = backup_scanner.scan_for_backups()
            all_files.extend(backup_files)
            print(f"DEBUG: Found {len(backup_files)} backup files")  # Debugging
        except Exception as e:
            print(f"ERROR: Failed to scan backup files - {str(e)}")

    # Temp Files
        try:
            temp_files = self.temp_scanner.scan_temp_files()
            all_files.extend(temp_files)
            print(f"DEBUG: Found {len(temp_files)} temporary files")  # Debugging
        except Exception as e:
            print(f"ERROR: Failed to scan temp files - {str(e)}")

    # Hidden Files
        try:
            hidden_scanner = HiddenFileScanner(directory)
            hidden_files = hidden_scanner.scan_hidden_files()
            all_files.extend(hidden_files)
            print(f"DEBUG: Found {len(hidden_files)} hidden files")  # Debugging
        except Exception as e:
            print(f"ERROR: Failed to scan hidden files - {str(e)}")

        print(f"DEBUG: Total files found in all scans: {len(all_files)}")  # Debugging output

        self.refresh_files_list(all_files)
        # # Scan recycle bin
        # scanner = RecoveryScanner(directory)
        # all_files.extend(scanner.scan_directory())
        
        # # Scan backups
        # backup_scanner = BackupScanner(directory)
        # all_files.extend(backup_scanner.scan_for_backups())
        
        # # Scan temp files
        # all_files.extend(self.temp_scanner.scan_temp_files())
        
        # # Scan hidden files
        # hidden_scanner = HiddenFileScanner(directory)
        # all_files.extend(hidden_scanner.scan_hidden_files())
        
        # self.refresh_files_list(all_files)

    def refresh_current_scan_type(self):
        if not self.current_scan_type:
            messagebox.showwarning("Warning", "Please select a recovery method first")
            return
            
        if self.current_scan_type == "recycle_bin":
            self.scan_recycle_bin()
        elif self.current_scan_type == "backup":
            self.scan_backups()
        elif self.current_scan_type == "temp":
            self.scan_temp_files()
        elif self.current_scan_type == "hidden":
            self.scan_hidden_files()
        elif self.current_scan_type == "all":
            self.scan_all()

    def refresh_current_scan(self):
        if self.current_scanner:
            self.tree.delete(*self.tree.get_children())
            self.tree.insert("", tk.END, values=("", "Scanning...", "", "", "", "", ""))
            threading.Thread(target=self.perform_scan, daemon=True).start()
        else:
            messagebox.showwarning("Warning", "Please select a recovery method first")

    def perform_scan(self):
        try:
            files = self.current_scanner.scan_directory()
            self.root.after(0, self.refresh_files_list, files)
        except Exception as e:
            self.root.after(0, self.show_scan_error, str(e))

   
    
    
    # def refresh_files_list(self, files):
    def refresh_files_list(self, files):
        self.files_list = files
        self.tree.delete(*self.tree.get_children())
        self.selected_files = {}  # Reset selection state
        target_directory = self.dir_var.get()  # User-selected directory

        # **Dynamically update column name based on scan type**


        if self.current_scan_type in ["temp", "backup", "hidden"]:
            self.tree.heading("Deletion Date", text="Creation Date")
        else:
            self.tree.heading("Deletion Date", text="Deletion Date")
     
        
        if not files:
        # Show "No files found" message in the tree
            self.tree.insert("", tk.END, values=(
                "",  # Checkbox
                "",  # Index
                "No files found here",  # Name
                "",  # Size
                "",  # Date
                "",  # Type
                ""   # Confidence
            ))
            return
    
        for idx, file in enumerate(files, 1):
            try:
                # Size calculation
                if hasattr(file, 'size') and file.size is not None:
                    # Convert size to appropriate unit
                    if file.size >= 1024 * 1024 * 1024:  # Size in GB
                        size_str = f"{file.size / (1024 * 1024 * 1024):.1f} GB"
                    elif file.size >= 1024 * 1024:  # Size in MB
                        size_str = f"{file.size / (1024 * 1024):.1f} MB"
                    elif file.size >= 1024:  # Size in KB
                        size_str = f"{file.size / 1024:.1f} KB"
                    elif file.size > 0:  # Size in bytes
                        size_str = f"{file.size} bytes"
                    else:
                        size_str = "0 bytes"
                else:
                    # Try to get file size from path for temp and hidden files
                    try:
                        if hasattr(file, 'path') and os.path.exists(file.path):
                            file_size = os.path.getsize(file.path)
                            if file_size >= 1024 * 1024 * 1024:
                                size_str = f"{file_size / (1024 * 1024 * 1024):.1f} GB"
                            elif file_size >= 1024 * 1024:
                                size_str = f"{file_size / (1024 * 1024):.1f} MB"
                            elif file_size >= 1024:
                                size_str = f"{file_size / 1024:.1f} KB"
                            elif file_size > 0:
                                size_str = f"{file_size} bytes"
                            else:
                                size_str = "0 bytes"
                        else:
                            size_str = "Unknown"
                    except (OSError, AttributeError):
                        size_str = "Unknown"
            except (AttributeError, TypeError):
                size_str = "Unknown"

            # Date handling
            modified_str = file.modified.strftime('%Y-%m-%d %H:%M:%S') if hasattr(file, 'modified') and file.modified else "Unknown"
            # created_str = EnhancedRecoveryGUI.get_creation_date('%Y-%m-%d %H:%M:%S') if hasattr(file, 'created') and file.created else "Unknown"
            # created_date = self.get_creation_date(file.path) if hasattr(file, 'path') and os.path.exists(file.path) else None
            # **Fix: Get the actual creation date for applicable files**
            if hasattr(file, 'path') and os.path.exists(file.path):
                created_date = EnhancedRecoveryGUI.get_creation_date(file.path)  # ✅ Correct method call
                created_str = created_date.strftime('%Y-%m-%d %H:%M:%S') if created_date else "Unknown"
            else:
                created_str = "Unknown"
            confidence_str = f"{file.confidence * 100:.1f}%" if hasattr(file, 'confidence') and file.confidence is not None else "N/A"

            # Show correct date based on file type
            if file.recovery_type in ['temp', 'hidden', 'backup']:
                display_date = created_str  # Show Creation Date for non-deleted files
            else:
                display_date = modified_str if modified_str != "Unknown" else "Not deleted yet"  # Use modified date if it's a deleted file

            # Insert the item into the tree
            item_id = self.tree.insert("", tk.END, values=(
                "☐",  # Checkbox (unchecked by default)
                idx,
                file.original_name,
                size_str,
                display_date,
                file.recovery_type,
                confidence_str
            ))
            

            # Initialize selection state for this item
            self.selected_files[item_id] = False

    # Reset select all checkbox
        self.select_all_var.set(False)  # Reset select all checkbox
    def show_scan_error(self, error):
        messagebox.showerror("Scan Error", f"An error occurred: {error}")
        self.tree.delete(*self.tree.get_children())

    def recover_selected(self):
        # Get all selected item IDs
        selected_items = [item_id for item_id, selected in self.selected_files.items() if selected]
        
        if not selected_items:
            messagebox.showwarning("Warning", "Please select files to recover")
            return
        
        dest_dir = filedialog.askdirectory(title="Select Recovery Location")
        if not dest_dir:
            return
        
        self.tree.configure(selectmode="none")
        
        selected_indices = []
        for item_id in selected_items:
            idx = int(self.tree.item(item_id)['values'][1]) - 1  # Get the actual index value (column 1)
            selected_indices.append(idx)
        
        threading.Thread(target=self.perform_multiple_recovery, 
                        args=(selected_indices, dest_dir), 
                        daemon=True).start()

    def perform_multiple_recovery(self, indices, destination):
        total = len(indices)
        successful = 0
        failed = 0
        recycle_bin_files = []  # Keep track of successfully recovered recycle bin files
        
        for idx in indices:
            file_info = self.files_list[idx]
            success, message, original_path = self.recover_file(file_info, destination)
            
            if success:
                successful += 1
                self.update_history(file_info.original_name, True)
                
                # If it's a recycle bin file, add it to the list to handle deletion later
                if file_info.recovery_type == 'recycle_bin':
                    recycle_bin_files.append(original_path)
            else:
                failed += 1
                self.update_history(file_info.original_name, False, message)
        
        # Handle recycle bin deletion after recovery
        if recycle_bin_files and os.name == 'nt':  # Only for Windows
            self.root.after(0, self.ask_delete_from_recycle_bin, recycle_bin_files)
        
        self.root.after(0, self.handle_multiple_recovery_result, successful, failed, total)

    def ask_delete_from_recycle_bin(self, file_paths):
        if messagebox.askyesno("Delete from Recycle Bin", 
                             "Do you want to delete the recovered files from the Recycle Bin?"):
            try:
                for path in file_paths:
                    if os.path.exists(path):
                        os.remove(path)
                messagebox.showinfo("Success", "Files successfully removed from Recycle Bin")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to delete from Recycle Bin: {str(e)}")

    def handle_multiple_recovery_result(self, successful, failed, total):
        self.tree.configure(selectmode="extended")
        messagebox.showinfo("Recovery Complete", 
                          f"Recovery process completed.\n"
                          f"Successfully recovered: {successful} file(s)\n"
                          f"Failed: {failed} file(s)\n"
                          f"Total processed: {total} file(s)")
        self.refresh_current_scan_type()
    
    def recover_file(self, file_info: FileInfo, destination: str) -> tuple:
        try:
            dest_path = os.path.join(destination, file_info.original_name)
            
            if os.path.exists(dest_path):
                base, ext = os.path.splitext(file_info.original_name)
                counter = 1
                while os.path.exists(dest_path):
                    dest_path = os.path.join(destination, f"{base}_recovered_{counter}{ext}")
                    counter += 1
            
            if file_info.recovery_type == 'recycle_bin' and os.name == 'nt':
                with open(file_info.path, 'rb') as source:
                    with open(dest_path, 'wb') as dest:
                        shutil.copyfileobj(source, dest)
            else:
                shutil.copy2(file_info.path, dest_path)
                
            # Remove hidden attribute if it's a hidden file
            if file_info.recovery_type == 'hidden':
                if os.name == 'nt':  # Windows
                    # Remove hidden attribute using Windows API
                    FILE_ATTRIBUTE_NORMAL = 0x80
                    try:
                        ctypes.windll.kernel32.SetFileAttributesW(dest_path, FILE_ATTRIBUTE_NORMAL)
                    except Exception as attr_error:
                        return False, f"File copied but failed to remove hidden attribute: {str(attr_error)}", ""
                else:  # Unix-like systems
                    try:
                        # Remove the dot prefix from filename if it exists
                        if os.path.basename(dest_path).startswith('.'):
                            new_path = os.path.join(
                                os.path.dirname(dest_path),
                                os.path.basename(dest_path)[1:]
                            )
                            os.rename(dest_path, new_path)
                            dest_path = new_path
                    except Exception as rename_error:
                        return False, f"File copied but failed to rename: {str(rename_error)}", ""
                        
            return True, f"Successfully recovered to: {dest_path}", file_info.path  # Return original path for recycle bin deletion
        except Exception as e:
            return False, str(e), ""

    def clear_files_list(self):
        self.tree.delete(*self.tree.get_children())
        self.files_list = []
        self.selected_files = {}
        self.current_scanner = None
        self.current_scan_type = None

    def show_login_frame(self):
        self.clear_window()
        
        frame = ttk.Frame(self.root, padding="20")
        frame.pack(expand=True, fill="both")
        
        title = ttk.Label(frame, text="Enhanced File Recovery System", font=("Helvetica", 24))
        title.pack(pady=20)
        
        ttk.Label(frame, text="Username:").pack(pady=5)
        self.username_entry = ttk.Entry(frame, width=30)
        self.username_entry.pack(pady=5)
        
        ttk.Label(frame, text="Password:").pack(pady=5)
        self.password_entry = ttk.Entry(frame, width=30, show="*")
        self.password_entry.pack(pady=5)
        
        button_frame = ttk.Frame(frame)
        button_frame.pack(pady=20)
        
        ttk.Button(button_frame, text="Login", command=self.login).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Register", command=self.show_register_frame).pack(side=tk.LEFT, padx=5)

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Please fill in all fields")
            return
        
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        
        self.cursor.execute("SELECT * FROM users WHERE username = %s AND password = %s",
                          (username, hashed_password))
        user = self.cursor.fetchone()
        
        if user:
            self.current_user = username
            self.show_directory_selection_frame()  # Show directory selection after login
        else:
            messagebox.showerror("Error", "Invalid credentials")

    def show_register_frame(self):
        self.clear_window()
        
        frame = ttk.Frame(self.root, padding="20")
        frame.pack(expand=True, fill="both")
        
        ttk.Label(frame, text="Register New Account", font=("Helvetica", 24)).pack(pady=20)
        
        ttk.Label(frame, text="Username:").pack(pady=5)
        self.reg_username = ttk.Entry(frame, width=30)
        self.reg_username.pack(pady=5)
        
        ttk.Label(frame, text="Password:").pack(pady=5)
        self.reg_password = ttk.Entry(frame, width=30, show="*")
        self.reg_password.pack(pady=5)
        
        ttk.Label(frame, text="Confirm Password:").pack(pady=5)
        self.reg_confirm = ttk.Entry(frame, width=30, show="*")
        self.reg_confirm.pack(pady=5)
        
        button_frame = ttk.Frame(frame)
        button_frame.pack(pady=20)
        
        ttk.Button(button_frame, text="Register", command=self.register).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Back to Login", command=self.show_login_frame).pack(side=tk.LEFT, padx=5)

    def register(self):
        username = self.reg_username.get()
        password = self.reg_password.get()
        confirm = self.reg_confirm.get()
        
        if not username or not password or not confirm:
            messagebox.showerror("Error", "Please fill in all fields")
            return
        
        if password != confirm:
            messagebox.showerror("Error", "Passwords do not match")
            return
        
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        
        try:
            self.cursor.execute("INSERT INTO users (username, password, recovery_history) VALUES (%s, %s, %s)",
                              (username, hashed_password, json.dumps([])))
            self.conn.commit()
            messagebox.showinfo("Success", "Registration successful!")
            self.show_login_frame()
        except mysql.connector.IntegrityError:
            messagebox.showerror("Error", "Username already exists")

    def show_history(self):
        history_window = tk.Toplevel(self.root)
        history_window.title("Recovery History")
        history_window.geometry("800x500")
        
        frame = ttk.Frame(history_window, padding="20")
        frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(frame, text="Recovery History", font=("Helvetica", 20)).pack(pady=10)
        
        columns = ("File", "Date", "Status", "Details")
        tree = ttk.Treeview(frame, columns=columns, show="headings")
        
        y_scrollbar = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        x_scrollbar = ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=y_scrollbar.set, xscrollcommand=x_scrollbar.set)
        
        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, width=150, minwidth=100)
        
        self.cursor.execute("SELECT recovery_history FROM users WHERE username = %s", (self.current_user,))
        result = self.cursor.fetchone()
        history_json = result[0] if result else None
        
        if history_json:
            history = json.loads(history_json)
            for entry in history:
                tree.insert("", tk.END, values=(
                    entry["file"],
                    entry["date"],
                    entry["status"],
                    entry.get("details", "")
                ))
        
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        y_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        x_scrollbar.pack(side=tk.BOTTOM, fill=tk.X)
        
        export_frame = ttk.Frame(frame)
        export_frame.pack(fill=tk.X, pady=10)
        ttk.Button(export_frame, text="Export History", 
                  command=lambda: self.export_history(history if history_json else [])).pack(side=tk.LEFT, padx=5)
        ttk.Button(export_frame, text="Close", command=history_window.destroy).pack(side=tk.RIGHT, padx=5)

    def export_history(self, history):
        try:
            file_path = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
            )
            if file_path:
                with open(file_path, 'w') as f:
                    json.dump(history, f, indent=4)
                messagebox.showinfo("Success", "History exported successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export history: {str(e)}")

    def update_history(self, filename: str, success: bool, details: str = ""):
        self.cursor.execute("SELECT recovery_history FROM users WHERE username = %s", (self.current_user,))
        result = self.cursor.fetchone()
        history_json = result[0] if result else None
        history = json.loads(history_json) if history_json else []
        
        history.append({
            "file": filename,
            "date": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "status": "Success" if success else "Failed",
            "details": details
        })
        
        self.cursor.execute("UPDATE users SET recovery_history = %s WHERE username = %s",
                          (json.dumps(history), self.current_user))
        self.conn.commit()

    def logout(self):
        if messagebox.askyesno("Confirm Logout", "Are you sure you want to log out?"):
            self.current_user = None
            self.show_login_frame()

    def delete_account(self):
        if messagebox.askyesno("Confirm Delete", "Are you sure you want to delete your account? This action cannot be undone."):
            try:
                self.cursor.execute("DELETE FROM users WHERE username = %s", (self.current_user,))
                self.conn.commit()
                messagebox.showinfo("Success", "Account deleted successfully")
                self.current_user = None
                self.show_login_frame()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to delete account: {str(e)}")

    def clear_window(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def run(self):
        self.root.mainloop()

    def __del__(self):
        try:
            if hasattr(self, 'conn') and self.conn:
                self.conn.close()
        except:
            pass

def main():
    app = EnhancedRecoveryGUI()
    app.run()

if __name__ == "__main__":
    main()