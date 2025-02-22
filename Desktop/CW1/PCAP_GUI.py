import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import mysql.connector
from mysql.connector import Error
import hashlib
import json
import os
import threading
from typing import Optional
from scapy.all import *
from pcap_analyzerr import AdvancedPCAPAnalyzer

class DatabaseManager:
    def __init__(self):
        self.connection = None
        try:
            self.connection = mysql.connector.connect(
                host='localhost',
                user='root',
                password='',
                database='pcap_analyzer'
            )
            self.create_tables()
        except Error as e:
            messagebox.showerror("Database Error", f"Failed to connect to database: {e}")
    
    def create_tables(self):
        cursor = self.connection.cursor()
        # Create users table with user_password column
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(50) UNIQUE NOT NULL,
            user_password VARCHAR(255) NOT NULL,
            email VARCHAR(100) UNIQUE NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        ''')

        # Create analysis_history table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS analysis_historyy (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT,
            pcap_file VARCHAR(255) NOT NULL,
            analysis_date DATETIME DEFAULT CURRENT_TIMESTAMP,
            suspicious_activities INT,
            successful_logins INT,
            file_transfers INT,
            results_json TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        ''')
        
        self.connection.commit()
        cursor.close()

    def register_user(self, username: str, password: str, email: str) -> bool:
        try:
            cursor = self.connection.cursor()
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            
            cursor.execute('''
                INSERT INTO users (username, user_password, email)
                VALUES (%s, %s, %s)
            ''', (username, hashed_password, email))
            
            self.connection.commit()
            cursor.close()
            return True
        except Error as e:
            messagebox.showerror("Registration Error", str(e))
            return False

    def verify_login(self, username: str, password: str) -> Optional[int]:
        try:
            cursor = self.connection.cursor()
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            
            cursor.execute('''
                SELECT id FROM users 
                WHERE username = %s AND user_password = %s
            ''', (username, hashed_password))
            
            result = cursor.fetchone()
            cursor.close()
            return result[0] if result else None
        except Error as e:
            messagebox.showerror("Login Error", str(e))
            return None

    def save_analysis_history(self, user_id: int, analysis_data: dict):
        try:
            cursor = self.connection.cursor()
            cursor.execute('''
                INSERT INTO analysis_historyy 
                (user_id, pcap_file, suspicious_activities, successful_logins, 
                 file_transfers, results_json)
                VALUES (%s, %s, %s, %s, %s, %s)
            ''', (
                user_id,
                analysis_data['pcap_file'],
                analysis_data['suspicious_activities'],
                analysis_data['successful_logins'],
                analysis_data['file_transfers'],
                json.dumps(analysis_data['results'])
            ))
            
            self.connection.commit()
            cursor.close()
        except Error as e:
            messagebox.showerror("History Save Error", str(e))

    def get_user_history(self, user_id: int) -> list:
        try:
            cursor = self.connection.cursor(dictionary=True)
            cursor.execute('''
                SELECT * FROM analysis_historyy
                WHERE user_id = %s 
                ORDER BY analysis_date DESC
            ''', (user_id,))
            
            history = cursor.fetchall()
            cursor.close()
            return history
        except Error as e:
            messagebox.showerror("History Retrieval Error", str(e))
            return []

class LoginWindow(tk.Tk):
    def __init__(self):
        super().__init__()
        
        self.db = DatabaseManager()
        self.title("PCAP Analyzer - Login")
        self.geometry("400x300")
        
        self.create_widgets()
    
    def create_widgets(self):
        # Login Frame
        login_frame = ttk.LabelFrame(self, text="Login", padding="20")
        login_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        ttk.Label(login_frame, text="Username:").pack(fill="x", pady=5)
        self.username_entry = ttk.Entry(login_frame)
        self.username_entry.pack(fill="x", pady=5)
        
        ttk.Label(login_frame, text="Password:").pack(fill="x", pady=5)
        self.password_entry = ttk.Entry(login_frame, show="*")
        self.password_entry.pack(fill="x", pady=5)
        
        ttk.Button(login_frame, text="Login", command=self.login).pack(fill="x", pady=10)
        ttk.Button(login_frame, text="Register", command=self.show_register).pack(fill="x", pady=5)
    
    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        user_id = self.db.verify_login(username, password)
        if user_id:
            self.withdraw()
            MainWindow(user_id, username, self)
        else:
            messagebox.showerror("Login Failed", "Invalid username or password")
    
    def show_register(self):
        RegisterWindow(self)

class RegisterWindow(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        
        self.parent = parent
        self.title("PCAP Analyzer - Register")
        self.geometry("400x350")
        
        self.create_widgets()
    
    def create_widgets(self):
        register_frame = ttk.LabelFrame(self, text="Register", padding="20")
        register_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        ttk.Label(register_frame, text="Username:").pack(fill="x", pady=5)
        self.username_entry = ttk.Entry(register_frame)
        self.username_entry.pack(fill="x", pady=5)
        
        ttk.Label(register_frame, text="Email:").pack(fill="x", pady=5)
        self.email_entry = ttk.Entry(register_frame)
        self.email_entry.pack(fill="x", pady=5)
        
        ttk.Label(register_frame, text="Password:").pack(fill="x", pady=5)
        self.password_entry = ttk.Entry(register_frame, show="*")
        self.password_entry.pack(fill="x", pady=5)
        
        ttk.Label(register_frame, text="Confirm Password:").pack(fill="x", pady=5)
        self.confirm_password_entry = ttk.Entry(register_frame, show="*")
        self.confirm_password_entry.pack(fill="x", pady=5)
        
        ttk.Button(register_frame, text="Register", command=self.register).pack(fill="x", pady=10)
    
    def register(self):
        username = self.username_entry.get()
        email = self.email_entry.get()
        password = self.password_entry.get()
        confirm_password = self.confirm_password_entry.get()
        
        if not all([username, email, password, confirm_password]):
            messagebox.showerror("Error", "All fields are required")
            return
        
        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match")
            return
        
        if self.parent.db.register_user(username, password, email):
            messagebox.showinfo("Success", "Registration successful! You can now login.")
            self.destroy()

class MainWindow(tk.Toplevel):
    def __init__(self, user_id: int, username: str, login_window: LoginWindow):
        super().__init__()
        
        self.user_id = user_id
        self.username = username
        self.login_window = login_window
        self.db = login_window.db
        
        self.title(f"PCAP Analyzer - Welcome {username}")
        self.geometry("800x600")
        self.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        self.create_widgets()
        self.load_history()
    
    def create_widgets(self):
        # Main container
        main_container = ttk.PanedWindow(self, orient=tk.HORIZONTAL)
        main_container.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Left panel - Analysis controls
        left_panel = ttk.LabelFrame(main_container, text="Analysis Controls")
        main_container.add(left_panel, weight=1)
        
        ttk.Button(left_panel, text="Select PCAP File", command=self.select_file).pack(fill="x", padx=5, pady=5)
        ttk.Button(left_panel, text="Start Analysis", command=self.start_analysis).pack(fill="x", padx=5, pady=5)
        
        # Back/Clear button
        ttk.Button(left_panel, text="Clear / Back", command=self.clear_analysis).pack(fill="x", padx=5, pady=5)
        
        # Logout button
        ttk.Button(left_panel, text="Logout", command=self.logout).pack(fill="x", padx=5, pady=5)
        
        self.progress_var = tk.StringVar(value="Ready")
        ttk.Label(left_panel, textvariable=self.progress_var).pack(fill="x", padx=5, pady=5)
        
        self.progress_bar = ttk.Progressbar(left_panel, mode='indeterminate')
        self.progress_bar.pack(fill="x", padx=5, pady=5)
        
        # Right panel - Results and History
        right_panel = ttk.Notebook(main_container)
        main_container.add(right_panel, weight=2)
        
        # Results tab
        self.results_text = tk.Text(right_panel, wrap=tk.WORD)
        right_panel.add(self.results_text, text="Results")
        
        # Configure color tags
        self.results_text.tag_config("header", foreground="blue", font=("Helvetica", 12, "bold"))
        self.results_text.tag_config("suspicious", foreground="red", font=("Helvetica", 10, "bold"))
        self.results_text.tag_config("logins", foreground="green", font=("Helvetica", 10, "bold"))
        self.results_text.tag_config("transfers", foreground="purple", font=("Helvetica", 10, "bold"))
        
        # History tab
        self.history_tree = ttk.Treeview(right_panel, columns=("Date", "File", "Activities", "Logins", "Transfers"), show='headings')
        right_panel.add(self.history_tree, text="History")
        
        self.history_tree.heading("Date", text="Date")
        self.history_tree.heading("File", text="File")
        self.history_tree.heading("Activities", text="Suspicious Activities")
        self.history_tree.heading("Logins", text="Successful Logins")
        self.history_tree.heading("Transfers", text="File Transfers")
        
        for col in ("Date", "File", "Activities", "Logins", "Transfers"):
            self.history_tree.column(col, width=120)

    def select_file(self):
        self.pcap_file = filedialog.askopenfilename(
            filetypes=[("PCAP files", "*.pcap *.pcapng"), ("All files", "*.*")]
        )
        if self.pcap_file:
            self.progress_var.set(f"Selected file: {os.path.basename(self.pcap_file)}")
    
    def start_analysis(self):
        if not hasattr(self, 'pcap_file') or not self.pcap_file:
            messagebox.showerror("Error", "Please select a PCAP file first")
            return
        
        self.progress_bar.start()
        self.progress_var.set("Analysis in progress...")
        
        # Create analysis thread
        analysis_thread = threading.Thread(target=self.run_analysis)
        analysis_thread.start()
    
    def run_analysis(self):
        try:
            analyzer = AdvancedPCAPAnalyzer(self.pcap_file)
            analyzer.analyze()
            
            # Prepare results
            results = {
                'pcap_file': os.path.basename(self.pcap_file),
                'suspicious_activities': len(analyzer.suspicious_activities),
                'successful_logins': len(analyzer.successful_logins),
                'file_transfers': len(analyzer.file_transfers),
                'results': {
                    'suspicious_activities': analyzer.suspicious_activities,
                    'successful_logins': analyzer.successful_logins,
                    'file_transfers': analyzer.file_transfers
                }
            }
            
            # Save to database
            self.db.save_analysis_history(self.user_id, results)
            
            # Update GUI
            self.after(0, self.update_results, results)
            self.after(0, self.load_history)
            
        except Exception as e:
            self.after(0, messagebox.showerror, "Analysis Error", str(e))
        finally:
            self.after(0, self.progress_bar.stop)
            self.after(0, self.progress_var.set, "Analysis complete")
    
    def update_results(self, results):
        """Display the analysis results in color-coded format."""
        self.results_text.delete(1.0, tk.END)
        
        # Title
        self.results_text.insert(tk.END, f"Analysis Results for {results['pcap_file']}\n\n", "header")
        
        # Summary lines
        self.results_text.insert(tk.END, f"Suspicious Activities: {results['suspicious_activities']}\n", "suspicious")
        self.results_text.insert(tk.END, f"Successful Logins: {results['successful_logins']}\n", "logins")
        self.results_text.insert(tk.END, f"File Transfers: {results['file_transfers']}\n\n", "transfers")
        
        # Detailed output
        self.color_print_json(results['results'])
    
    def color_print_json(self, data):
        """
        Print suspicious_activities, successful_logins, and file_transfers
        in color-coded lines for better readability.
        """
        susp = data.get("suspicious_activities", [])
        logs = data.get("successful_logins", [])
        trans = data.get("file_transfers", [])
        
        # Suspicious Activities
        if susp:
            self.results_text.insert(tk.END, "\nDetailed Suspicious Activities:\n", "suspicious")
            for i, activity in enumerate(susp, 1):
                line = (f"[{i}] Packet: {activity.get('packet_number')} "
                        f"Command: {activity.get('type')} "
                        f"From: {activity.get('src_ip')} "
                        f"To: {activity.get('dst_ip')}\n")
                self.results_text.insert(tk.END, line, "suspicious")
        
        # Successful Logins
        if logs:
            self.results_text.insert(tk.END, "\nDetailed Successful Logins:\n", "logins")
            for i, login in enumerate(logs, 1):
                line = (f"[{i}] Packet: {login.get('packet_number')} "
                        f"Protocol: {login.get('protocol')} "
                        f"Username: {login.get('username')} "
                        f"Password: {login.get('password')} "
                        f"From: {login.get('src_ip')} "
                        f"To: {login.get('dst_ip')}\n")
                self.results_text.insert(tk.END, line, "logins")
        
        # File Transfers
        if trans:
            self.results_text.insert(tk.END, "\nDetailed File Transfers:\n", "transfers")
            for i, ftransfer in enumerate(trans, 1):
                line = (f"[{i}] Packet: {ftransfer.get('packet_number')} "
                        f"File: {ftransfer.get('filename')} "
                        f"From: {ftransfer.get('src_ip')} "
                        f"To: {ftransfer.get('dst_ip')}\n")
                self.results_text.insert(tk.END, line, "transfers")
    
    def load_history(self):  
        # Clear existing items
        for item in self.history_tree.get_children():
            self.history_tree.delete(item)
        
        # Load history from database
        history = self.db.get_user_history(self.user_id)
        
        # Add to treeview
        for entry in history:
            self.history_tree.insert("", 0, values=(
                entry['analysis_date'],
                entry['pcap_file'],
                entry['suspicious_activities'],
                entry['successful_logins'],
                entry['file_transfers']
            ))
    
    def clear_analysis(self):
        """Clears the current analysis state and results."""
        # Remove any reference to the selected file
        if hasattr(self, 'pcap_file'):
            del self.pcap_file
        
        # Clear progress indicators
        self.progress_bar.stop()
        self.progress_var.set("Ready")
        
        # Clear the results text
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, "Ready for a new analysis.\n", "header")
    
    def logout(self):
        """Logs out the current user after confirmation."""
        answer = messagebox.askyesno("Logout", "Are you sure you want to logout?")
        if answer:
            self.login_window.deiconify()  # Show the login window again
            self.destroy()                 # Close the main window
    
    def on_closing(self):
        """Handle the window close event (top-right X)."""
        self.login_window.destroy()

if __name__ == "__main__":
    app = LoginWindow()
    app.mainloop()