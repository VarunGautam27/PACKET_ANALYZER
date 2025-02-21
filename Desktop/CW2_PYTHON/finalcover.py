import os
import glob
from colorama import init, Fore, Style
import shutil
from datetime import datetime
from typing import List, Dict, Any
import struct

# Initialize colorama
init()

class FileInfo:
    def __init__(self, path: str, size: int, modified: datetime, original_name: str, original_path: str):
        self.path = path
        self.size = size
        self.modified = modified
        self.original_name = original_name
        self.original_path = original_path

class RecoveryScanner:
    def __init__(self, base_directory: str):
        self.base_directory = os.path.abspath(base_directory)
        self.recycle_bins = self._get_all_recycle_bins()
        
    def _get_all_recycle_bins(self) -> List[str]:
        """Get all possible Recycle Bin locations"""
        recycle_bins = []
        if os.name == 'nt':  # Windows
            drive = os.path.splitdrive(self.base_directory)[0]
            recycle_bin_base = os.path.join(drive + os.sep, '$Recycle.Bin')
            
            if os.path.exists(recycle_bin_base):
                try:
                    for sid_folder in os.listdir(recycle_bin_base):
                        full_path = os.path.join(recycle_bin_base, sid_folder)
                        if os.path.isdir(full_path):
                            recycle_bins.append(full_path)
                except:
                    pass
                    
        return recycle_bins

    def _parse_recyclebin_i_file(self, i_file_path: str) -> tuple:
        """Parse the $I file to get original filename and path"""
        try:
            with open(i_file_path, 'rb') as f:
                f.seek(8)
                file_size = struct.unpack('Q', f.read(8))[0]
                del_time = struct.unpack('Q', f.read(8))[0]
                name_length = struct.unpack('I', f.read(4))[0]
                original_path = f.read(name_length * 2).decode('utf-16').split('\x00', 1)[0]
                return original_path, file_size, datetime.fromtimestamp(del_time / 10000000 - 11644473600)
        except:
            return None, 0, datetime.now()

    def _is_file_from_target_directory(self, original_path: str) -> bool:
        try:
            normalized_path = os.path.normpath(original_path).lower()
            normalized_base = os.path.normpath(self.base_directory).lower()
            return normalized_path.startswith(normalized_base)
        except:
            return False

    def scan_directory(self) -> List[FileInfo]:
        deleted_files = []
        
        for recycle_bin in self.recycle_bins:
            try:
                for root, _, filenames in os.walk(recycle_bin):
                    for filename in filenames:
                        if filename.startswith('$I'):
                            try:
                                i_file_path = os.path.join(root, filename)
                                r_file_path = os.path.join(root, '$R' + filename[2:])
                                
                                if os.path.exists(r_file_path):
                                    original_path, file_size, del_time = self._parse_recyclebin_i_file(i_file_path)
                                    
                                    if original_path and self._is_file_from_target_directory(original_path):
                                        stats = os.stat(r_file_path)
                                        file_info = FileInfo(
                                            path=r_file_path,
                                            size=stats.st_size,
                                            modified=del_time,
                                            original_name=os.path.basename(original_path),
                                            original_path=original_path
                                        )
                                        deleted_files.append(file_info)
                            except:
                                continue
            except Exception as e:
                print(f"{Fore.RED}Error scanning Recycle Bin {recycle_bin}: {str(e)}{Style.RESET_ALL}")

        deleted_files.sort(key=lambda x: x.modified, reverse=True)
        return deleted_files

class FileRecoveryTool:
    def __init__(self):
        self.scanner = None
        self.files = []
        self.files_per_page = 10
        self.current_page = 0
        self.valid_choices = ['n', 'p', 'r', 'q']

    def print_banner(self):
        print(f"\n{Fore.CYAN}═══════════════════════════════════════")
        print(f"{Fore.YELLOW}    Deleted Files Recovery Tool")
        print(f"{Fore.CYAN}═══════════════════════════════════════{Style.RESET_ALL}\n")

    def get_scan_directory(self) -> str:
        while True:
            print(f"{Fore.GREEN}Enter the directory path to scan for deleted files:")
            directory = input(f"{Fore.WHITE}> {Style.RESET_ALL}").strip()
            
            if not directory:
                print(f"{Fore.RED}Error: Please enter a directory path.{Style.RESET_ALL}")
                continue
                
            if os.path.exists(directory):
                return directory
            print(f"{Fore.RED}Error: Directory not found. Please enter a valid path.{Style.RESET_ALL}")

    def clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')

    def display_files(self, files: List[FileInfo]):
        if not files:
            print(f"{Fore.YELLOW}No deleted files found from the specified directory.{Style.RESET_ALL}")
            return

        total_pages = (len(files) + self.files_per_page - 1) // self.files_per_page
        
        while True:
            self.clear_screen()
            self.print_banner()
            
            start_idx = self.current_page * self.files_per_page
            end_idx = min(start_idx + self.files_per_page, len(files))
            current_files = files[start_idx:end_idx]
            
            print(f"\n{Fore.CYAN}Scanning for deleted files from: {self.scanner.base_directory}{Style.RESET_ALL}")
            print(f"\n{Fore.GREEN}Found {len(files)} deleted files. Showing {start_idx + 1}-{end_idx} (Page {self.current_page + 1} of {total_pages}){Style.RESET_ALL}")
            print(f"\n{Fore.CYAN}{'Index':<6} {'Original Name':<30} {'Size':<10} {'Deletion Date':<20}{Style.RESET_ALL}")
            print("─" * 100)
            
            for idx, file in enumerate(current_files, start_idx + 1):
                size_str = f"{file.size / 1024:.1f} KB"
                modified_str = file.modified.strftime('%Y-%m-%d %H:%M:%S')
                print(f"{idx:<6} {file.original_name[:30]:<30} {size_str:<10} {modified_str}")

            print(f"\n{Fore.CYAN}Options: {Style.RESET_ALL}")
            print(f"'n' - Next page")
            print(f"'p' - Previous page")
            print(f"'r' - Recover a file")
            print(f"'q' - Quit")
            
            while True:
                choice = input(f"\n{Fore.GREEN}Enter your choice: {Style.RESET_ALL}").strip().lower()
                
                if choice not in self.valid_choices:
                    print(f"{Fore.RED}Invalid choice. Please enter one of: {', '.join(self.valid_choices)}{Style.RESET_ALL}")
                    continue
                
                if choice == 'n' and self.current_page >= total_pages - 1:
                    print(f"{Fore.RED}Already on the last page.{Style.RESET_ALL}")
                    continue
                elif choice == 'p' and self.current_page <= 0:
                    print(f"{Fore.RED}Already on the first page.{Style.RESET_ALL}")
                    continue
                break
            
            if choice == 'n':
                self.current_page += 1
            elif choice == 'p':
                self.current_page -= 1
            elif choice == 'r':
                self.handle_recovery(files)
            elif choice == 'q':
                break

    def handle_recovery(self, files: List[FileInfo]):
        while True:
            print(f"\n{Fore.GREEN}Enter the index number of the file you want to recover (or 'b' to go back):")
            choice = input(f"{Fore.WHITE}> {Style.RESET_ALL}").strip().lower()
            
            if choice == 'b':
                break
            
            if not choice.isdigit():
                print(f"{Fore.RED}Invalid input. Please enter a number or 'b' to go back.{Style.RESET_ALL}")
                continue
                
            idx = int(choice) - 1
            if not (0 <= idx < len(files)):
                print(f"{Fore.RED}Invalid index number. Please enter a number between 1 and {len(files)}.{Style.RESET_ALL}")
                continue
                
            print(f"\n{Fore.YELLOW}Original file: {files[idx].original_path}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}Enter the destination directory for recovery:")
            
            while True:
                dest_dir = input(f"{Fore.WHITE}> {Style.RESET_ALL}").strip()
                
                if not dest_dir:
                    print(f"{Fore.RED}Error: Please enter a destination directory.{Style.RESET_ALL}")
                    continue
                    
                if not os.path.exists(dest_dir):
                    print(f"{Fore.RED}Error: Destination directory not found. Please enter a valid path.{Style.RESET_ALL}")
                    continue
                    
                break
            
            if self.recover_file(files[idx], dest_dir):
                files.pop(idx)  # Remove recovered file from the list
            
            input(f"\n{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")
            break

    def recover_file(self, file_info: FileInfo, destination: str) -> bool:
        try:
            source_path = file_info.path
            i_file_path = source_path.replace('$R', '$I')
            dest_path = os.path.join(destination, file_info.original_name)
            
            if os.path.exists(dest_path):
                base, ext = os.path.splitext(file_info.original_name)
                counter = 1
                while os.path.exists(dest_path):
                    dest_path = os.path.join(destination, f"{base}_recovered_{counter}{ext}")
                    counter += 1
            
            print(f"\n{Fore.YELLOW}Attempting to recover: {file_info.original_name}{Style.RESET_ALL}")
            
            # Read and write the file in binary mode to preserve encoding
            with open(source_path, 'rb') as source:
                with open(dest_path, 'wb') as dest:
                    shutil.copyfileobj(source, dest)
            
            # Remove files from recycle bin
            try:
                os.remove(source_path)  # Remove $R file
                os.remove(i_file_path)  # Remove $I file
                print(f"{Fore.GREEN}Successfully removed files from Recycle Bin{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.YELLOW}Warning: Could not remove files from Recycle Bin: {str(e)}{Style.RESET_ALL}")
            
            print(f"{Fore.GREEN}Successfully recovered file to: {dest_path}{Style.RESET_ALL}")
            return True
            
        except Exception as e:
            print(f"{Fore.RED}Error during recovery: {str(e)}{Style.RESET_ALL}")
            return False

    def run(self):
        self.print_banner()
        scan_dir = self.get_scan_directory()
        self.scanner = RecoveryScanner(scan_dir)
        
        print(f"\n{Fore.YELLOW}Scanning for deleted files... Please wait.{Style.RESET_ALL}")
        self.files = self.scanner.scan_directory()
        
        self.display_files(self.files)
        
        print(f"\n{Fore.CYAN}Thank you for using the Deleted Files Recovery Tool!{Style.RESET_ALL}")

def main():
    tool = FileRecoveryTool()
    tool.run()

if __name__ == "__main__":
    main()

    