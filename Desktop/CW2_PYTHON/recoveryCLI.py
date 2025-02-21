import os
import glob
from colorama import init, Fore, Style
import shutil
from datetime import datetime, timedelta
from typing import List, Optional
import struct
import fnmatch
import re
import tempfile
import ctypes
import win32con
import win32api


init()

class FileInfo:
    def __init__(self, path: str, size: int, modified: datetime, original_name: str, 
                 original_path: str, recovery_type: str, confidence: float = 1.0):
        self.path = path
        self.size = size
        self.modified = modified
        self.original_name = original_name
        self.original_path = original_path
        self.recovery_type = recovery_type
        self.confidence = confidence

class RecoveryScanner:
    """Scanner for finding files in the recycle bin"""
    
    def __init__(self, base_directory: str):
        self.base_directory = os.path.abspath(base_directory)
        self.recycle_bins = self._get_all_recycle_bins()
    
    def _get_all_recycle_bins(self) -> List[str]:
        """Get all possible Recycle Bin locations"""
        recycle_bins = []
        if os.name == 'nt':  # Windows
            drives = []
            for drive_letter in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
                drive = f"{drive_letter}:"
                if os.path.exists(drive):
                    drives.append(drive)
            
            for drive in drives:
                recycle_bin_base = os.path.join(drive + os.sep, '$Recycle.Bin')
                if os.path.exists(recycle_bin_base):
                    try:
                        for sid_folder in os.listdir(recycle_bin_base):
                            full_path = os.path.join(recycle_bin_base, sid_folder)
                            if os.path.isdir(full_path):
                                recycle_bins.append(full_path)
                    except PermissionError:
                        print(f"{Fore.YELLOW}Warning: Permission denied for {recycle_bin_base}. Try running as administrator.{Style.RESET_ALL}")
                    except Exception as e:
                        print(f"{Fore.YELLOW}Warning: Error accessing {recycle_bin_base}: {str(e)}{Style.RESET_ALL}")
        else:
            # Linux and macOS Trash locations
            trash_locations = [
                os.path.expanduser('~/.local/share/Trash/files'),  # Linux
                os.path.expanduser('~/.Trash')  # macOS
            ]
            for location in trash_locations:
                if os.path.exists(location):
                    recycle_bins.append(location)
        
        return recycle_bins

    def _parse_recyclebin_i_file(self, i_file_path: str) -> tuple:
        """Parse the $I file to get original filename and path"""
        try:
            with open(i_file_path, 'rb') as f:
                header = f.read(24)
                if len(header) < 24:
                    return None, 0, datetime.now()
                
                # Parse header
                version = struct.unpack('<I', header[:4])[0]
                file_size = struct.unpack('<Q', header[8:16])[0]  # 64-bit size (8 bytes)
                filetime = struct.unpack('<Q', header[16:24])[0]  # 64-bit FILETIME
                del_time = self._parse_filetime(filetime)
                
                # Read name length (DWORD at offset 24)
                name_length_bytes = f.read(4)
                if len(name_length_bytes) < 4:
                    return None, 0, datetime.now()
                name_length = struct.unpack('<I', name_length_bytes)[0]
                
                # Read UTF-16LE filename
                name_bytes = f.read(name_length * 2)  # UTF-16LE uses 2 bytes per character
                if len(name_bytes) != name_length * 2:
                    return None, 0, datetime.now()
                
                try:
                    original_path = name_bytes.decode('utf-16le', errors='replace').strip('\x00')
                except UnicodeDecodeError:
                    original_path = name_bytes.decode('utf-8', errors='replace').strip('\x00')
                
                return original_path, file_size, del_time
        except Exception as e:
            print(f"{Fore.YELLOW}Warning: Error parsing $I file {i_file_path}: {str(e)}{Style.RESET_ALL}")
            return None, 0, datetime.now()

    def _parse_filetime(self, ft: int) -> datetime:
        """Convert Windows FILETIME to datetime"""
        EPOCH_AS_FILETIME = 116444736000000000
        HUNDREDS_OF_NANOSECONDS = 10000000
        
        try:
            return datetime.utcfromtimestamp(
                (ft - EPOCH_AS_FILETIME) / HUNDREDS_OF_NANOSECONDS
            )
        except (ValueError, OSError):
            return datetime.now()

    def _is_file_from_target_directory(self, original_path: str) -> bool:
        """Check if the original file was from the target directory"""
        try:
            normalized_path = os.path.normpath(original_path).lower()
            normalized_base = os.path.normpath(self.base_directory).lower()
            return normalized_path.startswith(normalized_base)
        except:
            return False

    def scan_directory(self) -> List[FileInfo]:
        deleted_files = []
        
        for recycle_bin in self.recycle_bins:
            print(f"{Fore.CYAN}Scanning Recycle Bin location: {recycle_bin}{Style.RESET_ALL}")
            for root, _, filenames in os.walk(recycle_bin):
                for filename in filenames:
                    if os.name == 'nt' and filename.startswith('$I'):
                        try:
                            i_file_path = os.path.join(root, filename)
                            r_file_name = '$R' + filename[2:]
                            r_file_path = os.path.join(root, r_file_name)
                            
                            if os.path.exists(r_file_path):
                                original_path, file_size, del_time = self._parse_recyclebin_i_file(i_file_path)
                                
                                if original_path:
                                    # Only filter by target directory if we can parse the original path
                                    if not self.base_directory or self._is_file_from_target_directory(original_path):
                                        stats = os.stat(r_file_path)
                                        file_info = FileInfo(
                                            path=r_file_path,
                                            size=stats.st_size if file_size == 0 else file_size,
                                            modified=del_time,
                                            original_name=os.path.basename(original_path),
                                            original_path=original_path,
                                            recovery_type='recycle_bin',
                                            confidence=1.0
                                        )
                                        deleted_files.append(file_info)
                                        print(f"{Fore.GREEN}Found deleted file: {original_path}{Style.RESET_ALL}")
                        except Exception as e:
                            print(f"{Fore.YELLOW}Warning: Error processing file {filename}: {str(e)}{Style.RESET_ALL}")
                    elif os.name != 'nt':
                        # For Unix-like systems, just list all files in Trash directory
                        try:
                            full_path = os.path.join(root, filename)
                            stats = os.stat(full_path)
                            file_info = FileInfo(
                                path=full_path,
                                size=stats.st_size,
                                modified=datetime.fromtimestamp(stats.st_mtime),
                                original_name=filename,
                                original_path="Unknown (Trash)",
                                recovery_type='recycle_bin',
                                confidence=1.0
                            )
                            deleted_files.append(file_info)
                        except Exception as e:
                            print(f"{Fore.YELLOW}Warning: Error processing trash file {filename}: {str(e)}{Style.RESET_ALL}")

        if not deleted_files:
            print(f"{Fore.YELLOW}No deleted files found in Recycle Bin.{Style.RESET_ALL}")
                
        deleted_files.sort(key=lambda x: x.modified, reverse=True)
        return deleted_files

class BackupScanner:
    """Scanner for finding backup files"""
    
    def __init__(self, base_directory: str):
        self.base_directory = base_directory
        self.backup_patterns = [
            '*.bak', '*.backup', '~*', '*.old',
             '*.swp', '*.swo',
            '*.autosave', '*.auto', '*Copy*',
            'Backup of *', '* - Copy*', '*.save'
        ]

    def scan_for_backups(self) -> List[FileInfo]:
        backup_files = []
        
        for root, _, files in os.walk(self.base_directory):
            for pattern in self.backup_patterns:
                for filename in fnmatch.filter(files, pattern):
                    try:
                        full_path = os.path.join(root, filename)
                        stats = os.stat(full_path)
                        
                        original_name = self._get_original_name(filename)
                        
                        file_info = FileInfo(
                            path=full_path,
                            size=stats.st_size,
                            modified=datetime.fromtimestamp(stats.st_mtime),
                            original_name=original_name,
                            original_path=os.path.join(root, original_name),
                            recovery_type='backup',
                            confidence=0.9
                        )
                        backup_files.append(file_info)
                    except Exception:
                        continue
                        
        return backup_files

    def _get_original_name(self, backup_name: str) -> str:
        name = backup_name
        patterns = [
            (r'\.bak$', ''),
            (r'\.backup$', ''),
            (r'\.old$', ''),
            # (r'\.tmp$', ''),
            # (r'\.temp$', ''),
            (r'\.swp$', ''),
            (r'\.swo$', ''),
            (r'\.autosave$', ''),
            (r'\.auto$', ''),
            (r'\.save$', ''),
            (r'~', ''),
            (r' - Copy.*(\.\w+)$', r'\1'),
            (r' \(\d+\)(\.\w+)$', r'\1')
        ]
        
        for pattern, replacement in patterns:
            name = re.sub(pattern, replacement, name)
        
        return name

class TempFileScanner:
    """Scanner for finding temporary and autosave files"""
    
    # def __init__(self, custom_directory: Optional[str] = None):
    #     """Initialize with system temp directories and optionally a user-defined directory"""
    #     self.temp_dirs = [
    #         tempfile.gettempdir(),  # Default temp directory
    #         os.path.expanduser('~/AppData/Local/Temp') if os.name == 'nt' else None,
    #         os.path.expanduser('~/AppData/LocalLow/Temp') if os.name == 'nt' else None,
    #         os.path.expanduser('~/AppData/Roaming/Temp') if os.name == 'nt' else None,
    #         'C:\\Windows\\Temp' if os.name == 'nt' else None,  # Windows system temp
    #         os.path.expanduser('~/Library/Caches') if os.name == 'darwin' else None,
    #         '/tmp' if os.name != 'nt' else None,
    #         os.path.expanduser('~/.cache') if os.name != 'nt' else None,
    #     ]

    #     # If user provides a directory, include it in the scan
    #     if custom_directory and os.path.exists(custom_directory):
    #         self.temp_dirs.append(custom_directory)
    #     self.temp_dirs = [d for d in self.temp_dirs if d and os.path.exists(d)]
        
    #     self.autosave_patterns = [
    #         '*~*.tmp', '*.autosave*', '*.auto', 
    #         'Document*.asd', '*.wbk', '*.xlk',
    #         '~$*.*'
    #     ]

    # def scan_temp_files(self) -> List[FileInfo]:
    #     temp_files = []
        
    #     for temp_dir in self.temp_dirs:
    #         if os.path.exists(temp_dir):
    #             for pattern in self.autosave_patterns:
    #                 try:
    #                     for filepath in glob.glob(os.path.join(temp_dir, '**', pattern), recursive=True):
    #                         try:
    #                             stats = os.stat(filepath)
    #                             if datetime.fromtimestamp(stats.st_mtime) > datetime.now() - timedelta(days=1):
    #                                 file_info = FileInfo(
    #                                     path=filepath,
    #                                     size=stats.st_size,
    #                                     modified=datetime.fromtimestamp(stats.st_mtime),
    #                                     original_name=self._get_original_name(os.path.basename(filepath)),
    #                                     original_path=filepath,
    #                                     recovery_type='temp',
    #                                     confidence=0.7
    #                                 )
    #                                 temp_files.append(file_info)
    #                         except Exception:
    #                             continue
    #                 except Exception:
    #                     continue
    def __init__(self, custom_directory: Optional[str] = None):
        """Initialize with system temp directories and optionally a user-defined directory"""
        self.temp_dirs = [
            tempfile.gettempdir(),  # Default temp directory
            os.path.expanduser('~/AppData/Local/Temp') if os.name == 'nt' else None,
            os.path.expanduser('~/AppData/LocalLow/Temp') if os.name == 'nt' else None,
            os.path.expanduser('~/AppData/Roaming/Temp') if os.name == 'nt' else None,
            'C:\\Windows\\Temp' if os.name == 'nt' else None,  # Windows system temp
            os.path.expanduser('~/Library/Caches') if os.name == 'darwin' else None,
            '/tmp' if os.name != 'nt' else None,
            os.path.expanduser('~/.cache') if os.name != 'nt' else None,
        ]

        # If the user provides a custom directory, include it in the scan
        if custom_directory and os.path.exists(custom_directory):
            self.temp_dirs.append(custom_directory)

        self.temp_dirs = [d for d in self.temp_dirs if d and os.path.exists(d)]

        self.autosave_patterns = [
            '*.tmp', '*.temp', '*~*', '*.autosave*', '*.auto',
            'Document*.asd', '*.wbk', '*.xlk',
            '~$*.*'
        ]

    def scan_temp_files(self) -> List[FileInfo]:
        """Scan temp files in system temp folders and user-defined directories"""
        temp_files = []

        for temp_dir in self.temp_dirs:
            if os.path.exists(temp_dir):
                print(f"Scanning directory: {temp_dir}")  # Debugging output
                for pattern in self.autosave_patterns:
                    try:
                        for filepath in glob.glob(os.path.join(temp_dir, '**', pattern), recursive=True):
                            try:
                                stats = os.stat(filepath)
                                file_age = datetime.now() - datetime.fromtimestamp(stats.st_mtime)

                                # Check for files modified in the last 7 days
                                if file_age < timedelta(days=2):
                                    file_info = FileInfo(
                                        path=filepath,
                                        size=stats.st_size,
                                        modified=datetime.fromtimestamp(stats.st_mtime),
                                        original_name=os.path.basename(filepath),
                                        original_path=filepath,
                                        recovery_type='temp',
                                        confidence=0.7
                                    )
                                    temp_files.append(file_info)
                            except Exception as e:
                                print(f"Error reading file: {filepath}, Error: {e}")  # Debugging output
                                continue
                    except Exception as e:
                        print(f"Error scanning pattern {pattern} in {temp_dir}: {e}")  # Debugging output
                        continue

        if not temp_files:
            print(f"{Fore.YELLOW}No temporary files found.{Style.RESET_ALL}")

        return temp_files                     
        

    def _get_original_name(self, temp_name: str) -> str:
        name = temp_name
        patterns = [
            (r'~\$', ''),
            (r'\.temp$', ''),
            (r'\.tmp$', ''),
            (r'\.autosave\d*', ''),
            (r'\.auto$', ''),
            (r'\.wbk$', '.docx'),
            (r'\.xlk$', '.xlsx')
        ]
        
        for pattern, replacement in patterns:
            name = re.sub(pattern, replacement, name)
            
        return name

class HiddenFileScanner:
    """Scanner for finding hidden files"""
    
    def __init__(self, base_directory: str):
        self.base_directory = base_directory

    def scan_hidden_files(self) -> List[FileInfo]:
        hidden_files = []
        
        for root, _, files in os.walk(self.base_directory):
            for filename in files:
                try:
                    full_path = os.path.join(root, filename)
                    if self._is_hidden(full_path):
                        stats = os.stat(full_path)
                        file_info = FileInfo(
                            path=full_path,
                            size=stats.st_size,
                            modified=datetime.fromtimestamp(stats.st_mtime),
                            original_name=filename,
                            original_path=full_path,
                            recovery_type='hidden',
                            confidence=1.0
                        )
                        hidden_files.append(file_info)
                except Exception:
                    continue
                    
        return hidden_files

    def _is_hidden(self, filepath: str) -> bool:
        try:
            name = os.path.basename(filepath)
            if os.name == 'nt':
                import win32api
                import win32con
                try:
                    attributes = win32api.GetFileAttributes(filepath)
                    return bool(attributes & win32con.FILE_ATTRIBUTE_HIDDEN)
                except:
                    return name.startswith('.')
            return name.startswith('.')
        except Exception:
            return False
    def _get_visible_name(self, filename: str) -> str:
        """Remove hidden file indicators from the filename"""
        if filename.startswith('.'):
            return filename[1:]
        return filename

class FileRecoveryTool:
    """Base class for file recovery tools"""
    
    def __init__(self):
        self.scanner = None
        self.files = []

    def print_banner(self):
        print(f"\n{Fore.CYAN}===============================")
        print("Enhanced File Recovery Tool")
        print(f"==============================={Style.RESET_ALL}")
        print(f"==============================={Style.RESET_ALL}")

    def get_scan_directory(self) -> str:
        while True:
            scan_dir = input(f"\n{Fore.WHITE}Enter directory to scan (or 'all' for entire system): {Style.RESET_ALL}").strip()
            if scan_dir.lower() == 'all':
                return ''  # Empty string to scan all
            if os.path.exists(scan_dir) and os.path.isdir(scan_dir):
                return os.path.abspath(scan_dir)
            print(f"{Fore.RED}Invalid directory. Please enter a valid path.{Style.RESET_ALL}")

    def display_files(self, files: List[FileInfo]):
        if not files:
            print(f"{Fore.YELLOW}No files found.{Style.RESET_ALL}")
            return

        print(f"\n{Fore.GREEN}Found {len(files)} file(s):{Style.RESET_ALL}")
        for i, file in enumerate(files, 1):
            print(f"\n{Fore.CYAN}[{i}] {file.original_name}{Style.RESET_ALL}")
            print(f"    Path: {file.path}")
            print(f"    Size: {file.size:,} bytes")
            print(f"    Modified: {file.modified}")
            print(f"    Recovery Type: {file.recovery_type}")
            print(f"    Confidence: {file.confidence * 100:.1f}%")

        while True:
            choice = input(f"\n{Fore.WHITE}Enter file number to recover (or 'b' to go back): {Style.RESET_ALL}").strip().lower()
            if choice == 'b':
                break
                
            try:
                file_index = int(choice) - 1
                if 0 <= file_index < len(files):
                    dest_dir = input(f"\n{Fore.WHITE}Enter destination directory: {Style.RESET_ALL}").strip()
                    if os.path.exists(dest_dir) and os.path.isdir(dest_dir):
                        self.recover_file(files[file_index], dest_dir)
                    else:
                        print(f"{Fore.RED}Invalid destination directory.{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}Invalid file number.{Style.RESET_ALL}")
            except ValueError:
                print(f"{Fore.RED}Please enter a valid number.{Style.RESET_ALL}")

class EnhancedFileRecoveryTool(FileRecoveryTool):
    def __init__(self):
        super().__init__()
        self.backup_scanner = None
        self.temp_scanner = TempFileScanner()
        self.hidden_scanner = None
        self.recovery_modes = {
            '1': ('Deleted Files Recovery', self._recover_from_recycle_bin),
            '2': ('Backup File Recovery', self._recover_from_backups),
            '3': ('Temporary File Recovery', self._recover_from_temp),
            '4': ('Hidden File Recovery', self._recover_hidden_files),
            '5': ('All Recovery Methods', self._recover_all)
        }

    def _recover_from_recycle_bin(self) -> List[FileInfo]:
        return self.scanner.scan_directory()

    def _recover_from_backups(self) -> List[FileInfo]:
        return self.backup_scanner.scan_for_backups()

    def _recover_from_temp(self) -> List[FileInfo]:
        return self.temp_scanner.scan_temp_files()

    def _recover_hidden_files(self) -> List[FileInfo]:
        return self.hidden_scanner.scan_hidden_files()

    def _recover_all(self) -> List[FileInfo]:
        all_files = []
        all_files.extend(self._recover_from_recycle_bin())
        all_files.extend(self._recover_from_backups())
        all_files.extend(self._recover_from_temp())
        all_files.extend(self._recover_hidden_files())
        return all_files

    def recover_file(self, file_info: FileInfo, destination: str) -> bool:
        try:
            dest_path = os.path.join(destination, file_info.original_name)
            
            # Handle filename conflicts
            if os.path.exists(dest_path):
                base, ext = os.path.splitext(file_info.original_name)
                counter = 1
                while os.path.exists(dest_path):
                    dest_path = os.path.join(destination, f"{base}_recovered_{counter}{ext}")
                    counter += 1
            
            print(f"\n{Fore.YELLOW}Attempting to recover: {file_info.original_name}{Style.RESET_ALL}")
            print(f"Recovery type: {file_info.recovery_type}")
            print(f"Confidence score: {file_info.confidence * 100:.1f}%")
            
            # Special handling for recycle bin files
            if file_info.recovery_type == 'recycle_bin' and os.name == 'nt':
                try:
                    source_path = file_info.path
                    
                    # Read and write the file in binary mode to preserve encoding
                    with open(source_path, 'rb') as source:
                        with open(dest_path, 'wb') as dest:
                            shutil.copyfileobj(source, dest)
                    
                    print(f"{Fore.GREEN}Successfully recovered file to: {dest_path}{Style.RESET_ALL}")
                    
                    # Ask user if they want to remove the file from recycle bin
                    remove_choice = input(f"{Fore.WHITE}Remove from Recycle Bin? (y/n): {Style.RESET_ALL}").strip().lower()
                    if remove_choice == 'y':
                        try:
                            i_file_path = source_path.replace('$R', '$I')
                            os.remove(source_path)  # Remove $R file
                            if os.path.exists(i_file_path):
                                os.remove(i_file_path)  # Remove $I file
                            print(f"{Fore.GREEN}Successfully removed files from Recycle Bin{Style.RESET_ALL}")
                        except Exception as e:
                            print(f"{Fore.YELLOW}Warning: Could not remove files from Recycle Bin: {str(e)}{Style.RESET_ALL}")
                        
                except Exception as e:
                    print(f"{Fore.RED}Error during recycle bin recovery: {str(e)}{Style.RESET_ALL}")
                    return False
           
            else:
                # Standard copy for non-recycle bin files
                shutil.copy2(file_info.path, dest_path)
                
            if file_info.recovery_type == 'hidden':
                if os.name == 'nt':
                    try:
                        # Remove hidden attribute on Windows
                        attributes = win32api.GetFileAttributes(dest_path)
                        win32api.SetFileAttributes(dest_path, attributes & ~win32con.FILE_ATTRIBUTE_HIDDEN)
                        print(f"{Fore.GREEN}Successfully made file visible{Style.RESET_ALL}")
                    except Exception as e:
                        print(f"{Fore.YELLOW}Warning: Could not remove hidden attribute: {str(e)}{Style.RESET_ALL}")
                else:
                    # For Unix-like systems, the file is already visible as we removed the dot prefix
                    pass
            
            print(f"{Fore.GREEN}Successfully recovered file to: {dest_path}{Style.RESET_ALL}")
            return True
            
        except Exception as e:
            print(f"{Fore.RED}Error during recovery: {str(e)}{Style.RESET_ALL}")
            return False

    def run(self):
        self.print_banner()
        
        while True:
            print(f"\n{Fore.GREEN}Select recovery method (or 'q' to quit):{Style.RESET_ALL}")
            for key, (name, _) in self.recovery_modes.items():
                print(f"{key}. {name}")
                
            choice = input(f"{Fore.WHITE}> {Style.RESET_ALL}").strip().lower()
            
            if choice == 'q':
                break
                
            if choice not in self.recovery_modes:
                print(f"{Fore.RED}Invalid choice. Please select a valid recovery method.{Style.RESET_ALL}")
                continue
            
            scan_dir = self.get_scan_directory()
            
            # Initialize scanners
            self.scanner = RecoveryScanner(scan_dir)
            self.backup_scanner = BackupScanner(scan_dir)
            self.hidden_scanner = HiddenFileScanner(scan_dir)
            
            print(f"\n{Fore.YELLOW}Scanning for files... Please wait.{Style.RESET_ALL}")
            
            try:
                # Get files based on selected recovery method
                self.files = self.recovery_modes[choice][1]()
                
                if not self.files:
                    print(f"{Fore.YELLOW}No files found using this recovery method.{Style.RESET_ALL}")
                    continue
                
                self.display_files(self.files)
                
            except Exception as e:
                print(f"{Fore.RED}Error during scanning: {str(e)}{Style.RESET_ALL}")
                continue
        
        print(f"\n{Fore.CYAN}Thank you for using the Enhanced File Recovery Tool!{Style.RESET_ALL}")

def main():
    """Main entry point for the file recovery tool"""
    try:
        # Create and run the recovery tool
        tool = EnhancedFileRecoveryTool()
        tool.run()
        
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}Program terminated by user.{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}An unexpected error occurred: {str(e)}{Style.RESET_ALL}")
    finally:
        print(f"\n{Fore.CYAN}Goodbye!{Style.RESET_ALL}")

if __name__ == "__main__":
    main()