import unittest, os, tempfile, shutil
from datetime import datetime

class FileInfo:
    def __init__(self, path, size, modified, name, orig_path, rec_type, confidence):
        self.path, self.size, self.modified = path, size, modified
        self.original_name, self.original_path = name, orig_path
        self.recovery_type, self.confidence = rec_type, confidence

class Scanner:
    def __init__(self, directory=None):
        self.directory = directory
        self.temp_dirs = []
        self.recycle_bins = []
    
    def _add_files(self, files, fpath, size, modified, name, orig_path, rec_type, confidence):
        files.append(FileInfo(fpath, size, modified, name, orig_path, rec_type, confidence))
    
    def scan_recycle_bin(self):
        files = []
        for bin_path in self.recycle_bins:
            for entry in os.listdir(bin_path):
                if entry.startswith('$I'):
                    i_file, r_file = os.path.join(bin_path, entry), os.path.join(bin_path, '$R' + entry[2:])
                    if os.path.exists(r_file):
                        with open(i_file, 'rb') as f:
                            f.seek(8)
                            size = int.from_bytes(f.read(8), 'little')
                            del_time = int.from_bytes(f.read(8), 'little')
                            path_len = int.from_bytes(f.read(4), 'little')
                            orig_path = f.read(path_len * 2).decode('utf-16le')
                        self._add_files(files, r_file, size, datetime.fromtimestamp(del_time),
                            os.path.basename(orig_path), orig_path, 'recycle_bin', 1.0)
        return files
    
    def scan_backup_files(self):
        files = []
        for ext in ['.bak', '.backup', '.old']:
            for root, _, files_list in os.walk(self.directory or '.'):
                for f in [f for f in files_list if f.endswith(ext)]:
                    fpath = os.path.join(root, f)
                    self._add_files(files, fpath, os.path.getsize(fpath),
                            datetime.fromtimestamp(os.path.getmtime(fpath)),
                            f.rsplit('.', 1)[0], fpath, 'backup', 0.9)
        return files
    
    def scan_temp_files(self):
        files = []
        for d in self.temp_dirs:
            for root, _, files_list in os.walk(d):
                for f in files_list:
                    if any(f.endswith(ext) for ext in ['.tmp', '.temp', '.autosave']):
                        fpath = os.path.join(root, f)
                        self._add_files(files, fpath, os.path.getsize(fpath),
                            datetime.fromtimestamp(os.path.getmtime(fpath)),
                            f.replace('~', '').rsplit('.', 1)[0], fpath, 'temporary', 0.7)
        return files
    
    def scan_hidden_files(self):
        files = []
        if self.directory:
            for root, _, files_list in os.walk(self.directory):
                for f in [f for f in files_list if f.startswith('.')]:
                    fpath = os.path.join(root, f)
                    self._add_files(files, fpath, os.path.getsize(fpath),
                            datetime.fromtimestamp(os.path.getmtime(fpath)),
                            f, fpath, 'hidden', 0.8)
        return files
    
    def scan_all(self):
        return (self.scan_recycle_bin() + self.scan_backup_files() + 
                self.scan_temp_files() + self.scan_hidden_files())

    def recover_file(self, file_info, rec_dir):
        os.makedirs(rec_dir, exist_ok=True)
        shutil.copy2(file_info.path, os.path.join(rec_dir, file_info.original_name))
        return True

class TestFileRecoveryToolSuite(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.test_dir = tempfile.mkdtemp()
        cls.rec_dir = tempfile.mkdtemp()
        print("\nStarting File Recovery Tests")

    def setUp(self):
        # Create test environment
        self.rbin = os.path.join(self.test_dir, '$Recycle.Bin', 'TEST')
        os.makedirs(self.rbin, exist_ok=True)
        
        # Create test files
        test_files = {
            os.path.join(self.test_dir, 'test.bak'): 'backup content',
            os.path.join(self.test_dir, '~temp.tmp'): 'temp content',
            os.path.join(self.test_dir, '.hidden.txt'): 'hidden content'
        }
        for path, content in test_files.items():
            with open(path, 'w') as f:
                f.write(content)
        
        # Create recycle bin files
        i_file, r_file = os.path.join(self.rbin, '$I000.txt'), os.path.join(self.rbin, '$R000.txt')
        with open(i_file, 'wb') as f:
            f.write(b'\x01\x00\x00\x00\x00\x00\x00\x00')  # version & flags
            f.write((100).to_bytes(8, 'little'))  # size
            f.write(int(datetime.now().timestamp()).to_bytes(8, 'little'))
            test_path = os.path.join(self.test_dir, 'deleted.txt')
            f.write(len(test_path).to_bytes(4, 'little'))
            f.write(test_path.encode('utf-16le'))
        with open(r_file, 'w') as f:
            f.write('deleted content')

    def _test_scanner(self, scan_method, recovery_type):
        scanner = Scanner(self.test_dir)
        scanner.recycle_bins = [self.rbin]
        scanner.temp_dirs = [self.test_dir]
        
        files = scan_method()
        self.assertEqual(len(files), 1)
        
        recovered = scanner.recover_file(files[0], self.rec_dir)
        self.assertTrue(recovered)
        
        rec_path = os.path.join(self.rec_dir, files[0].original_name)
        self.assertTrue(os.path.exists(rec_path))
        print(f"✓ File successfully recovered from {recovery_type}: {files[0].original_name}")

    def test_1_file_info(self):
        print("\nTest 1: FileInfo Object Testing")
        path = os.path.join(self.test_dir, 'test.file')
        file_info = FileInfo(path, 100, datetime.now(), 'test.file', path, 'test', 0.9)
        self.assertEqual(file_info.path, path)
        self.assertEqual(file_info.confidence, 0.9)
        print("✓ FileInfo object created and verified successfully")

    def test_2_recycle_bin(self):
        print("\nTest 2: Recycle Bin Recovery")
        scanner = Scanner()
        scanner.recycle_bins = [self.rbin]
        self._test_scanner(scanner.scan_recycle_bin, "Recycle Bin")

    def test_3_backup_scanner(self):
        print("\nTest 3: Backup File Recovery")
        scanner = Scanner(self.test_dir)
        self._test_scanner(scanner.scan_backup_files, "Backup")

    def test_4_temp_scanner(self):
        print("\nTest 4: Temporary File Recovery")
        scanner = Scanner()
        scanner.temp_dirs = [self.test_dir]
        self._test_scanner(scanner.scan_temp_files, "Temporary Files")

    def test_5_hidden_scanner(self):
        print("\nTest 5: Hidden File Recovery")
        scanner = Scanner(self.test_dir)
        self._test_scanner(scanner.scan_hidden_files, "Hidden Files")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.test_dir)
        shutil.rmtree(cls.rec_dir)
        print("\n✓ All tests completed successfully")

if __name__ == '__main__':
    unittest.main(verbosity=1)