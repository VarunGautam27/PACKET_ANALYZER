import os
import subprocess
from colorama import Fore, Style, init

# Initialize colorama for Windows compatibility
init(autoreset=True)

# Define the file paths
FILES = {
    "1": "C:\\Users\\LENONO\\Desktop\\CW2_PYTHON\\recoveryCLI.py",
    "2": "C:\\Users\\LENONO\\Desktop\\CW2_PYTHON\\FINAL_GUI.py",
    "3": "C:\\Users\\LENONO\\Desktop\\CW2_PYTHON\\test_recovery3.py"
}

# Define colors for output
COLOR_TITLE = Fore.CYAN + Style.BRIGHT
COLOR_OPTION = Fore.YELLOW
COLOR_SUCCESS = Fore.GREEN
COLOR_ERROR = Fore.RED
COLOR_RESET = Style.RESET_ALL

def run_file(file_path):
    """Runs the Python file using subprocess."""
    try:
        if os.path.exists(file_path):
            print(f"{COLOR_SUCCESS}Running {file_path}...{COLOR_RESET}")
            subprocess.run(["python", file_path], shell=True)
        else:
            print(f"{COLOR_ERROR}Error: File does not exist.{COLOR_RESET}")
    except Exception as e:
        print(f"{COLOR_ERROR}Error running file: {e}{COLOR_RESET}")

def main():
    while True:
        print(f"\n{COLOR_TITLE}=== CHOOSE A METHOD  ==={COLOR_RESET}")
        print(f"{COLOR_OPTION}1. Run CLI")
        print(f"{COLOR_OPTION}2. Run GUI")
        print(f"{COLOR_OPTION}3. Run UNIT TESTING")
        print(f"{COLOR_OPTION}4. Exit{COLOR_RESET}")

        choice = input(f"{Fore.BLUE}Enter your choice: {COLOR_RESET}").strip()

        if choice == "4":
            print(f"{COLOR_SUCCESS}Exiting program. Goodbye!{COLOR_RESET}")
            break
        elif choice in FILES:
            run_file(FILES[choice])
        else:
            print(f"{COLOR_ERROR}Invalid choice, please try again.{COLOR_RESET}")

if __name__ == "__main__":
    main()
