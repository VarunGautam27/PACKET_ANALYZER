import subprocess
import colorama
import os
from colorama import Fore, Style

colorama.init(autoreset=True)

# Get the absolute path of the current directory
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))

def display_menu():
    """Displays a colorful menu for user interaction."""
    print(Fore.CYAN + "=" * 50)
    print(Fore.YELLOW + "WELCOME TO NETWORK PACKET ANALYSIS TOOL".center(50))
    print(Fore.CYAN + "=" * 50)
    print(Fore.GREEN + "Please select an option to proceed:\n")
    print(Fore.BLUE + "[1] GUI Mode (Launch User Interface)")
    print(Fore.MAGENTA + "[2] CLI Mode (Analyze PCAP in Command Line)")
    print(Fore.RED + "[3] Run Unit Tests")
    print(Fore.YELLOW + "[4] Exit\n")  

def main():
    while True:
        display_menu()
        choice = input(Fore.CYAN + "Enter your choice (1-4): " + Style.RESET_ALL)

        # Define script paths relative to the current directory
        script_paths = {
            "1": os.path.join(CURRENT_DIR, "PCAP_GUI.py"),
            "2": os.path.join(CURRENT_DIR, "pcap_analyzerr.py"),
            "3": os.path.join(CURRENT_DIR, "test_packet_analyzer2.py")
        }

        if choice in script_paths:
            script = script_paths[choice]

            # Verify if the script exists before execution
            if not os.path.isfile(script):
                print(Fore.RED + f"\n[ERROR] {script} not found in the directory!\n")
                continue  # Return to menu

            if choice == "2":  # CLI mode requires user input for PCAP file
                pcap_file = input(Fore.YELLOW + "\nEnter the PCAP file path: " + Style.RESET_ALL)
                if not os.path.isfile(pcap_file):
                    print(Fore.RED + "\n[ERROR] Specified PCAP file not found!\n")
                    continue  # Return to menu
                print(Fore.MAGENTA + "\nStarting CLI Packet Analysis...\n")
                subprocess.run(["python", script, pcap_file], check=True)

            else:
                print(Fore.GREEN + f"\nLaunching {script}...\n")
                subprocess.run(["python", script], check=True)

        elif choice == "4":
            print(Fore.YELLOW + "\nExiting Network Packet Analysis Tool. Goodbye!\n")
            break

        else:
            print(Fore.RED + "\nInvalid choice! Please enter a valid option (1-4).\n")

if __name__ == "__main__":
    main()
