from termcolor import colored

def success_op(msg):
    """
    Print a success message in green color.
    """
    print(colored(f"\n[+] {msg}\n", "green"))

def fail_op(msg):
    """
    Print a failure message in red color.
    """
    print(colored(f"\n[-] {msg}\n", "red"))

def mid_op(msg):
    """
    Print an informational message in yellow color.
    """
    print(colored(f"\n[*] {msg}\n", "yellow"))