from colorama import Style, Fore 
import sys
def err(msg: str, colour: bool):
    if colour:
        sys.stderr.writelines(Fore.RED + Style.BRIGHT + "[!!]" 
                          + Style.RESET_ALL + f" {msg}\n")
    else:
        sys.stderr.writelines(f"error: {msg}")
def info(msg: str, colour: bool):
    if colour:
        print(Fore.WHITE + Style.BRIGHT + "[*]" + Style.RESET_ALL + f" {msg}" )
    else:
        print(f"info: {msg} ")

def warn(msg: str, colour: bool):
    if colour:
        sys.stderr.writelines(Fore.YELLOW + Style.BRIGHT + "[!]" 
                          + Style.RESET_ALL + f" {msg}\n")
    else:
        sys.stderr.writelines(f"warning: {msg}")
        
    
    
