from colorama import Style, Fore 
import curses
import sys


def err(msg: str, colour: bool):
    if colour:
        sys.stderr.writelines(Fore.RED + Style.BRIGHT + "[!]" 
                          + Style.RESET_ALL + f" {msg}\n")
    else:
        sys.stderr.writelines(f"error: {msg}\n")

def info(msg: str, colour: bool):
    if colour:
        print(Fore.WHITE + Style.BRIGHT + "[*]" + Style.RESET_ALL + f" {msg}" )
    else:
        print(f"info: {msg}\n")

def warn(msg: str, colour: bool):
    if colour:
        sys.stderr.writelines(Fore.YELLOW + Style.BRIGHT + "[?]" 
                          + Style.RESET_ALL + f" {msg}\n")
    else:
        sys.stderr.writelines(f"warning: {msg}\n")
        
    
    
def cprint(colour: bool, fg: str , bg: str): #TODO coloured output for protos
    match fg:
        case "YELLOW":
            print(Fore.YELLOW,end="")
        case "BLUE":
            print(Fore.BLUE,end="")
        case "GREEN":
            print(Fore.GREEN,end="")
        case "CYAN":
            print(Fore.CYAN,end="")
        case "YELLOW":
            print(Fore.YELLOW,end="")
        case "YELLOW":
            print(Fore.YELLOW,end="")
    print(f"{fg}")
    pass
