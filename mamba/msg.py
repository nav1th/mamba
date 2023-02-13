from colorama import Style, Fore 
import sys
import json


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
        
    
    
def cprint(content: str, colour: bool, fg="", bg="",): #TODO coloured output for protos
    if not colour: #regular print if no colours
        print(content)
        return
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
    pass
