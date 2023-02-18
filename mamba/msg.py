from colorama import Back, Style, Fore 
import sys
import json

def err(content: str, colour: bool):
    if colour:
        sys.stderr.writelines(Fore.RED + Style.BRIGHT + "[!]" 
                          + Style.RESET_ALL + f" {content}\n")
    else:
        sys.stderr.writelines(f"error: {content}\n")

def info(content: str, colour: bool):
    if colour:
        print(Fore.BLUE + Style.BRIGHT + "[*]" + Style.RESET_ALL + f" {content}" )
    else:
        print(f"info: {content}\n")

def warn(content: str, colour: bool):
    if colour:
        sys.stderr.writelines(Fore.YELLOW + Style.BRIGHT + "[?]" 
                          + Style.RESET_ALL + f" {content}\n")
    else:
        sys.stderr.writelines(f"warning: {content}\n")

def warn_confirmed(content: str, colour: bool) -> bool:
    if colour:
        print(f"{Fore.YELLOW}{Style.BRIGHT}[?] {Style.RESET_ALL}{content}", end=" ")
        user_input = input(f"are you sure? [{Fore.GREEN}y{Style.RESET_ALL}/{Fore.RED}N{Style.RESET_ALL}]: ")
    else:
        print(f"warning: {content}", end=" ")
        user_input = input(f"are you sure? [y/N]: ")

    if user_input == "y":
        return True
    return False

