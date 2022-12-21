from colorama import Style, Fore 
import sys
def emesg(x: str):
    sys.stderr.writelines(Fore.RED + Style.BRIGHT + "error" 
                          + Style.RESET_ALL + f": {x}\n")
    
    
