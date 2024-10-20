import os
import json
import sys
import getpass

from hashlib import sha256
from termcolor import colored
from halo import Halo

from modules.encryption import DataManip
from modules.exceptions import UserExits, PasswordFileDoesNotExist
from modules.menu import Manager
from modules.master_pass_verifying import *


def exit_program():
    print(colored("Exiting...", "red"))
    sys.exit()

def start(obj: DataManip):
    if os.path.isfile("db/masterpassword.json"):
        with open("db/masterpassword.json", "r") as jsondata:
            jfile = json.load(jsondata)
        
        stored_master_pass_info = jfile["Master"] # load the saved encrypted info of the master password
        master_password = getpass.getpass("Enter Your Master Password:") # hidden pass input

        # verify inputted master password using ZKP
        spinner = Halo(text=colored("Unlocking", "green"), color="green", spinner=obj.dots_)
        
        if verify_master_pass(stored_master_pass_info, master_password):
            print(colored("Thank you! Choose an option below:", "green"))
            # create instance of Manager class
            menu = Manager(obj, "db/passwords.json", "db/masterpassword.json", stored_master_pass_info)

            try:
                menu.begin()
            except UserExits:
                exit_program()
            except PasswordFileDoesNotExist:
                print(colored("DB not found. Try adding a password", "red"))
        else:
            print(colored("Master password is incorrect", "red"))
            return start(obj)

    else: # first time running program: create a master password
        try:
            os.mkdir("db/")
        except FileExistsError:
            pass

        print(colored("To start, we'll have you create a master password. Be careful not to lose it as it is unrecoverable.", "green"))
        master_password = getpass.getpass("Create a master password for the program: ")
        second_input = getpass.getpass("Verify your master password: ")

        if master_password == second_input:
            spinner = Halo(text=colored("initializing base...", "green"), color="green", spinner=obj.dots_)
            spinner.start()
            # store info of master password, do not leak it!
            h = get_master_public_info(master_password)

            jfile = {"Master": {}}
            jfile["Master"] = h

            with open("db/masterpassword.json", "w") as jsondata:
                json.dump(jfile, jsondata, sort_keys=True, indent=4)
            spinner.stop()
            print(colored("Thank you! Restart the program and enter your master password to begin.", "green"))
        else:
            print(colored("Passwords do not match. Please try again", "red"))
            return start(obj)

if __name__ == "__main__":
    obj = DataManip()
    start(obj)
