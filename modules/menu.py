import sys
import getpass
import os
import pyperclip

from termcolor import colored 
from halo import Halo

from modules.encryption import DataManip
from modules.exceptions import *

class Manager:

    def __init__(self, obj: DataManip, filename: str, master_file: str, master_pass: int):
        self.obj_ = obj
        self.filename_ = filename
        self.master_file_ = master_file
        self.master_pass_ = master_pass
        
    def begin(self):
        try:
            choice = self.menu_prompt()
        except UserExits:
            raise UserExits
        
        if choice == '4': # user exits
            raise UserExits
        
        if choice == '1': # add or update a password
            try:
                self.update_db()
                return self.begin()
            except UserExits:
                raise UserExits
        elif choice == '2': # look up a stored password
            try:
                string = self.load_password()
                website = string.split(":")[0]
                password = string.split(":")[1]
                print(colored(f"Password for {website}: {password}", "yellow"))

                copy_to_clipboard = input("Copy password to clipboard? (Y/N): ").strip()
                if copy_to_clipboard == "exit":
                    raise UserExits
                elif copy_to_clipboard == "y":
                    try:
                        pyperclip.copy(password)
                        print(colored("Password copied to clipboard", "green"))
                    except pyperclip.PyperclipException:
                        print(colored("If you see this message on Linux use `sudo apt-get install xsel` for copying to work.", "red"))
                else:
                    pass

                return self.begin()
            except UserExits:
                raise UserExits
            except PasswordFileDoesNotExist:
                print(colored("DB not found. Try adding a password", "red"))
                return self.begin()
        elif choice == "3": # delete a single password
            try:
                self.delete_password()
            except UserExits:
                raise UserExits
        elif choice == "5": # delete DB of passwords
            try:
                self.delete_db(self.master_pass_)
            except MasterPasswordIncorrect:
                print(colored("Master password is incorrect", "red"))
                return self.delete_db(self.master_pass_)
            except UserExits:
                raise UserExits
        elif choice == "6":
            try:
                self.delete_all_data(self.master_pass_)
            except MasterPasswordIncorrect:
                print(colored("Master password is incorrect", "red"))
                return self.delete_all_data(self.master_pass_)
            except UserExits:
                raise UserExits
    
    def menu_prompt(self):
        """
        asking user for a choice from menu
        """
        print(colored("\n\t*Enter 'exit' at any point to exit.*\n", "magenta"))
        print(colored("1. Add/Update a password", "blue"))
        print(colored("2. Look up a stored password", "blue"))
        print(colored("3. Delete a password", "blue"))
        print(colored("4. Exit program", "blue"))
        print(colored("5. Erase all passwords", "red"))
        print(colored("6. Delete all data including Master Password", "red"))

        choice = input("Enter a choice: ")

        if choice == "":
            return self.menu_prompt()
        elif choice == "exit":
            raise UserExits
        else:
            return choice.strip()
    
    # return a generated password
    def __return_generated_password(self, website):
        try:
            generated_pass = self.obj_.generate_password()
            print(colored(generated_pass, "yellow"))

            loop = input("Generate a new password? (Y/N): ")
            if loop.lower().strip() == "exit":
                raise UserExits
            elif (loop.lower().strip() == "y") or (loop.strip() == ""):
                return self.__return_generated_password(website) #recursive call
            elif loop.lower().strip() == "n":
                return generated_pass
        except (PasswordNotLongEnough, EmptyField):
            print(colored("Password length invalid.", "red"))
            return self.__return_generated_password(website)
        except UserExits:
            print(colored("Exiting...", "red"))
            sys.exit()
    
    # add or update a password in the db
    def update_db(self): # option 1 on main.py 
        website = input("Enter the website for which you want to store a password (ex. google.com): ")
        if website.lower() == "":
            self.update_db()
        elif website.lower().strip() == "exit":
            raise UserExits
        else:
            gen_question = input(f"Do you want to generate a password for {website} ? (Y/N): ")
            if gen_question.strip() == "":
                self.update_db()
            elif gen_question.lower().strip() == "exit":
                raise UserExits
            elif gen_question.lower().strip() == "n": # user wants to manually enter  a password
                password = input(f"Enter a password for {website}: ")
                if password.lower().strip() == "exit":
                    raise UserExits
                else:
                    self.obj_.encrypt_data(self.filename_, self.master_pass_, website, password)
            elif gen_question.lower().strip() == "y":
                password = self.__return_generated_password(website)        
                self.obj_.encrypt_data(self.filename_, self.master_pass_, website, password)

    # load a string of websites stored and ask user to enter a website, then decrypt password for entered website
    def load_password(self):
        try:
            # self.list_passwords()
            pass
        except PasswordFileIsEmpty:
            return self.begin()

        website = input("Enter website for the password you want to retrieve: ")
        plaintext = None
        if website.lower().strip() == "exit":
            raise UserExits
        elif website.strip() == "":
            return self.load_password()
        else:
            try:  
                encrypted_domain, _ = self.obj_.look_up(self.filename_, self.master_pass_, website)                
                plaintext = self.obj_.decrypt_data(self.filename_, self.master_pass_, encrypted_domain)
            except PasswordNotFound:
                print(colored(f"Password for {website} not found.", "red"))
                return self.load_password()
            except PasswordFileDoesNotExist:
                print(colored("DB not found. Try adding a password", "red"))
                return self.begin()
        final_str = f"{website}:{plaintext}"        
        return final_str
    
    # menu prompt to delete db/passwords
    def delete_db(self, stored_master):
        confirmation = input("Are you sure you want to delete the password file? (Y/N) ")
        if confirmation.lower().strip() == "y":
            entered_master = getpass.getpass("Enter your master password to delete all stored passwords: ")
            if entered_master.lower().strip() == "exit":
                raise UserExits
            else:
                try:
                    self.obj_.delete_db(self.filename_, stored_master, entered_master)
                    print(colored("Password Data Deleted successfully. ", "green"))
                    return self.begin()
                except MasterPasswordIncorrect:
                    raise MasterPasswordIncorrect
                except PasswordFileDoesNotExist:
                    print(colored("DB not found. Try adding a password", "red"))
                    return self.begin()
        elif confirmation.lower().strip() == "n":
            print(colored("Cancelling...", "red"))
            return self.begin()
        elif confirmation.lower().strip() == "exit":
            raise UserExits
        elif confirmation.strip() == "":
            return self.delete_db(stored_master)

    # list all websites stored in DB
    # def list_passwords(self):
    #     print(colored("Current Passwords Stored:", "yellow"))
    #     spinner = Halo(text=colored("Loading Passwords", "yellow"), color="yellow", spinner=self.obj_.dots_)
    #     spinner.start()

    #     try:
    #         lst_of_passwords = self.obj_.list_passwords(self.filename_)
    #         spinner.stop()
    #         print(colored(lst_of_passwords, "yellow"))
    #     except PasswordFileIsEmpty:
    #         lst_of_passwords = "--There are no passwords stored.--"
    #         spinner.stop()
    #         print(colored(lst_of_passwords, "yellow"))
    #         raise PasswordFileIsEmpty
    #     except PasswordFileDoesNotExist:
    #         spinner.stop()
    #         raise PasswordFileDoesNotExist
    
    # delete a single password from DB
    def delete_password(self):
        website = input("What website do you want to delete? (ex. google.com): ").strip()

        if website == "exit":
            raise UserExits
        elif website == "":
            return self.delete_password()
        else:
            try:
                encrypted_domain, _ = self.obj_.look_up(self.filename_, self.master_pass_, website)   
                self.obj_.delete_password(self.filename_, encrypted_domain)
                print(colored(f"Data for {website} deleted successfully.", "green"))
                return self.begin()
            except PasswordNotFound:
                print(colored(f"{website} not in DB", "red"))
                return self.delete_password()
            except PasswordFileDoesNotExist:
                print(colored("DB not found. Try addding a password ", "red"))
                return self.begin()

    # delete all data including master password and passwords stored
    def delete_all_data(self, stored_master):
        confirmation = input("Are you sure you want to delete all data? (Y/N)")
        if confirmation.lower().strip() == "y":
            entered_master = getpass.getpass("Enter your master password to delete all stored passwords: ")
            if entered_master.lower().strip() == "exit":
                raise UserExits
            else:
                try:
                    self.obj_.delete_all_data(self.filename_, self.master_file_, stored_master, entered_master)
                    print(colored("All data deleted successfully. ", "green"))
                    sys.exit()
                except MasterPasswordIncorrect:
                    raise MasterPasswordIncorrect
        elif confirmation.lower().strip() == "n":
            print(colored("Cancelling...", "red"))
            return self.begin()
        elif confirmation.lower().strip() == "exit":
            raise UserExits
        elif confirmation.strip() == "":
            return self.delete_all_data(stored_master)