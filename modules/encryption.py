import json
import string
import os
import random
import hmac
import sys

from Crypto.Cipher import AES
from halo import Halo
from termcolor import colored
from hashlib import pbkdf2_hmac, sha256

from modules.exceptions import *
from modules.master_pass_verifying import verify_master_pass

class DataManip:
    def __init__(self):
        self.dots_ = {"interval": 80, "frames": ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]}
        self.specialChar_ = "!@#$%^&*()-_"
    
    def derive_keys(self, master_password, salt: bytes = None, interations: int = 100000, key_length: int = 64):
        if salt is None:
            salt = os.urandom(16) # create random salt with 16 bytes

        # using PBKDF2 to derive keys
        derived_key =  pbkdf2_hmac(
            "sha256",                   # hash algorithm
            str(master_password).encode(),   # master password converted to bytes
            salt,                       # salt (as bytes)
            interations,                # number of interations
            key_length                  # total derised key length in bytes (64 bytes for 2 keys)
        )

        # split into 2 parts:
        hmac_key = derived_key[:32]     # for domain name
        aes_key = derived_key[32:]      # for password

        return hmac_key, aes_key, salt

    def _calculate_hash(self, filename):
        # Create a SHA-256 hash object
        sha256_hash = sha256()
        # Open the file in binary mode for reading (rb).
        with open(filename, "rb") as file:
            # Read the file in 64KB chunks to efficiently handle large files.
            while True:
                data = file.read(65536)
                if not data:
                    break
                # Update the hash object with the data read from the file.
                sha256_hash.update(data)
        return sha256_hash.hexdigest()
    def _verify_integrity(self, filename):
        sha256_val = self._calculate_hash(filename)
        with open("/home/thanh/Password-Manager/sekret/passwords.hash", "r") as hash_file:
            stored_hash = hash_file.read().strip()
        if stored_hash != sha256_val:
            print(colored("[!!] File passwords.json is illegally modified.", "red"))
            sys.exit()
    # save password to DB
    def __save_password(self, filename, salt, encrypted_website, data, nonce):
        spinner = Halo(text=colored("Saving", "green"), spinner=self.dots_, color="green")
        # spinner.start()
        
        if os.path.isfile(filename):
            self._verify_integrity(filename)
            try:
                with open(filename, "r") as jsondata:
                    jfile = json.load(jsondata)
                jfile[encrypted_website]["salt"] = salt
                jfile[encrypted_website]["nonce"] = nonce
                jfile[encrypted_website]["password"] = data
                with open(filename, "w") as jsondata:
                    json.dump(jfile, jsondata, sort_keys=True, indent=4)
            except KeyError:
                with open(filename, "r") as jsondata:
                    jfile = json.load(jsondata)
                
                jfile[encrypted_website] = {} # do not have this web already
                jfile[encrypted_website]["salt"] = salt
                jfile[encrypted_website]["nonce"] = nonce
                jfile[encrypted_website]["password"] = data

                with open(filename, "w") as jsondata:
                    json.dump(jfile, jsondata, sort_keys=True, indent=4)
        else: # initialize the file in case it doesn't exist off the start.
            # 'cause of first time, we need to write hash value of passwords.json aka filename without check integrity
            jfile = {}
            jfile[encrypted_website] = {}
            jfile[encrypted_website]["salt"] = salt
            jfile[encrypted_website]["nonce"] = nonce
            jfile[encrypted_website]["password"] = data

            with open(filename, "w") as jsondata:
                json.dump(jfile, jsondata, sort_keys=True, indent=4)

        sha256_val = self._calculate_hash(filename)
        with open("/home/thanh/Password-Manager/sekret/passwords.hash", "w") as hash_file:
            hash_file.write(sha256_val)
        spinner.stop()
        print(colored("Saved successfully. Thank you!", "green"))
    
    # encrypt and save the data to a file using master password as the key
    def encrypt_data(self, filename, master_pass, website, password):
        encrypted_domain = None
        if os.path.isfile(filename):
            encrypted_domain, salt = self.look_up(filename, master_pass, website)
            _, aes_key, _ = self.derive_keys(master_pass, salt)
        if encrypted_domain is None:
            hmac_key, aes_key, salt = self.derive_keys(master_pass)
            # hmac domain name
            encrypted_domain = hmac.new(hmac_key, website.encode(), sha256).hexdigest()

        cipher = AES.new(aes_key, AES.MODE_GCM) # create AES encryption object in GCM mode using aes_key

        # a value to ensure using different keys for every encryptions, convert to hex to be saved in DB
        nonce = cipher.nonce.hex()

        encrypted_password = cipher.encrypt(password.encode()).hex()
        self.__save_password(filename, salt.hex(), encrypted_domain, encrypted_password, nonce)
    
    # decrypt the password 
    def decrypt_data(self, filename, master_pass, encrypted_website):
        if encrypted_website is None:
            raise PasswordNotFound
        if os.path.isfile(filename):
            self._verify_integrity(filename)
            with open(filename, "r") as jsondata:
                jfile = json.load(jsondata)
                salt = bytes.fromhex(jfile[encrypted_website]["salt"])
                nonce = bytes.fromhex(jfile[encrypted_website]["nonce"])
                password = bytes.fromhex(jfile[encrypted_website]["password"])
        else:
            raise PasswordFileDoesNotExist
        
        _, aes_key, _ = self.derive_keys(master_pass, salt)
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce)
        plaintext_pass = cipher.decrypt(password).decode()

        return plaintext_pass
    
    # generate a complex password
    def generate_password(self):
        password = []
        length = input("enter length for password (at least 8): ")

        if length.lower().strip() == "exit":
            raise UserExits
        elif length.strip() == "":
            raise EmptyField
        elif int(length) < 8:
            raise PasswordNotLongEnough
        else:
            # generating a password
            spinner = Halo(text=colored("Generating Password", "green"), spinner=self.dots_, color="green")
            spinner.start()
            for i in range(0, int(length)):
                password.append(random.choice(random.choice([string.ascii_lowercase, string.ascii_uppercase, string.digits, self.specialChar_])))
            
            finalPass = "".join(password)
            spinner.stop()
            return finalPass
    
    # delete DB/Password file & contents
    def delete_db(self, filename, stored_master_info, entered_master):
        if os.path.isfile(filename):
            self._verify_integrity(filename)
            # print(type(stored_master_info))
            if verify_master_pass(stored_master_info, entered_master):
                # clear the data 
                spinner = Halo(text=colored("Deleting all password data...", "red"), spinner=self.dots_, color="red")
                spinner.start()
                jfile = {}
                with open(filename, "w") as jdata:
                    json.dump(jfile, jdata)
                # delete the file
                os.remove(filename)
                os.remove("/home/thanh/Password-Manager/sekret/passwords.hash")
                spinner.stop()
            else:
                raise MasterPasswordIncorrect
        else:
            raise PasswordFileDoesNotExist
    
    def delete_password(self, filename, encrypted_website): # using hmac of website
        if os.path.isfile(filename):
            self._verify_integrity(filename)
            with open(filename, "r") as jdata:
                jfile = json.load(jdata)
            
            try:
                jfile.pop(encrypted_website) # pop the website out of json

                with open(filename, "w") as jdata:
                    json.dump(jfile, jdata, sort_keys=True, indent=4)
                sha256_val = self._calculate_hash(filename)
                with open("/home/thanh/Password-Manager/sekret/passwords.hash", "w") as hash_file:
                    hash_file.write(sha256_val)
            except KeyError:
                raise PasswordNotFound
        else:
            raise PasswordFileDoesNotExist
    
    # delete all data including master password and passwords stored 
    def delete_all_data(self, filename, master_file, stored_master_info, entered_master):
        if os.path.isfile(master_file) and os.path.isfile(filename):
            self._verify_integrity(filename)
            if verify_master_pass(stored_master_info, entered_master):
                spinner = Halo(text=colored("Deleting all data...", "red"), spinner=self.dots_, color="red")
                spinner.start()
                jfile = {}
                with open(master_file, "w") as jdata:
                    json.dump(jfile, jdata)
                with open(filename, "w") as jdata:
                    json.dump(jfile, jdata)
                
                # delete file
                os.remove(filename)
                sha256_val = self._calculate_hash(filename)
                with open("/home/thanh/Password-Manager/sekret/passwords.hash", "w") as hash_file:
                    hash_file.write(sha256_val)
                spinner.stop()
            else:
                raise MasterPasswordIncorrect
        elif os.path.isfile(master_file) and not os.path.isfile(filename):
            spinner = Halo(text=colored("Deleting all data...", "red"), spinner=self.dots_, color="red")
            spinner.start()
            if verify_master_pass(stored_master_info, entered_master):
                jfile = {}
                with open(master_file, 'w') as jdata:
                    json.dump(jfile, jdata)
                os.remove(master_file)
                spinner.stop()
            else:
                raise MasterPasswordIncorrect
    
    def look_up(self, filename, master_pass, plain_domain):
        if os.path.isfile(filename):
            self._verify_integrity(filename)
            with open(filename, "r") as jdata:
                jfile = json.load(jdata)
            
            try:
                for cipher_domain, details in jfile.items():
                    salt = bytes.fromhex(details["salt"])
                    hmac_key, _, salt = self.derive_keys(master_pass, salt)
                    encrypted_domain = hmac.new(hmac_key, plain_domain.encode(), sha256).hexdigest()
                    if encrypted_domain == cipher_domain:
                        return cipher_domain, salt
                # raise PasswordNotFound
            except KeyError:
                raise PasswordNotFound
        else:
            raise PasswordFileDoesNotExist
        return None, None