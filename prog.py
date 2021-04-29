import argparse

parser = argparse.ArgumentParser(prog="PBKDF2 Encryption Utility", \
  usage="Program for encrypting and decrypting files. CLI input takes mode of operation, path to file, and the password.")

parser.add_argument("mode", help="[ encrypt | decrypt ]")
parser.add_argument("path", help="<file path>")
parser.add_argument("password", help="<password>")

args = parser.parse_args()

mode = args.mode
file_path = args.path
password = args.password

DEBUG = True
if DEBUG:
  print(f"Mode: {mode} File Path: {file_path} Password: {password}")