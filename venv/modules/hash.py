# hashlib is a built-in Python library used for cryptographic hashing
# It supports algorithms like MD5, SHA-1, SHA-256, etc
import hashlib

"""
    Generates a SHA-256 hash for a given file.

    Args:
        file_path (str): Path to the file to be hashed

    Returns:
        str: Hexadecimal representation of the file's hash
"""

def hash_file(file_path): 
  h = hashlib.new("sha256")
  with open (file_path, "rb") as file:
      while True:
        chunk = file.read(1024)
        if chunk ==b"":
           break 
        h.update(chunk)
  return h.hexdigest()

def verify_integrity (file1,file2):
   hash1 =hash_file(file1)
   hash2 = hash_file(file2)
   print("\n Checking integrity between ", file1 , "and" , file2)
  # If hashes match, files are identical
   if hash1 == hash2:
      return "File is intact, No modification has been made."
       # If hashes differ, one of the files has changed
   return "File has been modified , possibly unsafe"

       


if __name__ == "__main__": 
   print("SHA Hash of file is : ", hash_file(r"venv\sample_files\sample.txt")) 
   print( verify_integrity(r"venv\sample_files\Pic1.png", r"venv\sample_files\Pic 2 .png"))
   print( verify_integrity(r"venv\sample_files\Pic1.png", r"venv\sample_files\Pic 3.png"))
