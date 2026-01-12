# secrets is used to generate cryptographically secure random values
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa , padding
from cryptography.hazmat.primitives import hashes


#AES 
#symmetric encryption 


"""
    Encrypts and decrypts a message using AES-GCM.

    Args:
        message (str): Plaintext message

    Returns:
        tuple: AES key, ciphertext, decrypted plaintext
    """

def aes_ed(message): 
  
  # Generate a secure 256-bit key
  key = secrets.token_bytes(32)
  
  # Generate a 96-bit nonce (required for AES-GCM)
  nonce = secrets.token_bytes(12)

  
  # Create AES-GCM cipher object
  aes = AESGCM(key)

  
  # Encrypt the message
  ciphertext = nonce + aes.encrypt(nonce , message.encode(), None)
  plaintext = aes.decrypt(ciphertext[:12], ciphertext[12:], None)
  return key.hex(), ciphertext.hex() , plaintext.decode()


#rsa
#asymmetric encryption 

"""
    Encrypts and decrypts a message using RSA public/private keys.

    Args:
        message (str): Plaintext message

    Returns:
        tuple: Ciphertext and decrypted plaintext
    """

def rsa_ed(message):
  
  # Generate RSA private key
  private_key = rsa.generate_private_key(public_exponent= 65537, key_size = 2048)

  
  # Extract the public key from the private key
  public_key = private_key.public_key()

  # Encrypt message using the public key
  ciphertext = public_key.encrypt(
    message. encode(),
    padding.OAEP( 
      mgf= padding.MGF1(algorithm= hashes.SHA256()),
      algorithm= hashes.SHA256(),
      label= None

    )
  )
  
  # Decrypt message using the private key
  plaintext = private_key.decrypt(
    ciphertext,
    padding.OAEP( 
      mgf= padding.MGF1(algorithm= hashes.SHA256()),
      algorithm= hashes.SHA256(),
      label= None
   )
  )

  return ciphertext.hex(), plaintext.decode()




if __name__ == "__main__":
  print(aes_ed("Hello, AES!"))
  print(rsa_ed("Hello, RSA!"))



