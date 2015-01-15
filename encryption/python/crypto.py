# -*- coding: utf-8 -*-
"""
Implements text decryption and encryption.
"""

from Crypto.Cipher import AES


def try_to_decrypt_text(text,
                        enabled,
                        secret_key):
    """
    Try to decrypt text string.
    If not possible, return None.
    """
    # If encryption is disabled, do nothing
    if not enabled:
        return text

    # Create cipher
    cipher = AES.new(secret_key, AES.MODE_ECB)

    try:
        # Decode hex encoded message
        decoded_msg = text.decode('hex')

        # Decrypt message
        decrypted_msg = cipher.decrypt(decoded_msg)

        # Strip padding
        n = ord(decrypted_msg[-1])
        unpadded_msg = decrypted_msg[:-n]

        # Decode utf8
        unpadded_msg = unpadded_msg.decode('utf8')

    except Exception:
        return None

    return unpadded_msg



def encrypt_text(text,
                 enabled,
                 secret_key):
    """
    Encrypt text string with configured algorithm.
    """
    # If encryption is disabled, do nothing
    if not enabled:
        return text

    # Encode utf8
    text = text.encode('utf8')

    # Create cipher
    cipher = AES.new(secret_key, AES.MODE_ECB)

    # Append PKCS padding to input message
    n = AES.block_size - (len(text) % AES.block_size)
    padded_msg = text + (chr(n) * n)

    # Encrypt message
    encrypted_msg = cipher.encrypt(padded_msg)

    # Encode message with hex encoding
    encoded_msg = encrypted_msg.encode('hex')

    return encoded_msg
