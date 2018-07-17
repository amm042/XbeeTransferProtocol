import hashlib
class xTP:
    # message ids
    HELLO = b'\x08'
    SEND32_REQ = b'\x09'   # send file with 32 bit fragments
    SEND32_BEGIN = b'\x0a' # ack send file
    SEND32_GETACKS = b'\x0b'
    SEND32_ACKS = b'\x0c'
    SEND32_DATA = b'\x0d'
    SEND32_DONE = b'\x0e'
    
    MD5_CHECK = b'\x11'
    
def md5file(filename):
    hash = hashlib.md5()         
    with open(filename, 'rb') as f:               
        chunk = f.read(6*1024)        
        hash.update(chunk)
    return hash.digest()