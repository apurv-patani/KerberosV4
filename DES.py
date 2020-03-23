from Crypto.Cipher import DES
import hashlib,sys,binascii,Padding,base64,random,string

def encrypt(plaintext,key):
	# encrypt plaintext using DES with 'key', with padding
	plaintext = Padding.appendPadding(plaintext,blocksize=Padding.DES_blocksize,mode='CMS').encode()
	encobj = DES.new(key,DES.MODE_CBC,'00000000')
	return(encobj.encrypt(plaintext))

def decrypt(ciphertext,key):
	# decrypt ciphertext using DES with 'key' and remove padding
	encobj = DES.new(key,DES.MODE_CBC,'00000000')
	plaintext = (encobj.decrypt(ciphertext))
	plaintext = Padding.removePadding(plaintext.decode(),mode='CMS')
	return plaintext

def bToHex(val):
	# convert bytes to hexadecimal
	return binascii.hexlify(bytearray(val)).decode()

def hexToB(val):
	# convertt hexadecimal to bytes
	return bytes.fromhex(val)

def passToKey(passwd):
	# convert passwd to key for DES
	return hashlib.sha256(passwd.encode()).digest()[:8]

def getRandStr(len):
	# generate random string of length 'len'
	return ''.join(random.choices(string.ascii_uppercase+string.ascii_lowercase+string.digits, k = len)) 