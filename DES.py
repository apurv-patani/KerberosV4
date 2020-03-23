from Crypto.Cipher import DES
import hashlib,sys,binascii,Padding,base64,random,string
val='germany'
password = "strongpass"

plaintext=val
salt='00000000'

def encrypt(plaintext,key):
	plaintext = Padding.appendPadding(plaintext,blocksize=Padding.DES_blocksize,mode='CMS').encode()
	encobj = DES.new(key,DES.MODE_CBC,salt)
	return(encobj.encrypt(plaintext))

def decrypt(ciphertext,key):
	salt='00000000'
	encobj = DES.new(key,DES.MODE_CBC,salt)
	plaintext = (encobj.decrypt(ciphertext))
	plaintext = Padding.removePadding(plaintext.decode(),mode='CMS')
	return plaintext

def bToHex(val):
	return binascii.hexlify(bytearray(val)).decode()

def hexToB(val):
	return bytes.fromhex(val)

def passToKey(passwd):
	return hashlib.sha256(passwd.encode()).digest()[:8]

def getRandStr(len):
	return ''.join(random.choices(string.ascii_uppercase+string.ascii_lowercase+string.digits, k = len)) 
# print("\nDES")

# # key = hashlib.sha256(password.encode()).digest()[:8]
key = passToKey(password)
print(key)
# print("type",type(key))
print("hex",bToHex(key))
# print("bin",hexToB(bToHex(key)))
# # print("key type",type(key))
# # print("key",key)
# # val = binascii.hexlify(bytearray(key))
# # print("val: ",bToHex(key))
# # hexkeyC = "5e884898da280471"
# # val2 = hexToB(val)
# # print("val2",val2)


# print("After padding (CMS): ",binascii.hexlify(bytearray(plaintext.encode())))

# ciphertext = encrypt(plaintext,key)

# print("Cipher (ECB): ",binascii.hexlify(bytearray(ciphertext)),end="")
# print ("  ",base64.b64encode (ciphertext).decode())

# print("ciphertext tpye",type(ciphertext))
# plaintext = decrypt(ciphertext,key)

# print("  decrypt: "+plaintext)
# passwd = input("Enter pass: ")
# passwd = "sherlocked"
# passwd = passToKey(passwd)
# encrypted = encrypt("s"*1000,passwd)
# print(type(encrypted))
# decrypted = decrypt(encrypted,passwd)
# print(decrypted)