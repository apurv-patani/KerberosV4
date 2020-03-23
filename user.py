import socket
import sys
import time, threading
from DES import *
ID = 1
IDtgs = 2
tTGS = None
Kctgs = None
Kcv = None
ticketV = None
IP = None
hashfunc = None
def getIP():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ret = s.getsockname()
    s.close()
    return ret[0]

def sock_send(sock , data):
    total = len(data)
    sl = 0
    while sl < total:
        sl += sock.send(data[sl:])

def tcp_connect(host , port):
    addrs_list = socket.getaddrinfo(host , port , family=socket.AF_INET , proto=socket.IPPROTO_TCP)
    ret_sock = None
    for addrs in addrs_list:
        try:
            print(addrs)
            ret_sock = socket.socket(addrs[0] , addrs[1])
            ret_sock.connect(addrs[4])
            break
        except Exception as e:
            print(e)
            if ret_sock is not None:
                ret_sock.close()
                ret_sock = None
            continue
    return ret_sock


def client():
    sock = None
    while True:
        try:
            tokens = input(">> ").split(" ")
            data =tokens[0].strip()
            # data = tokens[0]
            if(data=="get" and tokens[1]=="tgt"):
                # get tgt (ticker-granting ticket) through auth service exchange
                global IDtgs
                request = "||".join(["tgt",str(ID), str(IDtgs), str(time.time())])
                 # IDc || IDtgs || TS 1
                print("Requesting TGT:\n",request,"\n")
                sock_send(sock , request.encode('utf-8'))
                recv = sock.recv(4096).decode('utf-8')
                recv = hexToB(recv)
                passwd = input("Enter password: ")
                passwd = passToKey(passwd) #generate key using password
                try:
                	decrypted = decrypt(recv,passwd).split("||") # decryption using passwd
                except Exception as e:
                	print("Wrong password! Pleae try again.")
                	continue
                Kctgs,IDtgs,ts2,lf2,tTGS = decrypted # retriving Kc,tgs
                if(time.time()>float(ts2)+float(lf2)):
                    print("Ticket is expired.")
                    continue
                else:
                    print("Verified that ticket is valid.")
                print("Received TGT :",tTGS)
                print("Received Kc,tgs:",Kctgs)
                Kctgs = hexToB(Kctgs)

            elif (data=="get" and tokens[1]=="sgt"):
                mAuth = "||".join([str(ID),IP,str(time.time())])
                authenticator = bToHex(encrypt(mAuth,Kctgs)) 
                # E(Kc,tgs , [IDc || ADc || TS3 ])
                request = "||".join(["sgt",tokens[2],str(tTGS), authenticator])
                 # IDv || Tickettgs || Authenticatorc
                print("Requesting SGT for server", request)
                sock_send(sock ,request.encode('utf-8'))
                recv = sock.recv(4096).decode('utf-8')
                Kcv,IDv,ts4,ticketV=decrypt(hexToB(recv),Kctgs).split("||") 
                # [Kc,v || IDv || TS4 || Ticketv ]
                if(time.time()-100>float(ts4)):
                    print("TGS Response expired.")
                    continue
                print("Received Kc,v:",Kcv)
                print("Received SGT:",ticketV)

            elif(data == "auth" and tokens[1]=="server"):
                ts5 = str(int(time.time()))
                mAuth = "||".join([str(ID),str(IP),ts5])
                authenticator = bToHex(encrypt(mAuth,hexToB(Kcv))) 
                # E (Kc,v , [IDc || ADc || TS5 ])
                mV = "||".join(["auth",ticketV,authenticator])
                print("Authenticating with server:",mV)
                sock_send(sock ,mV.encode('utf-8'))
                recv = sock.recv(4096).decode('utf-8')
                ack = decrypt(hexToB(recv),hexToB(Kcv)) # [TS5 + 1]
                print("Received ack",ack,"for syn",ts5)
                if(int(ts5)+1==int(ack)):
                    print("Server Authenticated.")
                else:
                    print("Server Not Authenticated.")

            elif(data=="verifyID"):
                encrypted = bToHex(encrypt(tokens[1],hexToB(Kcv)))
                 # E(Kc,v , [ID]) (enc)
                toSend = "||".join([data,encrypted,hashfunc(encrypted)]) 
                # ["verifyID" || enc || hash(enc)]
                print("Requesting license info:",toSend)
                sock_send(sock ,toSend.encode('utf-8'))
                recv = sock.recv(4096).decode('utf-8').split("||") 
                # [data || hash(data)]
                if(hashfunc(recv[0])!=recv[1]):
                    print("Hash NOT Verified!")
                    continue
                license = decrypt(hexToB(recv[0]),hexToB(Kcv)).split("||") 
                # [ID || Name || Validity || VehicleType]
                print("Received Info:-")
                if(len(license)==1):
                    print(license[0])
                    continue
                else: 
                    print("License No.:",license[0])
                    print("Name:",license[1])
                    print("Validity:",license[2]=="1")
                    print("Vehicle Type:",license[3])

            elif(data == "connect"):
                host = '192.168.1.9'
                port = tokens[1]
                print("[+] Connecting to {}:{}".format(host , port))
                sock = tcp_connect(host , port)
                if sock is  None:
                    print("Connection Failed")
                    return
                print(sock)
                print("[+] Connection to {}:{} Succeded".format(host , port))

            elif(data=="useHash"):
                # client and server decide on a common hash
                encrypted = bToHex(encrypt(tokens[1],hexToB(Kcv))) # E(Kc,v, ["useHash || hashname"])
                toSend = "||".join([tokens[0],encrypted]) 
                print("Using Hash",tokens[1])
                if(tokens[1]=="sha256"):
                    hashfunc = lambda x : hashlib.sha256(x.encode()).hexdigest()
                print("Requesting to use hash",tokens[1])
                sock_send(sock ,toSend.encode('utf-8'))
				# recv = sock.recv(4096).decode('utf-8')
            elif(data == "exit"):
                data = data.encode('utf-8')
                sock_send(sock , data)
                recv = sock.recv(4096).decode('utf-8')
                sock.close()
            else:
                # pass
                data = data.encode('utf-8')
                sock_send(sock , data)
                recv = sock.recv(4096).decode('utf-8')
                print(recv)
                if(recv.strip()=="GoodBye"):
                    print("[+] Closing Connection")
                    sock.close()
                    return

        except Exception as ex:
            print("Exception :",ex)
            print("[+] Client Shutdown")
            try:
                sock.close()
            except:
                pass
            return

if __name__ == '__main__':
    # if len(sys.argv) < 3:
    #     print("[!] Usage : client <host> <port>")
    #     exit()
    # else:
    IP = getIP()
    client()
