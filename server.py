import socket, sys, threading, time, ctypes
from serverKeyData import *
from DES import *

Kcv = None
hashfunc = None
def sock_send(sock , data):
    total = len(data)
    sl = 0
    while sl < total:
        sl += sock.send(data[sl:])

def handle_client(*args):
    sock = args[0]
    addr = args[1]
    print("[+] Handling Client : {}".format(addr))
    log = lambda x : print("[{}] ".format(addr) + x)
    while True:
        try:
            data = sock.recv(4096).decode('utf-8')
            log("Got Msg : {}".format(data))
            # if(data==""):
            #     continue
            data = data.split("||")
            opcode = data[0].strip()
            if(opcode=="auth"):
                ticketV = data[1]
                Kcv,IDc,ADc,IDv,ts4,lf4=decrypt(hexToB(ticketV),keyServ).split("||")
                # [Kc,v || IDc || ADc || IDv || TS4 || Lifetime4]
                authenticator = data[2]
                authenticator= decrypt(hexToB(authenticator),hexToB(Kcv)).split("||")
                #  [IDc || ADc || TS3 ]
                ts5 = int(authenticator[2])
                
                if(IDc==authenticator[0] and ADc==authenticator[1]
                    and time.time()<ts5+10):
                    print("User Authenticated.")
                else:
                    print("User Not Authenticated.")
                    continue
                if(time.time()>float(ts4)+float(lf4)):
                    print("Ticket for server expired.")
                else:
                    print("Verified that ticket for server is valid.")
                print("Received Kc,v:",Kcv)
                print("Received timestamp:",ts5)
                print("Sending ack:",ts5+1)
                
                ret = bToHex(encrypt(str(ts5+1),hexToB(Kcv))) # sending ts5+1 as ack
                sock_send(sock, ret.encode('utf-8'))

            elif(opcode=="verifyID"):
                if(hashfunc(data[1])!=data[2]):
                    print("Hash not Verified")
                    continue
                licenseID = decrypt(hexToB(data[1]),hexToB(Kcv))
                if(licenseID in licenseData.keys()):
                    license = bToHex(encrypt(licenseData[licenseID],hexToB(Kcv)))
                    # [ID || Name || Validity || VehicleType]
                    print("For licenseID",licenseID,
                        "send info:",license)
                else:
                    license = "License with that ID doesn't exist."
                    print(license)
                    license = bToHex(encrypt(license,hexToB(Kcv)))
                sock_send(sock, "||".join([license,hashfunc(license)]).encode('utf-8'))
            elif(opcode=="useHash"):
                # client and server decide on a common hash
                data[1] = decrypt(hexToB(data[1]),hexToB(Kcv))
                if(data[1]=="sha256"):
                    hashfunc = lambda x : hashlib.sha256(x.encode()).hexdigest()
                else:
                    continue
            elif (opcode == "exit"):
                sock_send(sock , "GoodBye".encode('utf-8'))
                return

            else:
                # data = ":".join(data)
                # sock_send(sock, data.encode('utf-8'))
                data = "wrong_opcode "+":".join(data)
                sock_send(sock, data.encode('utf-8'))

        except Exception as ex:
        	print("Exception :",ex)
            # sock_send(sock , "Msg Received : {}".format(data).encode('utf-8'))
            
def server(port):
    with socket.socket(socket.AF_INET , socket.SOCK_STREAM) as serv_sock:
        serv_sock.bind(('' , port))
        serv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        serv_sock.listen(5)
        
        print("[+] Listening on Port %d" % port)
        while True:
            try:
                # args = serv_sock.accept()
                th = threading.Thread(target=handle_client , args=serv_sock.accept())
                th.start()
                # th2 = threading.Thread(target=inputThread , args=args)
                # th2.start()
            except KeyboardInterrupt:
                break
            except Exception as e:
                continue
        print("[+] Server Shutdown")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        PORT = 7778
    else:
        try:
            PORT = int(sys.argv[1])
        except ValueError:
            print("[!] Give integer Port")
            exit()
    server(PORT)
