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
    global shift,PUother, clientID
    sock = None
    while True:
        try:
            tokens = input(">> ").split(" ")
            data =tokens[0].strip()
            # data = tokens[0]
            if(data=="as"):
                global IDtgs
                # IDc || IDtgs || TS 1
                toSend = "||".join(["auth",str(ID), str(IDtgs), str(time.time())])
                print(toSend)
                sock_send(sock , toSend.encode('utf-8'))
                recv = sock.recv(4096).decode('utf-8')
                recv = hexToB(recv)
                print("recv",recv)
                passwd = input("Enter pass: ")
                passwd = passToKey(passwd)
                decrypted = decrypt(recv,passwd).split("||")
                Kctgs,IDtgs,TS2,lf2,tTGS = decrypted
                Kctgs = hexToB(Kctgs)
                # print(decrypted)
                # tokens = decrypted.split("||")
            elif (data == "tgs"):
                mAuth = "||".join([str(ID),IP,str(time.time())])
                authenticator = bToHex(encrypt(mAuth,Kctgs))
                toSend = "||".join(["auth","3",str(tTGS), authenticator])
                print(toSend)
                sock_send(sock ,toSend.encode('utf-8'))
                recv = sock.recv(4096).decode('utf-8')
                Kcv,IDv,ts4,ticketV=decrypt(hexToB(recv),Kctgs).split("||")
                print(Kcv,IDv,ts4,ticketV)
            elif(data == "server"):
                ts5 = str(int(time.time()))
                print("ts5:",ts5)
                mAuth = "||".join([str(ID),str(IP),ts5])
                authenticator = bToHex(encrypt(mAuth,hexToB(Kcv)))
                mV = "||".join(["auth",ticketV,authenticator])
                print(mV)
                sock_send(sock ,mV.encode('utf-8'))
                recv = sock.recv(4096).decode('utf-8')
                ack = decrypt(hexToB(recv),hexToB(Kcv))
                print(ack)
            elif(data=="verifyID"):
                encrypted = bToHex(encrypt(tokens[1],hexToB(Kcv)))
                toSend = "||".join([tokens[0],encrypted])
                sock_send(sock ,toSend.encode('utf-8'))
                recv = sock.recv(4096).decode('utf-8')
                license = decrypt(hexToB(recv),hexToB(Kcv)).split("||")
                print("License No.:",license[0])
                print("Name:",license[1])
                print("Validity:",license[2]=="1")
                print("Vehicle Type:",license[3])
            elif(data == "c"):
                host = '192.168.1.9'
                port = tokens[1]
                print("[+] Connecting to {}:{}".format(host , port))
                sock = tcp_connect(host , port)
                if sock is  None:
                    print("Connection Failed")
                    return
                print(sock)
                print("[+] Connection to {}:{} Succeded".format(host , port))
            elif(data == "get"):
                data=("getPublicKey:"+tokens[1]).encode('utf-8')
                # print("[+] Sent",str(data))
                sock_send(sock , data)
                recv = sock.recv(4096).decode('utf-8')
                tokens = recv.split("||")
                print(recv)
                # print("tokens[1]",tokens[1])
                certi = tokens[0]
                hashedCerti = decrypt(tokens[1].strip(),PUca[0],PUca[1])
                # print("hashedCerti",hashedCerti)
                # print("certi",certi)
                if(customHash(certi)==int(hashedCerti)):
                    print("Signature Verified.")
                else:
                    print("Signature NOT verified.")
                tokens = certi.split(",")
                PUother = [int(tokens[1]),int(tokens[2])]
                print("[+] Received Certificate :",certi)
            elif(data == "hello"):
                data = ":".join(tokens)
                print("Sending data",data)
                encrypted = encrypt(data,PUother[0],PUother[1])
                sock_send(sock ,encrypted.encode('utf-8'))
                recv = sock.recv(4096).decode('utf-8')
                decrypted = decrypt(recv.strip(),PRa[0],PRa[1])
                decrypted = str(hex(decrypted))[2:]
                decrypted = (bytearray.fromhex(decrypted)).decode()
                print("[+] Received",decrypted)
            elif(data == "startServer"):
                port = 7773
                # if(len(tokens)>1):
                    # port = tokens[-1]
                
                try:
                    data = "exit".encode('utf-8')
                    sock_send(sock , data)
                    recv = sock.recv(4096).decode('utf-8')
                    sock.close()
                except:
                   pass
                th = threading.Thread(target=server , args=[port])
                th.start()

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
