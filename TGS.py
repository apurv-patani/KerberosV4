import socket, sys, threading, time, ctypes
from TGSKeyData import *
from DES import *

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
            if(opcode=="sgt"):
                IDv = data[1]
                tTGS = decrypt(hexToB(data[2]),keyTGS).split("||")
                # [K c,tgs || IDc || ADc || IDtgs || TS2 || Lifetime2 ]
                Kctgs,IDc,ADc,IDtgs,ts2,lf2 = tTGS
                authenticator = decrypt(hexToB(data[3]),hexToB(Kctgs)).split("||")
                # [IDc || ADc || TS3 ]
                ts3 = float(authenticator[2])
                ts4 = str(time.time())
                Kcv = bToHex(passToKey(getRandStr(10)))
                mV = "||".join([Kcv,IDc,ADc,IDv,ts4,'100'])
                ticketV = bToHex(encrypt(mV,keys[str(IDv)]))
                # E(Kv , [Kc,v || IDc || ADc || IDv || TS4 || Lifetime4 ])
                mCTGS = "||".join([Kcv,IDv,ts4,ticketV])
                # E(Kc,tgs , [Kc,v || IDv || TS4 || Ticketv ])
                retTicket = bToHex(encrypt(mCTGS,hexToB(Kctgs)))
                
                if(time.time()>float(ts2)+float(lf2)):
                    print("TicketTGS expired.")
                    continue
                if(IDc==authenticator[0] and ADc==authenticator[1]
                    and ts3+10>time.time()):
                    print("Client identity verified using authenticator.")
                else:
                    print("Client identity not verified.")
                    continue
                print("Received Kc,tgs:",Kctgs)
                print("Generated SGT:",ticketV)
                sock_send(sock, retTicket.encode('utf-8'))
                
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
