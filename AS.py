import socket, sys, threading, time, ctypes
from ASKeyData import *
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
            data = data.split("||")
            opcode = data[0].strip()
            if(opcode=="tgt"):
                # Ticket tgs = E(K tgs , [K c,tgs || ID C || AD C || ID tgs || TS 2 || Lifetime 2 ])
                IDc = data[1]
                IDtgs = data[2]
                TS1 = data[3]
                if(time.time()-100>float(TS1)):
                    print("Request expired.")
                    continue
                ADc = str(list(addr)[0])
                Kctgs = bToHex(passToKey(getRandStr(10)))
                #generate key using password
                mTGS = "||".join([Kctgs,IDc,ADc,IDtgs,str(time.time()),'100'])
                ticketTGS = bToHex(encrypt(mTGS,keyTGS))
                # E(Ktgs , [K c,tgs || IDc || ADc || IDtgs || TS2 || Lifetime2 ])
                print("Generated ticketTGS:",ticketTGS)
                mC = "||".join([Kctgs,str(IDtgs),str(time.time()),'100',ticketTGS])
                ret = bToHex(encrypt(mC,keyC))
                # E(Kc , [Kc,tgs || IDtgs || TS2 || Lifetime2 || Tickettgs])
                sock_send(sock, ret.encode('utf-8'))

            elif (opcode == "exit"):
                sock_send(sock , "GoodBye".encode('utf-8'))
                return

            else:
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
