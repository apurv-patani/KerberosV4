import socket, sys, threading, time, ctypes
from serverKeyData import *
from DES import *

PRca = [65537,
149528699512355331950617158437205689962641679841951287818736694173430524716959483812917461770802212608043328183936552525043568074455738052445050577986833352259236057142049482388687029506718460278289214453416095255584782837301568810229584475388367554929282408185983247040122405879742753398303478073431163051643]
# PRca=[5,2]
# For p,q = 281, 293
Kcv = None
idToKey = {1:"65537,128734038322558840675499639659181884650263093020775590019691518744813102899260812877034992815664262701527457927623580843055438029031627541832027078343761541160533906120675473307461626639667939166648833235027654976370572851921941890307805185701924246363176656595328439882480387604987758970091391355061767317523"
, 2:"65537,146419590359531671922689480690830618587349660996977693253584525470974100095725894689607009560036578111805834367576883813580166659608129392655316573764246272803827366366519291415541385349773303585892709330286653348288658081021486859618921563970726791682119007397041216512553290331679142392395035437585914618109"}

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
                # Ticket tgs = E(K tgs , [K c,tgs || ID C || AD C || ID tgs || TS 2 || Lifetime 2 ])
                print(data)
                ticketV = data[1]
                Kcv,IDc,ADc,IDv,ts4,lf4=decrypt(hexToB(ticketV),keyServ).split("||")
                authenticator = data[2]
                IDc,ADc,ts5 = decrypt(hexToB(authenticator),hexToB(Kcv)).split("||")
                ret = bToHex(encrypt(str(int(ts5)+1),hexToB(Kcv)))
                # ADc = str(list(addr)[0])
                # Kctgs = bToHex(passToKey(getRandStr(10)))
                # mTGS = "||".join([Kctgs,IDc,ADc,IDtgs,str(time.time()),'100'])
                # print(ticketTGS)
                # ticketTGS = bToHex(encrypt(mTGS,keyTGS))
                # print(ticketTGS)
                # mC = "||".join([Kctgs,str(IDtgs),str(time.time()),'100',ticketTGS])
                # ticketC = bToHex(encrypt(mC,keyC))
                # passwd = input("Enter pass: ")
                # passwd = passToKey(passwd)
                # print("passwd",passwd)
                # decrypted = decrypt(hexToB(encrypted),passwd)
                # print(decrypted)
                sock_send(sock, ret.encode('utf-8'))
            elif(opcode=="verifyID"):
                licenseID = decrypt(hexToB(data[1]),hexToB(Kcv))
                license = bToHex(encrypt(licenseData[licenseID],hexToB(Kcv)))
                sock_send(sock, license.encode('utf-8'))
            elif (opcode == "exit"):
                sock_send(sock , "GoodBye".encode('utf-8'))
                return
            elif (opcode == "getPublicKey"):
                # pass
                clientID = int(data[1])
                certificate = str(data[1])+","+idToKey[clientID]+","+str(time.time())
                hashedCerti = customHash(certificate)
                print("hashedCerti",hashedCerti)
                encrypted = encrypt(hashedCerti,PRca[0],PRca[1])
                print(encrypted)
                signedCertificate = certificate+"||"+str(encrypted) 
                print("signedCertificate",type(signedCertificate))
                # val = signedCertificate.encode('utf-8')
                sock_send(sock, signedCertificate.encode('utf-8'))
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
