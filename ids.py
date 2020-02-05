import socket
import sys
import nstp_v2_pb2
import struct

def handleNewConn(ids_event, conn, sock):
    print ("inside conn established")
    try:
        if ids_event.remote_address in listIpConn.keys():
            if len(listIpConn[ids_event.remote_address])<=25:
                listIpConn[ids_event.remote_address].append(conn)
                sendIDSDecision(ids_event, True, sock)
            else:
                print ("DoS advisory detected")
                sendDecision(ids_event, False, sock)
                closeConnection(ids_event.remote_address, sock)
        else:
            print ("first connection from IP")
            listIpConn[ids_event.remote_address]=[conn]
            sendIDSDecision(ids_event, True, sock)
    except KeyError:
        print ("key exception")

def handleTerminateConn(ids_event, conn, sock):
    print ("inside terminate conn")
    sendIDSTerminateConn(conn, sock)

def handleClientHello(ids_event, conn, sock):
    print("inside client hello")
    if conn not in clientInit:
        clientInit[conn] = 1
        cHello = nstp_v2_pb2.ClientHello()
        cHello.CopyFrom(ids_event.client_hello)
        if cHello.major_version != 2:
            sendIDSDecision(ids_event, False, sock)
        else:
            print("client initialized")
            sendIDSDecision(ids_event, True, sock)
    else:
        print("out of spec")
        sendIDSDecision(ids_event, False, sock)

def handlePingReq(ids_event, conn, sock):
    print("inside ping req")
    try:
        if clientInitialized(conn):
            pingReq=nstp_v2_pb2.PingRequest()
            if pingReq.hash_algorithm>=0 and pingReq.hash_algorithm<=2:
                sendIDSDecision(ids_event, True,sock)
            else:
                sendIDSDecision(ids_event, False, sock)
    except KeyError:
        print ("out of spec detected")
        sendIDSDecision(ids_event, False, sock)

def handleStoreReq(ids_event, conn, sock):
    print("inside store req")
    if clientInitialized(conn):
        storeReq = nstp_v2_pb2.StoreRequest()
        storeReq.CopyFrom(ids_event.store_request)
        if len(bytes(storeReq.key, "utf-8")) < 512:
            if checkKeyPath(storeReq.key):
                sendIDSDecision(ids_event, True, sock)
            else:
                sendIDSDecision(ids_event, False, sock)
        else:
            print("Overflow advisory detected")
            sendIDSDecision(ids_event, False, sock)
    else:
        print("out of spec detected")
        sendIDSDecision(ids_event, False, sock)


def handleLoadReq(ids_event, conn, sock):
    print ("inside load req")
    if clientInitialized(conn):
        loadReq=nstp_v2_pb2.LoadRequest()
        loadReq.CopyFrom(ids_event.load_request)
        if checkKeyPath(loadReq.key):
            sendIDSDecision(ids_event, True, sock)
        else:
            sendIDSDecision(ids_event, False, sock)
    else:
        print("out of spec detected")
        sendIDSDecision(ids_event, False, sock)

def append_len(data):
    return struct.pack(f'!H{len(data)}s', len(data), data)

def clientInitialized(conn):
    try:
        if clientInit[conn]==1:
            return True
        else:
            return False
    except KeyError:
        print ("Key error")
        return False

def closeConnection(ip, sock):
    lstConn=listIpConn[ip]
    del listIpConn[ip]
    for val in lstConn:
        sendIDSTerminateConn(val, sock)

def sendIDSDecision(ids_event, decision, sock):
    print (decision)
    ids_des=nstp_v2_pb2.IDSDecision()
    ids_des.event_id=ids_event.event_id
    ids_des.allow=decision
    msg = nstp_v2_pb2.IDSMessage()
    msg.decision.CopyFrom(ids_des)
    sock.sendall(append_len(msg.SerializeToString()))

def sendIDSTerminateConn(conn, sock):
    ids_ter=nstp_v2_pb2.IDSTerminateConnection()
    ids_ter.address_family= conn[0]
    ids_ter.address_family = conn[1]
    ids_ter.address_family = conn[2]
    ids_ter.address_family = conn[3]
    ids_ter.address_family = conn[4]
    msg=nstp_v2_pb2.IDSMessage()
    msg.terminate_connection.CopyFrom(ids_ter)
    sock.sendall(append_len(msg.SerializeToString()))

def checkKeyPath(key):
    print("handle path traversals")
    if key[0]=='/' or key[0:2]=='..' or key[0:4]=='./..':
        return False
    else:
        depth=0
        if len(key)>0:
            for i in range(0, len(key)-1):
                if key[i]!='/' and key[i]!='.' and key[i+1]=='/':
                    depth=depth+1
                elif key[i]=='.' and key[i+1]=='.':
                    depth=depth-1
                if depth < 0:
                    break
        if depth < 0:
            return False
        else:
            return True

# Create a UDS socket
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

# Connect the socket to the socket file where the server is listening
server_address = sys.argv[1]
# server_address = '/tmp/nstp_ids.socket'
# server_address = './tmp/ids_socket'
print('connecting to {}'.format(server_address))
try:
    sock.connect(server_address)
except socket.error as msg:
    print(msg)
    sys.exit(1)
clientInit={}
listIpConn={}
try:
    while True:
        data = sock.recv(1024)
        if data:
            ids_msg = nstp_v2_pb2.IDSMessage()
            len_msg = struct.unpack('!H', data[:2])
            ids_msg.ParseFromString(data[2:2+len_msg[0]])
            print (ids_msg)
            #ids_event=nstp_v2_pb2.IDSMessage()
            ids_event= nstp_v2_pb2.IDSEvent()
            ids_event.CopyFrom(ids_msg.event)
            #print (ids_event)
            if ids_event.client_to_server:
                switcher = {
                    'connection_established': handleNewConn,
                    'connection_terminated': handleTerminateConn,
                    'client_hello': handleClientHello,
                    'ping_request': handlePingReq,
                    'store_request': handleStoreReq,
                    'load_request': handleLoadReq
                }
                print (ids_event.WhichOneof("event"))
                func = switcher.get(ids_event.WhichOneof("event"))
                conn = (ids_event.address_family, ids_event.server_address, ids_event.server_port, ids_event.remote_address,ids_event.remote_port)
                func(ids_event,conn,sock)
            else:
                print("message from server to client")
                sendIDSDecision(ids_event, True, sock)
        else:
            print("no data from server")
            break
finally:
    sock.close()