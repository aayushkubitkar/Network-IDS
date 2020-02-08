import socket
import os
import nstp_v2_pb2
import struct

def app_len(data):
    return struct.pack(f'!H{len(data)}s', len(data), data)
server_address='./tmp/ids_socket'
try:
    os.unlink(server_address)
except OSError:
    if os.path.exists(server_address):
        raise
sock=socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.bind(server_address)
sock.listen(1)

while True:
    print('waiting for a connection')
    connection, client_address = sock.accept()
    try:
        # conn establish
        for i in range(24):
            msg = nstp_v2_pb2.IDSMessage()
            ids_event = nstp_v2_pb2.IDSEvent()
            ids_event.event_id = 1+i
            ids_event.client_to_server = True
            ids_event.server_address=b'192.168.1.1'
            ids_event.server_port=1234
            ids_event.remote_address=b'192.168.1.2'
            ids_event.remote_port=1111+i
            conn_est=nstp_v2_pb2.ConnectionEstablished()
            ids_event.connection_established.CopyFrom(conn_est)
            msg.event.CopyFrom(ids_event)
            connection.sendall(app_len(msg.SerializeToString()))
            i=0

        msg = nstp_v2_pb2.IDSMessage()
        ids_event = nstp_v2_pb2.IDSEvent()
        ids_event.event_id = 1
        ids_event.client_to_server = True
        ids_event.server_address = b'192.168.1.1'
        ids_event.server_port = 1234
        ids_event.remote_address = b'192.168.1.3'
        ids_event.remote_port = 1111
        conn_est = nstp_v2_pb2.ConnectionEstablished()
        ids_event.connection_established.CopyFrom(conn_est)
        msg.event.CopyFrom(ids_event)
        connection.sendall(app_len(msg.SerializeToString()))

        while True:
            data = connection.recv(1024)
            if data:
                ids_msg = nstp_v2_pb2.IDSMessage()
                len_msg = struct.unpack('!H', data[:2])
                ids_msg.ParseFromString(data[2:2 + len_msg[0]])
                print(ids_msg)


        #initialize
        print('connection from', client_address)
        message = b'This is the message.'
        msg = nstp_v2_pb2.IDSMessage()
        ids_event = nstp_v2_pb2.IDSEvent()
        ids_event.event_id = 2
        ids_event.client_to_server = True
        ch=nstp_v2_pb2.ClientHello()
        ch.major_version=2
        ch.minor_version=2
        ch.user_agent="mozilla"
        ids_event.client_hello.CopyFrom(ch)
        msg.event.CopyFrom(ids_event)
        connection.sendall(app_len(msg.SerializeToString()))
        data = connection.recv(1024)
        ids_msg = nstp_v2_pb2.IDSMessage()
        len_msg = struct.unpack('!H', data[:2])
        ids_msg.ParseFromString(data[2:2 + len_msg[0]])
        print(ids_msg)

        #store
        ids_event=nstp_v2_pb2.IDSEvent()
        ids_event.event_id=3
        ids_event.client_to_server=True
        ce=nstp_v2_pb2.StoreRequest()
        ce.key='../abc/'
        ce.value=b'abc'
        ids_event.store_request.CopyFrom(ce)
        msg.event.CopyFrom(ids_event)
        connection.sendall(app_len(msg.SerializeToString()))
        data = connection.recv(1024)
        ids_msg = nstp_v2_pb2.IDSMessage()
        len_msg = struct.unpack('!H', data[:2])
        ids_msg.ParseFromString(data[2:2+len_msg[0]])
        print(ids_msg)


        #load
        ids_event = nstp_v2_pb2.IDSEvent()
        ids_event.event_id = 4
        ids_event.client_to_server = True
        ce = nstp_v2_pb2.LoadRequest()
        ce.key = '../abc/'
        ids_event.load_request.CopyFrom(ce)
        msg.event.CopyFrom(ids_event)
        connection.sendall(app_len(msg.SerializeToString()))
        data = connection.recv(1024)
        ids_msg = nstp_v2_pb2.IDSMessage()
        len_msg = struct.unpack('!H', data[:2])
        ids_msg.ParseFromString(data[2:2 + len_msg[0]])
        print(ids_msg)

    finally:
        connection.close()