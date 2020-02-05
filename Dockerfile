FROM python:3
RUN mkdir /solution
COPY ids.py /solution/
COPY nstp_v2_pb2.py /solution/
RUN pip3 install protobuf
RUN chmod +x /solution/ids.py /solution/nstp_v2_pb2.py
WORKDIR /solution
#CMD [ "python" , "./ids.py" ]
ENTRYPOINT [ "python", "./ids.py" ]