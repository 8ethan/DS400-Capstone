import socket
import os.path
import time


def send_pe_data(file_dir):
    #SEND PE DATA
    hostname = "adal.etown.edu"
    port = 42069

    for i in range(100): 
        try:
            s = socket.socket()
            s.connect((hostname,port))
            print("Socket connected to ", hostname)
        except:
            print("Error connecting to socket.")
            return

        try:
            file_data = open(file_dir, "rb").read()
            #print(file_data)
            test_val = s.send(file_data)
            print("Sent ",test_val)
            print("Sent PE data.")
            s.close()
        except:
            print("Error sending file")
        time.sleep(0.1)
        

send_pe_data('/home/ethan/Desktop/DS420/FinalProject/test_pes/putty.exe')