import time
import pandas as pd
import os

def parse_v1(f, df, label):
    #block_type = f.read(4)
    block_length = f.read(4)
    magic_seq = f.read(4)
    major_ver = f.read(2)
    minor_ver = f.read(2)
    sec_length = f.read(8)
    options = f.read(int.from_bytes(block_length, "little")-28)
    block_length2 = f.read(4)
    
    # Read in interface description block(s)
    b_type = f.read(4)      
    while int.from_bytes(b_type, "little") == 1:

        #i_block_type = f.read(4)
        i_block_length = f.read(4)
        link_type = f.read(2)
        res1 = f.read(2)
        snap_length = f.read(4)
        i_options = f.read(int.from_bytes(i_block_length, "little")-20)
        i_block_length2 = f.read(4)

        b_type = f.read(4)

    f.seek(-4, 1)

    test = []
    last_loc = 0
    # Loop through all packets
    while f.tell() != last_loc:
        last_loc = f.tell()
        # Read in packet header block
        p_block_type = f.read(4)
        p_block_length = int.from_bytes(f.read(4), "little")
        if p_block_length==0:
            break
        interfaceID = f.read(4)
        timestamp1 = f.read(4)
        timestamp2 = f.read(4)
        if p_block_length < 24:
            print("Block length too short?")
            print(p_block_length)
            print(len(test))
            break
        data = f.read(p_block_length-24)
        f.read(4)

        test.append(data)
        
    temp = pd.DataFrame(data=test, columns=["p_bytes"])
    temp["label"] = label
    new_df = pd.concat([df, temp], axis=0)
    new_df.reset_index(drop=True, inplace=True)
    return new_df
    

def parse_v2(f, df, label):
    
    #Read in file header
    version = f.read(4)
    reserves = f.read(8)
    snap_len = f.read(4)
    link_type = f.read(4)
    
    test = []
    last_loc = 0
    while f.tell() != last_loc:
        #Read in packet header
        last_loc = f.tell()
        ts1 = f.read(4)
        ts2 = f.read(4)
        cap_len = f.read(4)
        if int.from_bytes(cap_len, "little") == 0:
            break
        p_len = f.read(4)
        data = f.read(int.from_bytes(cap_len, "little"))
        test.append(data)
        
    temp = pd.DataFrame(data=test, columns=["p_bytes"])
    temp["label"] = label
    new_df = pd.concat([df, temp], axis=0)
    new_df.reset_index(drop=True, inplace=True)
    return new_df
    

def parse_pcap(file_dir, df, label):
    with open(file_dir, "rb") as f:
        
        magic_nums = ["d4c3b2a1"]
        starter = "0a0d0d0a"
        
        first_read = f.read(4)
        #print(first_read.hex())
        if first_read.hex() in magic_nums:
            print("Using v2.4")
            magic_seq = first_read
            return parse_v2(f, df , label)
        elif first_read.hex()==starter:
            print("Using v1.0")
            block_type = first_read
            return parse_v1(f, df, label)
        else:
            print("Unable to detect the pcap file format.")