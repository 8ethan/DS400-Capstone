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

    all_bytes = []
    timestamps = []
    src_ips = []
    src_ports = []
    dst_ips = []
    dst_ports = []
    protos = [1,6,17] # Acceptable protocols (ICMP, TCP, UDP)
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
        ts1 = f.read(4)
        ts2 = f.read(4)
        ts_actual = (int.from_bytes(ts1, "little") << 32)|(int.from_bytes(ts2, "little"))
        cap_len = f.read(4)
        p_len = f.read(4)
        if p_block_length < 32:
            print("Block length too short?")
            print(p_block_length)
            print(len(test))
            break
        data = f.read(p_block_length-32)
        f.read(4)
        
        # Only include packet if its from outside source, ipv4, and TCP/UDP/ICMP protocol
        #if data[1] != 4 and data[16]!=96 and data[25] in protos:
        timestamps.append(round(ts_actual/1000000))
        src_ips.append( str(data[28])+"."+str(data[29])+"."+str(data[30])+"."+str(data[31]) )
        dst_ips.append( str(data[32])+"."+str(data[33])+"."+str(data[34])+"."+str(data[35]) )
        src_ports.append(int.from_bytes(data[36:38],"big"))
        dst_ports.append(int.from_bytes(data[38:40],"big"))
        all_bytes.append(data)
            
        
    temp = pd.DataFrame(data=all_bytes, columns=["p_bytes"])
    temp["label"] = label
    temp["pcap_ver"] = 1
    temp["ts"] = timestamps
    temp["src_ip"] = src_ips
    temp["dst_ip"] = dst_ips
    temp["src_port"] = src_ports
    temp["dst_port"] = dst_ports
    new_df = pd.concat([df, temp], axis=0)
    new_df.reset_index(drop=True, inplace=True)
    return new_df
    

def parse_v2(f, df, label):
    
    #Read in file header
    version = f.read(4)
    reserves = f.read(8)
    snap_len = f.read(4)
    link_type = f.read(4)
    
    all_bytes = []
    timestamps = []
    src_ips = []
    src_ports = []
    dst_ips = []
    dst_ports = []
    protos = [1,6,17] # Acceptable protocols (ICMP, TCP, UDP)
    last_loc = 0
    while f.tell() != last_loc:
        #Read in packet header
        last_loc = f.tell()
        ts1 = f.read(4)
        ts2 = f.read(4)
        cap_len = f.read(4)
        #if int.from_bytes(cap_len, "little") == 0:
        #    break
        p_len = f.read(4)
        data = f.read(int.from_bytes(cap_len, "little"))
        
        # Only include packet if its from outside source, ipv4, and TCP/UDP/ICMP protocol
        #if data[1] != 4 and data[16]!=96 and data[25] in protos:
        if len(data) > 0:
            timestamps.append( round( int.from_bytes(ts1, "little")+(int.from_bytes(ts2, "little")/1000000) ) )
            src_ips.append( str(data[28])+"."+str(data[29])+"."+str(data[30])+"."+str(data[31]) )
            dst_ips.append( str(data[32])+"."+str(data[33])+"."+str(data[34])+"."+str(data[35]) )
            src_ports.append(int.from_bytes(data[36:38], "big"))
            dst_ports.append(int.from_bytes(data[38:40], "big"))
            all_bytes.append(data)
        
    temp = pd.DataFrame(data=all_bytes, columns=["p_bytes"])
    temp["label"] = label
    temp["ts"] = timestamps
    temp["src_ip"] = src_ips
    temp["dst_ip"] = dst_ips
    temp["src_port"] = src_ports
    temp["dst_port"] = dst_ports
    temp["pcap_ver"] = 2
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