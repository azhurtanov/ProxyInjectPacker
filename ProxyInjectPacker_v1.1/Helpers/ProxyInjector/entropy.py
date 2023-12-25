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
    parser.add_argument('input', metavar="FILE", help='input file')

    parser.add_argument('-o', metavar="FILE", help='output', default="packed.exe")
    parser.add_argument('-s', metavar="SIGCHECK", help='sigcheck', default="Sigcheck.exe")

    args = parser.parse_args()

    # open the unpack.exe binary

    # then create the a .packed section, with the packed PE inside :

    # read the whole file to be packed

  
    loader = lief.PE.parse(args.input)
    file_alignment = loader.optional_header.file_alignment
    section_alignment = loader.optional_header.section_alignment
    
    with open(args.input, "rb") as f:
        input_PE_data = f.read()
    

    with open('e:\\old_develop\\stage\\packer_new\\helpers\\war_and_peace.txt', "r") as f:
                text = f.read()
    data = ' '.join(random.choices(text, k=len(input_PE_data)))
    data = bytes(data,'utf-8')
    text_data = list(data)
    # create the section in lief
    packed_data = list(input_PE_data) + text_data # lief expects a list, not a "bytes" object.
    packed_data = pad_data(packed_data, file_alignment) # pad with 0 to align with file alignment (removes a lief warning)
    packed_section = lief.PE.Section(".fdata")
    packed_section.content =  packed_data
    packed_section.size = len(packed_data)
    packed_section.characteristics = (lief.PE.SECTION_CHARACTERISTICS.MEM_READ
                                    | lief.PE.SECTION_CHARACTERISTICS.CNT_INITIALIZED_DATA)
    # We don't need to specify a Relative Virtual Address here, lief will just put it at the end, that doesn't matter.
    loader.add_section(packed_section)
    #unpack_PE.remove_section(".rsrc")

    # remove the SizeOfImage, which should change, as we added a section. Lief will compute this for us.
    


    # save the resulting PE
    if(os.path.exists(args.o)):
        # little trick here : lief emits no warning when it cannot write because the output
        # file is already opened. Using this function ensure we fail in this case (avoid errors).
        os.remove(args.o)
    
   
    builder = lief.PE.Builder(loader)
    builder.build()
    builder.write(args.o)

    
    size = int(loader.virtual_size/10)
    res = str(os.popen(args.s + " -a " + args.o).read()).split("\n")
    print("[*] Entropy: " + (res[20].split(':')[1].strip()))
    exit(0)
    while(True):
        
        if (float(res[20].split(':')[1])>6):
            
            data = ' '.join(random.choices(text, k=size))
            data = bytes(data,'utf-8')
            text_data = list(data)
    
        
            os.remove(args.o)
            builder = lief.PE.Builder(unpack_PE)
            builder.build()
            builder.write(args.o)
            unpack_PE.remove_section('.orpc')
            size += 20000
            res = str(os.popen("c:\\Apps\\SysInternals\\Sigcheck.exe -a " + args.o).read()).split("\n")
            print("[!] Entropy is too high. Adding .orpc section. Resulting entropy: " + (res[20].split(':')[1].strip()))
        else:
            print("[+] Good entropy: " + (res[20].split(':')[1].strip()) + ". Exiting.")
            if 'text_section' in locals():
                unpack_PE.add_section(text_section)
            
            unpack_PE.remove_section('.fdata')
            unpack_PE.add_section(packed_section)
            unpack_PE.optional_header.sizeof_image = 0
           
            os.remove(args.o)
            builder = lief.PE.Builder(unpack_PE)
            
            builder.build()
            builder.write(args.o)
            break