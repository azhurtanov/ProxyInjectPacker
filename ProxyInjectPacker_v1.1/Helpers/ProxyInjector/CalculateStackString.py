import sys
from struct import pack
from keystone import *

def print_assembly(array):
    print("\" mov rax, 0x" + array.encode('ascii').hex() + ";\"\r\n\" push rax;\"")
    
def get_chunks(l, n):
    for i in range(0, len(l), n): 
        yield l[i:i + n]

if __name__ == '__main__':
    try:
        esi = sys.argv[1]
    except IndexError:
        print("Usage: %s INPUTSTRING" % sys.argv[0])
        sys.exit()


    array = sys.argv[1]#, 'ascii'
    chunks = list(get_chunks(array, 8))[::-1]
    #print_assembly(chunks[0][::-1])
    #exit(0)
    for i in chunks:
        print_assembly(i[::-1])
        #print(print_assembly(i))
        #exit()
        #print_assembly(i)
    


