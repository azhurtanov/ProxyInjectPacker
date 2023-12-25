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
    array = sys.argv[1]
    array2 = ''
    for i in array:
        array2 += i + "\x00"
    chunks = list(get_chunks(array2, 8))[::-1]
    for i in chunks:
        print_assembly(i[::-1])
    


