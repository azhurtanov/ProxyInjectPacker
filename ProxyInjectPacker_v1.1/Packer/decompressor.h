#pragma once

#include "functions.h"
#ifdef _DEBUG
#include <stdio.h>
#endif

#define META_DATA_SIZE (2 * sizeof(ULONG))


PVOID SimpleAlloc(PVOID Context, SIZE_T Size)
{
    UNREFERENCED_PARAMETER(Context);
    return malloc(Size);
}

VOID SimpleFree(PVOID Context, PVOID Memory)
{
    UNREFERENCED_PARAMETER(Context);
    if (Memory != NULL)
    {
        free(Memory);
    }
    return;
}


BOOL BlockModeDecompress(
    _In_ PBYTE InputData,
    _In_ DWORD InputSize,
    _Deref_out_opt_ PBYTE* OutputData,
    _Out_ DWORD* DecompressedSize
)
{
    DECOMPRESSOR_HANDLE Decompressor = NULL;
    DWORD ProcessedSoFar = 0;
    DWORD CompressedBlockSize = 0;
    DWORD UncompressedBlockSize = 0;
    DWORD DecompressedSoFar = 0;
    DWORD OutputDataSize = 0;
    BOOL Success = FALSE;

    COMPRESS_ALLOCATION_ROUTINES AllocationRoutines;

    //  Init. allocation routines
    AllocationRoutines.Allocate = SimpleAlloc;
    AllocationRoutines.Free = SimpleFree;
    AllocationRoutines.UserContext = NULL;

    *DecompressedSize = 0;
    *OutputData = NULL;
    
    //  Create a LZMS decompressor and set to Block mode.
    Success = CreateDecompressor(
        COMPRESS_ALGORITHM_LZMS | COMPRESS_RAW,   //  Compression algorithm is LZMS
        &AllocationRoutines,                    //  Memory allocation routines
        &Decompressor);                         //  handle
    
    if (!Success)
    {
#ifdef _DEBUG
        printf("[-] Cannot create decompressor handle: %d\n", GetLastError());
#endif
        
    }
    
    //  Read uncompressed size
    ProcessedSoFar = 0;
    OutputDataSize = *((ULONG UNALIGNED*)(InputData + ProcessedSoFar));
    ProcessedSoFar += sizeof(ULONG);

    *OutputData = (PBYTE)malloc(OutputDataSize);
    
   
    
    if (!*OutputData)
    {
#ifdef _DEBUG
        printf("Cannot allocate memory for uncompressed buffer.\n");
#endif
        Success = FALSE;
        exit(0);
    }
    
    //  Decompress data block by block.
    while (ProcessedSoFar < InputSize)
    {
       
        
        if (ProcessedSoFar + META_DATA_SIZE > InputSize)
        {
            Success = FALSE;
#ifdef _DEBUG
            printf("[-] Data corrupt (1).\n");
#endif
            exit(0);
        }
        
        //  Read block information.
        CompressedBlockSize = *((ULONG UNALIGNED*)(InputData + ProcessedSoFar));
        ProcessedSoFar += sizeof(ULONG);
        UncompressedBlockSize = *((ULONG UNALIGNED*)(InputData + ProcessedSoFar));
        ProcessedSoFar += sizeof(ULONG);

        
        if (ProcessedSoFar + CompressedBlockSize > InputSize)
        {
            if (Decompressor != NULL)
            {
                _CloseDecompressor(Decompressor);
                return Success;
            }
        }
        
        

        if (DecompressedSoFar + UncompressedBlockSize > OutputDataSize)
        {
            Success = FALSE;
#ifdef _DEBUG
            printf("[-] Output buffer not enough to hold decompressed data.\n");
#endif
            exit(0);
        }
        
        //  Decompress a block
        Success = Decompress(
            Decompressor,                   //  Decompressor Handle
            InputData + ProcessedSoFar,     //  Compressed data
            CompressedBlockSize,            //  compressed data size
            *OutputData + DecompressedSoFar, //  Start of decompressed buffer
            UncompressedBlockSize,          //  Uncompressed block size
            NULL);                          //  Decompressed data size
        
        if (!Success)
        {
#ifdef _DEBUG
            printf("[-] Decompression failure: %d\n", GetLastError());
#endif
            exit(0);
        }
        
        ProcessedSoFar += CompressedBlockSize;
        DecompressedSoFar += UncompressedBlockSize;
        
       
    }

    *DecompressedSize = DecompressedSoFar;


    
   
}

PBYTE DecompressData(PBYTE CompressedBuffer, DWORD InputSize)
{

    
#ifdef _DEBUG
    printf("[*] Decompressing data.\r\n");
#endif 
   

    PBYTE DecompressedBuffer = NULL;

    BOOL DeleteTargetFile = TRUE;
    BOOL Success;
    DWORD DecompressedDataSize;

    
    //  Decompress data and write data to DecompressedBuffer.
    Success = BlockModeDecompress(
        CompressedBuffer,           //  Compressed data
        InputSize,              //  Compressed data size
        &DecompressedBuffer,        //  Decompressed buffer        
        &DecompressedDataSize);     //  Decompressed data sizes

    return DecompressedBuffer;
}
