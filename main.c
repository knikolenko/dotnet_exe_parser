//https://rsdn.ru/article/dotnet/phmetadata.xml
//http://www.ntcore.com/files/dotnetformat.htm
#include <stdio.h>

#include <windows.h>

#include "net_types.h"

#define MAKE_PTR(type, base, offset) ((type)((size_t)(base)+(size_t)(offset)))

static LPSTR g_file_name = TEXT("D:\\Projects\\Csharp\\ScanIB\\ScanIB\\bin\\Debug\\ScanIB.exe");

LPVOID MapMzImage(LPSTR file_name)
{
    SIZE_T addr = (SIZE_T) LoadLibraryExA(file_name, NULL, LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE | LOAD_LIBRARY_AS_IMAGE_RESOURCE);
    return (LPVOID)(addr & (ULONG_MAX - 0xFF));
}

SIZE_T GetFSize(LPSTR file_name)
{
    SIZE_T size = 0;
    HANDLE handle = CreateFileA(file_name,
                                GENERIC_READ,
                                0,
                                NULL,
                                OPEN_EXISTING,
                                FILE_FLAG_SEQUENTIAL_SCAN,
                                NULL);
    if (handle == INVALID_HANDLE_VALUE)
        return 0;

    size = GetFileSize(handle, NULL);
    if (size == INVALID_FILE_SIZE)
    {
        CloseHandle(handle);
        return 0;
    }
    CloseHandle(handle);
    return size;
}

ULONG GetStreamSize(PSTORAGESTREAM stream)
{
    ULONG unaligned_size = (ULONG)(strlen(stream->rcName) + 1 + (sizeof(STORAGESTREAM) - sizeof(stream->rcName)));
    if (unaligned_size % sizeof(ULONG))
    {
        unaligned_size += sizeof(ULONG);
        unaligned_size &= (ULONG_MAX - 3);
    }
    return unaligned_size;
}

SIZE_T PutUserString(SIZE_T offset)
{
    SIZE_T length = 0;
    SIZE_T pos = offset;

    LPWSTR buf = NULL;

    if (!offset)
        return 0;

    length = *(BYTE *)pos;
    //printf("l:%d\n", length);
    pos++;
    if (length & 0x80)
    {
        //puts("-");
        length &= 0x7F;
        length |= (*(BYTE *)pos) << 7;
        pos++;

        if (length & (1 << 14))
        {
            length &= 0x3FFF;
            length |= (*(BYTE *)pos) << 14;
            pos++;
        }
    }
    buf = (LPWSTR)calloc(length + 4, 1);
    if (!buf)
        return (pos - offset) + length;

    memcpy((LPVOID)buf, (LPVOID)pos, length);
    printf("\"%ls\"\n", buf);
    free(buf);

    return (pos - offset) + length;
}

int main(int argc, char **argv)
{
    size_t i = 0;
    size_t stream_size = 0;
    SIZE_T file_size = 0;
    SIZE_T image_size = 0;
    SIZE_T cor_vaddr = 0;
    PIMAGE_DOS_HEADER dos_header = NULL;
    PIMAGE_NT_HEADERS pe_headers = NULL;
    PIMAGE_DATA_DIRECTORY dir_cor2 = NULL;
    PIMAGE_COR20_HEADER cor_header = NULL;

    SIZE_T meta_data_vaddr = 0;
    PSTORAGESIGNATURE stor_sign = NULL;
    PSTORAGEHEADER stor_hdr = NULL;
    PSTORAGESTREAM stor_stream = NULL;

    PSTORAGESTREAM stream_metadata = NULL;
    PSTORAGESTREAM stream_strings = NULL;
    PSTORAGESTREAM stream_user_strings = NULL;
    PSTORAGESTREAM stream_guid = NULL;
    PSTORAGESTREAM stream_blob = NULL;

    GUID *guid = NULL;
    SIZE_T offset = 0;
    SIZE_T limit = 0;
    SIZE_T len = 0;

    if (argc != 2)
    {
        puts("Usage:");
        puts("  net_parser filehame.exe");
        return EXIT_SUCCESS;
    }
    g_file_name = argv[1];

    file_size = GetFSize(g_file_name);
    if (file_size == 0)
    {
        puts("Open file error");
        return EXIT_FAILURE;
    }

    dos_header = MapMzImage(g_file_name);
    if (dos_header == NULL)
        return EXIT_FAILURE;

    if ((dos_header->e_magic != IMAGE_DOS_SIGNATURE) || ((SIZE_T)dos_header->e_lfanew > file_size))
    {
        FreeLibrary((HMODULE)dos_header);
        puts("Is not MZ image");
        return EXIT_FAILURE;
    }

    pe_headers = MAKE_PTR(PIMAGE_NT_HEADERS, dos_header, dos_header->e_lfanew);
    if (pe_headers->Signature != IMAGE_NT_SIGNATURE)
    {
        FreeLibrary((HMODULE)dos_header);
        puts("Is not PE image");
        return EXIT_FAILURE;
    }

    image_size = pe_headers->OptionalHeader.SizeOfImage;

    dir_cor2 = &pe_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR];
    if (dir_cor2->VirtualAddress == 0)
    {
        FreeLibrary((HMODULE)dos_header);
        puts("Not a .NET file");
        return EXIT_FAILURE;
    }
    cor_vaddr = dir_cor2->VirtualAddress;
    if (cor_vaddr > (image_size - sizeof(IMAGE_COR20_HEADER)))
    {
        FreeLibrary((HMODULE)dos_header);
        puts("PE is truncated");
        return EXIT_FAILURE;
    }
    cor_header = MAKE_PTR(PIMAGE_COR20_HEADER, dos_header, cor_vaddr);
    meta_data_vaddr = cor_header->MetaData.VirtualAddress;
    if (meta_data_vaddr > (image_size - sizeof(STORAGESIGNATURE) - sizeof(STORAGEHEADER)))
    {
        FreeLibrary((HMODULE)dos_header);
        puts("PE is truncated");
        return EXIT_FAILURE;
    }

    stor_sign = MAKE_PTR(PSTORAGESIGNATURE, dos_header, meta_data_vaddr);
    if (stor_sign->lSignature != STORAGE_MAGIC_SIG)
    {
        FreeLibrary((HMODULE)dos_header);
        puts("Corrupted MetaData");
        return EXIT_FAILURE;
    }

    printf("[Version]\n%s\n\n", stor_sign->pVersion);

    stor_hdr = MAKE_PTR(PSTORAGEHEADER, stor_sign, sizeof(*stor_sign)+stor_sign->iVersionString);
    stor_stream = MAKE_PTR(PSTORAGESTREAM, stor_hdr, sizeof(*stor_hdr));
    if (stor_hdr->iStreams)
    {
        puts("[Streams]");
        puts("Offset   Size     Name");
        for (i = 0; i < stor_hdr->iStreams; i++)
        {
            printf("%08x %08x %s\n", stor_stream->iOffset, stor_stream->iSize, stor_stream->rcName);

            while (1)
            {
                if (!strcmp(stor_stream->rcName, "#~"))
                {
                    stream_metadata = stor_stream;
                    break;
                }
                if (!strcmp(stor_stream->rcName, "#Strings"))
                {
                    stream_strings = stor_stream;
                    break;
                }
                if (!strcmp(stor_stream->rcName, "#US"))
                {
                    stream_user_strings = stor_stream;
                    break;
                }
                if (!strcmp(stor_stream->rcName, "#GUID"))
                {
                    stream_guid = stor_stream;
                    break;
                }
                if (!strcmp(stor_stream->rcName, "#Blob"))
                {
                    stream_blob = stor_stream;
                    break;
                }
                break;
            } // while

            stor_stream = MAKE_PTR(PSTORAGESTREAM, stor_stream, GetStreamSize(stor_stream));
        } // for ( ... stor_hdr->iStreams ...)

        if (stream_guid)
        {
             guid = MAKE_PTR(GUID *, stor_sign, stream_guid->iOffset);
             printf("\n[GUID]\n%08x-%02x-%02x-%08x\n\n", guid->Data1, guid->Data2, guid->Data3, guid->Data4);
        }

        if (stream_user_strings)
        {
            offset = MAKE_PTR(SIZE_T, stor_sign, stream_user_strings->iOffset);
            stream_size = stream_user_strings->iSize;
            limit = offset + stream_size;

            if (*(BYTE *)offset == 0)
            {
                offset++;
                puts("[User strings]");
                while (1)
                {
                    offset += PutUserString(offset);
                    if (offset >= limit)
                        break;
                }
                puts("");
            }
        }
        if (stream_strings)
        {
            offset = MAKE_PTR(SIZE_T, stor_sign, stream_strings->iOffset);
            stream_size = stream_strings->iSize;
            limit = offset + stream_size;

            if (*(BYTE *)offset == 0)
            {
                offset++;
                puts("[Strings]");
                while (1)
                {
                    // need support unicode
                    len = strlen((LPSTR)offset);
                   // printf("%d %p\n", len, offset);
                    printf("\"%s\"\n", (LPSTR)offset);
                    offset += (len + 1);
                    if (offset >= limit)
                        break;
                }
                puts("");
            }
        }
    } // if (stor_hdr->iStreams)


    return 0;
}

