#ifndef NET_TYPES_H
#define NET_TYPES_H

#include <windows.h>

#pragma pack(push)
#pragma pack(1)

// CLR 2.0 header structure.
/*
typedef struct IMAGE_COR20_HEADER
{
    // ���������� � ������
    ULONG                   cb;
    USHORT                  MajorRuntimeVersion;
    USHORT                  MinorRuntimeVersion;

    // ������� ����������, ����� � ���������� � ����� �����
    IMAGE_DATA_DIRECTORY    MetaData;
    ULONG                   Flags;
    ULONG                   EntryPointToken;

    IMAGE_DATA_DIRECTORY    Resources;
    IMAGE_DATA_DIRECTORY    StrongNameSignature;

    IMAGE_DATA_DIRECTORY    CodeManagerTable;
    IMAGE_DATA_DIRECTORY    VTableFixups;
    IMAGE_DATA_DIRECTORY    ExportAddressTableJumps;

    // ���������� � ������������������� ������ �����
    // ( ������ ��� ����������� ������������� )
    IMAGE_DATA_DIRECTORY    ManagedNativeHeader;

} IMAGE_COR20_HEADER;
*/

#define STORAGE_MAGIC_SIG 0x424A5342
#define MAXSTREAMNAME 32

typedef struct _STORAGESIGNATURE
{
    ULONG       lSignature;             // "����������" ��������� (0x424A5342 )
    USHORT      iMajorVer;              // ������� ����� ������ �����
    USHORT      iMinorVer;              // ������� ����� ������ �����
    ULONG       iExtraData;          // �������� ��������� ��������� � �����������
    ULONG       iVersionString;         // ����� ������ � ��������� ������
    BYTE        pVersion[0];            // ������, ���������� �������� ������.
}STORAGESIGNATURE, *PSTORAGESIGNATURE;

typedef struct _STORAGEHEADER
{
    BYTE        fFlags;                 // ����� STGHDR_.
    BYTE        pad;
    USHORT      iStreams;               // ������� ����� ������� ������������
}STORAGEHEADER, *PSTORAGEHEADER;

typedef struct _STORAGESTREAM
{
    ULONG       iOffset;                // �������� ������ � ����� ����������
    ULONG       iSize;                  // ������ ������
    CHAR        rcName[MAXSTREAMNAME];  // ��������� ������ �������� ������
} STORAGESTREAM, *PSTORAGESTREAM;

#pragma pack(pop)

#endif // NET_TYPES_H
