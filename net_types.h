#ifndef NET_TYPES_H
#define NET_TYPES_H

#include <windows.h>

#pragma pack(push)
#pragma pack(1)

// CLR 2.0 header structure.
/*
typedef struct IMAGE_COR20_HEADER
{
    // Информация о версии
    ULONG                   cb;
    USHORT                  MajorRuntimeVersion;
    USHORT                  MinorRuntimeVersion;

    // Таблицы метаданных, флаги и информация о точке входа
    IMAGE_DATA_DIRECTORY    MetaData;
    ULONG                   Flags;
    ULONG                   EntryPointToken;

    IMAGE_DATA_DIRECTORY    Resources;
    IMAGE_DATA_DIRECTORY    StrongNameSignature;

    IMAGE_DATA_DIRECTORY    CodeManagerTable;
    IMAGE_DATA_DIRECTORY    VTableFixups;
    IMAGE_DATA_DIRECTORY    ExportAddressTableJumps;

    // Информация о прекомипилированном образе файла
    // ( только для внутреннего использования )
    IMAGE_DATA_DIRECTORY    ManagedNativeHeader;

} IMAGE_COR20_HEADER;
*/

#define STORAGE_MAGIC_SIG 0x424A5342
#define MAXSTREAMNAME 32

typedef struct _STORAGESIGNATURE
{
    ULONG       lSignature;             // "Магическая" сигнатура (0x424A5342 )
    USHORT      iMajorVer;              // Старшая часть версии файла
    USHORT      iMinorVer;              // Младшая часть версии файла
    ULONG       iExtraData;          // Смещение следующей структуры с информацией
    ULONG       iVersionString;         // Длина строки с названием версии
    BYTE        pVersion[0];            // Строка, содержащая название версии.
}STORAGESIGNATURE, *PSTORAGESIGNATURE;

typedef struct _STORAGEHEADER
{
    BYTE        fFlags;                 // Флаги STGHDR_.
    BYTE        pad;
    USHORT      iStreams;               // Сколько всего стримов используется
}STORAGEHEADER, *PSTORAGEHEADER;

typedef struct _STORAGESTREAM
{
    ULONG       iOffset;                // Смещение потока в файле метаданных
    ULONG       iSize;                  // Размер потока
    CHAR        rcName[MAXSTREAMNAME];  // Начальный символ названия потока
} STORAGESTREAM, *PSTORAGESTREAM;

#pragma pack(pop)

#endif // NET_TYPES_H
