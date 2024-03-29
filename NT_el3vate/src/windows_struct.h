#pragma once
#include <Windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <stdint.h>

#define PHYSICAL_ADDRESS	LARGE_INTEGER
#define SystemModuleInformation (SYSTEM_INFORMATION_CLASS)0x0B

//Source: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_cm_partial_resource_descriptor
//slide modifications were made in comparison to msdn
typedef LARGE_INTEGER PHYSICAL_ADDRESS, * PPHYSICAL_ADDRESS;

#if defined(__clang__)
#pragma clang diagnostic ignored "-Wpragma-pack"
#endif

extern unsigned __int64 _EPROCESS_ImageFileName_offset;
extern unsigned __int64 _EPROCESS_UniqueProcessId_offset;
extern unsigned __int64 _EPROCESS_Token_offset;

// Source: https://git.back.engineering/_xeroxz/VDM/src/branch/master/VDM/util/util.hpp
#pragma pack (push, 1)
struct PhysicalMemoryPage//CM_PARTIAL_RESOURCE_DESCRIPTOR
{
    uint8_t type;
    uint8_t shareDisposition;
    uint16_t flags;
    uint64_t pBegin;
    uint32_t sizeButNotExactly;
    uint32_t pad;
    static constexpr uint16_t cm_resource_memory_large_40{ 0x200 };
    static constexpr uint16_t cm_resource_memory_large_48{ 0x400 };
    static constexpr uint16_t cm_resource_memory_large_64{ 0x800 };
    uint64_t size()const noexcept
    {
        if (flags & cm_resource_memory_large_40)
            return uint64_t{ sizeButNotExactly } << 8;
        else if (flags & cm_resource_memory_large_48)
            return uint64_t{ sizeButNotExactly } << 16;
        else if (flags & cm_resource_memory_large_64)
            return uint64_t{ sizeButNotExactly } << 32;
        else
            return uint64_t{ sizeButNotExactly };
    }
};
static_assert(sizeof(PhysicalMemoryPage) == 20, "PhysicalMemoryPage size is wrong\n");
#pragma pack (pop)

#pragma pack(push,4)
typedef struct _CM_PARTIAL_RESOURCE_DESCRIPTOR {
    UCHAR Type;
    UCHAR ShareDisposition;
    USHORT Flags;
    union {
        struct {
            PHYSICAL_ADDRESS Start;
            ULONG Length;
        } Generic;
        struct {
            PHYSICAL_ADDRESS Start;
            ULONG Length;
        } Port;
        struct {
#if defined(NT_PROCESSOR_GROUPS)
            USHORT Level;
            USHORT Group;
#else
            ULONG Level;
#endif
            ULONG Vector;
            KAFFINITY Affinity;
        } Interrupt;
        struct {
            union {
                struct {
#if defined(NT_PROCESSOR_GROUPS)
                    USHORT Group;
#else
                    USHORT Reserved;
#endif
                    USHORT MessageCount;
                    ULONG Vector;
                    KAFFINITY Affinity;
                } Raw;
                struct {
#if defined(NT_PROCESSOR_GROUPS)
                    USHORT Level;
                    USHORT Group;
#else
                    ULONG Level;
#endif
                    ULONG Vector;
                    KAFFINITY Affinity;
                } Translated;
            } DUMMYUNIONNAME;
        } MessageInterrupt;
        struct {
            PHYSICAL_ADDRESS Start;
            ULONG Length;
        } Memory;
        struct {
            ULONG Channel;
            ULONG Port;
            ULONG Reserved1;
        } Dma;
        struct {
            ULONG Channel;
            ULONG RequestLine;
            UCHAR TransferWidth;
            UCHAR Reserved1;
            UCHAR Reserved2;
            UCHAR Reserved3;
        } DmaV3;
        struct {
            ULONG Data[3];
        } DevicePrivate;
        struct {
            ULONG Start;
            ULONG Length;
            ULONG Reserved;
        } BusNumber;
        struct {
            ULONG DataSize;
            ULONG Reserved1;
            ULONG Reserved2;
        } DeviceSpecificData;
        struct {
            PHYSICAL_ADDRESS Start;
            ULONG Length40;
        } Memory40;
        struct {
            PHYSICAL_ADDRESS Start;
            ULONG Length48;
        } Memory48;
        struct {
            PHYSICAL_ADDRESS Start;
            ULONG Length64;
        } Memory64;
        struct {
            UCHAR Class;
            UCHAR Type;
            UCHAR Reserved1;
            UCHAR Reserved2;
            ULONG IdLowPart;
            ULONG IdHighPart;
        } Connection;
    } u;
} CM_PARTIAL_RESOURCE_DESCRIPTOR, * PCM_PARTIAL_RESOURCE_DESCRIPTOR;
#pragma pack(pop)


//Source: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_cm_partial_resource_list
typedef struct _CM_PARTIAL_RESOURCE_LIST {
    USHORT                         Version;
    USHORT                         Revision;
    ULONG                          Count;
    CM_PARTIAL_RESOURCE_DESCRIPTOR PartialDescriptors[1];
} CM_PARTIAL_RESOURCE_LIST, * PCM_PARTIAL_RESOURCE_LIST;


//Source: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ne-wdm-_interface_type
typedef enum _INTERFACE_TYPE {
    InterfaceTypeUndefined,
    Internal,
    Isa,
    Eisa,
    MicroChannel,
    TurboChannel,
    PCIBus,
    VMEBus,
    NuBus,
    PCMCIABus,
    CBus,
    MPIBus,
    MPSABus,
    ProcessorInternal,
    InternalPowerBus,
    PNPISABus,
    PNPBus,
    Vmcs,
    ACPIBus,
    MaximumInterfaceType
} INTERFACE_TYPE, * PINTERFACE_TYPE;

//Source: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_cm_full_resource_descriptor
typedef struct _CM_FULL_RESOURCE_DESCRIPTOR {
    INTERFACE_TYPE           InterfaceType;
    ULONG                    BusNumber;
    CM_PARTIAL_RESOURCE_LIST PartialResourceList;
} CM_FULL_RESOURCE_DESCRIPTOR, * PCM_FULL_RESOURCE_DESCRIPTOR;

//Source: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_cm_resource_list
typedef struct _CM_RESOURCE_LIST {
    ULONG                       Count;
    CM_FULL_RESOURCE_DESCRIPTOR List[1];
} CM_RESOURCE_LIST, * PCM_RESOURCE_LIST;


typedef struct IOCTL_buffer
{
    void* SectionHandle;
    DWORD offset;
    unsigned int BusAddress;
    PVOID PhysicalBaseAddress;
} IOCTL_buffer;


typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;
//source: https://processhacker.sourceforge.io/doc/ntldr_8h_source.html

typedef struct MEMORY_REGION
{
    unsigned __int64 address;
    unsigned __int64 size;
} MEMORY_REGION;
