#ifndef HEADERS_H
#define HEADERS_H

#pragma pack(push,1)
typedef struct generic_exe_header
{
    unsigned char id[2];
    unsigned short bytes_in_last_block;
    unsigned short blocks_in_file;
    unsigned short num_relocs;
    unsigned short header_paragraphs;
    unsigned short min_extra_paragraphs;
    unsigned short max_extra_paragraphs;
    unsigned short ss;
    unsigned short sp;
    unsigned short checksum;
    unsigned short ip;
    unsigned short cs;
    unsigned short reloc_table_offset;
    unsigned short overlay_number;
}generic_header;
#pragma pack(pop)
#pragma pack(push,1)
typedef struct ext_header
{
    unsigned short reserved[4];
    unsigned short oemid;		// OEM id
    unsigned short oeminfo;		// OEM info
    unsigned short reserved2[10];	// reserved
    unsigned int   e_lfanew;	// address of new EXE header
}ext_header;
#pragma pack(pop)

#pragma pack(push,1)
typedef struct NE_sig
{
    unsigned char unk[4];
    unsigned short behaviour;
    unsigned char unk1[26];
    unsigned int p_ne; // 0 if plain executable else offset
}ne_sig;
#pragma pack(pop)
#pragma pack(push,1)
typedef struct tlink_sig
{
    unsigned char unk[2];
    unsigned char BID;
    unsigned char ver; // tlink version major in high nibble
    unsigned char unk1[2];
}borland_sig;
#pragma pack(pop)
#pragma pack(push,1)
typedef struct old_arj
{
    unsigned char arj_sig[4]; //RJSX
}arj_sig;
#pragma pack(pop)
#pragma pack(push,1)
typedef struct lz_sig
{
    unsigned char id[2]; // LZ
    unsigned char ver[2];// 09->0.90, 91->0.91
}lz_sig;
#pragma pack(pop)
#pragma pack(push,1)
typedef struct pklite_sig
{
    unsigned char ver_minor;
    unsigned char bit_map; // 0-3 major version bit 4 extra compression 5 multisegment file
    unsigned char id[6];   // PKLITE
}pklite_sig;
#pragma pack(pop)
#pragma pack(push,1)
typedef struct lharc_sig
{
    unsigned char unk[4];
    unsigned char jmp[3]; // jump to execution code for extracting
    unsigned char unk1[2];
    unsigned char id[12];
}lharcv1_sig;
#pragma pack(pop)
#pragma pack(push,1)
typedef struct lharcv2_sig
{
    unsigned char unk[8];
    unsigned char id[10];
}lharcv2_sig;
#pragma pack(pop)
#pragma pack(push,1)
typedef struct lh_sfx
{
    unsigned char unk[8];
    unsigned char id[8];
}lhsfx;
#pragma pack(pop)
#pragma pack(push,1)
typedef struct TSC30
{
    unsigned int	id1; //018A0001h
    unsigned short  id2; //1565h
}TSC30_sig;
#pragma pack(pop)
#pragma pack(push,1)
typedef struct pkarc
{
    unsigned int   id1; //00020001h
    unsigned short id2;//=0700h
}pkarc_sig;
#pragma pack(pop)
#pragma pack(push,1)
typedef struct bsa
{
    unsigned short ID1; //000Fh
    unsigned char  ID2; //A7h
}bsa_sig;
#pragma pack(pop)
#pragma pack(push,1)
typedef struct larc
{
    unsigned char unk[4];
    unsigned char id[11]; // "SFX by LARC "
}larc_sig;
#pragma pack(pop)
#pragma pack(push,1)
typedef struct rel_itm
{
    unsigned short offset;
    unsigned short seg;
}rel_itm;
#pragma pack(pop)
#pragma pack(push,1)
typedef struct pe_header
{
    unsigned char  sig[2]; // PE
    unsigned short zero; //00
    unsigned short macine_id;
    unsigned short num_sections; // number of sections in PE image
    unsigned int   date_time_stamp;
    unsigned int   symtab_pointer; // symbol table pointer
    unsigned int   num_symbols; // total number of symbols
    unsigned short opt_header_size; // size of optional header
    unsigned short characteristic; // characteristic of the file
}pe_header;
#pragma pack(pop)
#pragma pack(push, 1)
struct data_directory
 {
    long VirtualAddress;
    long Size;
 };
typedef struct PEOptHeader
{
/*
char is 1 byte
short is 2 bytes
long is 4 bytes
*/
    short signature; //decimal number 267 for 32 bit, 523 for 64 bit, and 263 for a ROM image.
    char MajorLinkerVersion;
    char MinorLinkerVersion;
    long SizeOfCode;            //The size of the code section, in bytes, or the sum of all such sections if there are multiple code
                                //sections.
    long SizeOfInitializedData; //The size of the initialized data section, in bytes, or the sum of all such sections if there are
                                //multiple initialized data sections.
    long SizeOfUninitializedData;//The size of the uninitialized data section, in bytes, or the sum of all such sections if there are
                                 //multiple uninitialized data sections.
    long AddressOfEntryPoint;    //The RVA of the code entry point A pointer to the entry point function, relative to the image base
                                 //address. For executable files, this is the starting address. For device drivers, this is the address
                                 //of the initialization function. The entry point function is optional for DLLs. When no entry point
                                 //is present, this member is zero.
    long BaseOfCode;             //A pointer to the beginning of the code section, relative to the image base.
    long BaseOfData;             //A pointer to the beginning of the data section, relative to the image base.
    /*The next 21 fields are an extension to the COFF optional header format*/
    long ImageBase;              //The preferred address of the first byte of the image when it is loaded in memory. This value is a
                                 //multiple of 64K bytes. The default value for DLLs is 0x10000000. The default value for applications
                                 //is 0x00400000, except on Windows CE where it is 0x00010000.
    long SectionAlignment;       //The alignment of sections loaded in memory, in bytes. This value must be greater than or equal
                                 //to the FileAlignment member. The default value is the page size for the system.
    long FileAlignment;          //The alignment of the raw data of sections in the image file, in bytes. The value should
                                 //be a power of 2 between 512 and 64K (inclusive). The default is 512. If the SectionAlignment member
                                 //is less than the system page size, this member must be the same as SectionAlignment.
    short MajorOSVersion;        //    The major version number of the required operating system.
    short MinorOSVersion;        //    The minor version number of the required operating system.
    short MajorImageVersion;     //    The major version number of the image.
    short MinorImageVersion;     //    The minor version number of the image.
    short MajorSubsystemVersion; //    The major version number of the subsystem.
    short MinorSubsystemVersion; //    The minor version number of the subsystem.
    long Win32VersionValue;      //    This member is reserved and must be 0.
    long SizeOfImage;            //    The size of the image, in bytes, including all headers. Must be a multiple of SectionAlignment.
    long SizeOfHeaders;          //The combined size of the following items, rounded to a multiple of the value specified in the
                                 //FileAlignment member(    e_lfanew member of DOS_Header
                                                          //4 byte signature
                                                          //size of COFFHeader
                                                          //size of optional header
                                                          //size of all section headers

    long Checksum;               //The image file checksum. The following files are validated at load time: all drivers,
                                 //any DLL loaded at boot time, and any DLL loaded into a critical system process.
    short Subsystem;             //The Subsystem that will be invoked to run the executable
    short DLLCharacteristics;
    long SizeOfStackReserve;     //The number of bytes to reserve for the stack. Only the memory specified by
                                 //the SizeOfStackCommit member is committed at load time; the rest is made available
                                 //one page at a time until this reserve size is reached.
    long SizeOfStackCommit;      //The number of bytes to commit for the stack.
    long SizeOfHeapReserve;      //The number of bytes to reserve for the local heap. Only the memory specified by
                                 //the SizeOfHeapCommit member is committed at load time; the rest is made available one page
                                 //at a time until this reserve size is reached.
    long SizeOfHeapCommit;       //The number of bytes to commit for the local heap.
    long LoaderFlags;            //This member is obsolete.
    long NumberOfRvaAndSizes;    //The number of directory entries in the remainder of the optional header. Each entry describes
                                 //a location and size.
    //data_directory DataDirectory[16];     //Can have any number of elements, matching the number in NumberOfRvaAndSizes.
                                         //However, it is always 16 in PE files.
    // hardcoded Data directory entries bellow
    long ExportTableRVA;
    long ExportDataSize;
    long ImportTableRVA;
    long ImportDataSize;
    long ResourceTableRVA;
    long ResourceDataSize;
    long ExceptionTableRVA;
    long ExceptionDataSize;
    long SecurityTableRVA;
    long SecurityDataSize;
    long FixupTableRVA;
    long FixupDataSize;
    long DebugTableRVA;
    long DebugDataSize;
    long ImageDescriptionRVA;
    long DescriptionDataSize;
    long MachineSpecificRVA;
    long MachnineDataSize;
    long TLSRVA;
    long TLSDataSize;
    long LoadConfigRVA;
    long LoadConfigDataSize;
    char  Reserved01[8];
    long IATRVA;
    long IATDataSize;
    char  Reserved02[8];
    char  Reserved03[8];
    char  Reserved04[8];
}PEoptheader;

typedef struct section_header
{ // size 40 bytes
    unsigned char mName[8];
    unsigned long mVirtualSize;
    unsigned long mVirtualAddress;
    unsigned long mSizeOfRawData;
    unsigned long mPointerToRawData;
    unsigned long mPointerToRealocations;
    unsigned long mPointerToLinenumbers;
    unsigned short mNumberOfRealocations;
    unsigned short mNumberOfLinenumbers;
    unsigned long mCharacteristics;
}section_header;
#pragma pack(pop)

struct machineid
{
    unsigned short val;
    char  name[45];
};

struct subsystem
{
    int id;
    char sname[45];
};

#endif // HEADERS_H
