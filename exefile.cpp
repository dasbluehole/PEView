#include <QDebug>
#include "exefile.h"
#include <QTreeWidgetItem>
#include <QTreeWidget>

struct machineid    m_id[26]={
        {0x14c,"Intel 386"},
        {0x8664 	,"x64"},
        {0x162 	,"MIPS R3000"},
        {0x168 	,"MIPS R10000"},
        {0x169 	,"MIPS little endian WCI v2"},
        {0x183 	,"old Alpha AXP"},
        {0x184 	,"Alpha AXP"},
        {0x1a2 	,"Hitachi SH3"},
        {0x1a3 	,"Hitachi SH3 DSP"},
        {0x1a6 	,"Hitachi SH4"},
        {0x1a8 	,"Hitachi SH5"},
        {0x1c0 	,"ARM little endian"},
        {0x1c2 	,"Thumb"},
        {0x1d3 	,"Matsushita AM33"},
        {0x1f0 	,"PowerPC little endian"},
        {0x1f1 	,"PowerPC with floating point support"},
        {0x200 	,"Intel IA64"},
        {0x266 	,"MIPS16"},
        {0x268 	,"Motorola 68000 series"},
        {0x284 	,"Alpha AXP 64-bit"},
        {0x366 	,"MIPS with FPU"},
        {0x466 	,"MIPS16 with FPU"},
        {0xebc 	,"EFI Byte Code"},
        {0x8664 ,"AMD AMD64"},
        {0x9041 ,"Mitsubishi M32R little endian"},
        {0xc0ee ,"clr pure MSIL"}
};
struct subsystem subsys[13]={
    {0,"Unknown subsystem"},
    {1,"Device drivers and native system processes"},
    {2,"Windows (GUI) subsystem"},
    {3,"Windows (CUI) subsystem"},
    {5,"OS/2 CUI subsystem"},
    {7,"POSIX CUI subsystem"},
    {9,"Windows CE system"},
    {10,"EFI application"},
    {11,"EFI driver with boot services"},
    {12,"EFI driver with run-time services"},
    {13,"EFI ROM image"},
    {14,"Xbox system"},
    {16,"Boot application"}
};
QString list_data_dir(data_directory *ddir,int num_sec)
{
    QString res="";
    for(int i=0;i<num_sec;i++)
    {
        if(ddir->Size>0)
        res.append(QString::number(ddir->VirtualAddress)).append("+").append(QString::number(ddir->Size)).append("#");
        ddir++;
    }
    return(res);
}
Exefile::Exefile()
{
}
Exefile::~Exefile()
{
    f.close();
}

Exefile::Exefile(QString f)
{
    set_file(f);
}

void Exefile::set_file(QString filename)
{
    qDebug()<<filename;
    f.setFileName(filename);
    if(!f.open(QIODevice::ReadOnly))
        return;

    exe_header = (generic_header*) f.map(0,sizeof(generic_header));
    if(exe_header==0)
    {
        qDebug()<<"wrong header";
        return;
    }

    extra_header =(ext_header*) f.map(sizeof(generic_header),sizeof(ext_header));
    if(extra_header->e_lfanew==0||extra_header->e_lfanew>=f.size())
    {
        pehdr=0;
        opthdr=0;
        return;
    }

    pehdr=(pe_header*)f.map(get_peoffset(),sizeof(pe_header));
    opthdr =(PEoptheader*)f.map(get_peoffset()+sizeof(pe_header),sizeof(PEOptHeader));
   // f.close();
}
bool Exefile::is_valid()
{
    QString str;
    //str.append(exe_header->id[0]).append(exe_header->id[1]);
    str=QString::fromAscii((char*)exe_header->id,2);
    if(str=="MZ") // MZ
        return(true);
    else
        return(false);
}
QString Exefile::exeinfo()
{
    QString infostr;
    infostr.append(" Signature:"+QString::fromAscii((char*)exe_header->id,2)+"\n");
    infostr.append(" Bytes in last block:"+QString::number(exe_header->bytes_in_last_block)+"\n");
    infostr.append(" Total blocks including last page:"+QString::number(exe_header->blocks_in_file)+"\n");
    infostr.append(" Relocation table entries:"+QString::number(exe_header->num_relocs)+"\n");
    infostr.append(" Header size in paragraphs:"+QString::number(exe_header->header_paragraphs)+"\n");
    infostr.append(" Minimum paragraphs:"+QString::number(exe_header->min_extra_paragraphs)+"\n");
    infostr.append(" Maximum paragraphs:"+QString::number(exe_header->max_extra_paragraphs)+"\n");
    infostr.append(" SS:0x"+QString::number(exe_header->ss,16)+"\n");
    infostr.append(" SP:0x"+QString::number(exe_header->sp,16)+"\n");
    infostr.append(" Checksum:"+QString::number(exe_header->checksum)+"\n");
    infostr.append(" IP:0x"+QString::number(exe_header->ip,16)+"\n");
    infostr.append(" CS:0x"+QString::number(exe_header->cs,16)+"\n");
    infostr.append(" Relocation table Offset:0x"+QString::number(exe_header->reloc_table_offset,16)+"\n");
    infostr.append(" Overlay number:"+QString::number(exe_header->overlay_number)+"\n");
    return (infostr);
}
bool Exefile::is_borland()
{
    tlink_sig *tl = (tlink_sig*)extra_header;
    if(tl->BID==0xFB)
    {
        return(true);
    }
    return(false);
}
QString Exefile::get_borland_version()
{
    QString ver;
    tlink_sig *tl = (tlink_sig*)extra_header;
    ver.append("Borland linker(tlink)");
    ver.append(QString::number((int)tl->ver&0xF0));
    ver.append(".");
    ver.append(QString::number(tl->ver&0x0F));
    return(ver);
}
unsigned int Exefile::get_peoffset()
{
    return(extra_header->e_lfanew);
}
bool Exefile::is_pe_ne()
{
    if(extra_header->e_lfanew==0)
        return(false);
   return(true);
}
bool Exefile::is_pe()
{
    // qDebug()<<(char)pehdr->sig[0]<<(char)pehdr->sig[1];
    if(!pehdr)
        return false;
    if(QString::fromAscii((char*)pehdr->sig,2)=="PE")
        return(true);
    return(false);
}
QString Exefile::list_data_dir()
{
    QString res="";
    res.append("Export Table:0x"+QString::number(opthdr->ExportTableRVA,16)+"\t"+QString::number(opthdr->ExportDataSize)+" Bytes\n");
    res.append("Import Table:0x"+QString::number(opthdr->ImportTableRVA,16)+"\t"+QString::number(opthdr->ImportDataSize)+" Bytes\n");
    res.append("Resource Table:0x"+QString::number(opthdr->ResourceTableRVA,16)+"\t"+QString::number(opthdr->ResourceDataSize)+" Bytes\n");
    res.append("Exception Table:0x"+QString::number(opthdr->ExceptionTableRVA,16)+"\t"+QString::number(opthdr->ExceptionDataSize)+" Bytes\n");
    res.append("Security Table at:0x"+QString::number(opthdr->SecurityTableRVA,16)+"\t"+QString::number(opthdr->SecurityDataSize)+" Bytes\n");
    res.append("Fixup Table :0x"+QString::number(opthdr->FixupTableRVA,16)+"\t"+QString::number(opthdr->FixupDataSize)+" Bytes\n");
    res.append("Debug Table :0x"+QString::number(opthdr->DebugTableRVA,16)+"\t"+QString::number(opthdr->DebugDataSize)+" Bytes\n");
    res.append("Image Description:0x"+QString::number(opthdr->ImageDescriptionRVA ,16)+"\t"+QString::number(opthdr->DescriptionDataSize)+" Bytes\n");
    res.append("Machine Specific data:0x"+QString::number(opthdr->MachineSpecificRVA,16)+"\t"+QString::number(opthdr->MachnineDataSize)+" Bytes\n");
    res.append("TLS Info:0x"+QString::number(opthdr->TLSRVA,16)+"\t"+QString::number(opthdr->TLSDataSize)+" Bytes\n");
    res.append("Load config info:0x"+QString::number(opthdr->LoadConfigRVA,16)+"\t"+QString::number(opthdr->LoadConfigDataSize)+" Bytes\n");
    res.append("IAT:0x"+QString::number(opthdr->IATRVA,16)+"\t"+QString::number(opthdr->IATDataSize)+" Bytes\n");
    return(res);

}

QString Exefile::get_pe_info()
{
    QString pe_info_str;
    QString midstr;
    for(int i=0;i<26;i++)
        if(m_id[i].val==pehdr->macine_id)
            midstr.append(m_id[i].name);
    pe_info_str.append("Machine ID:"+QString::number(pehdr->macine_id,16)+"h "+midstr+"\n");
    pe_info_str.append("Number of sections:"+QString::number(pehdr->num_sections)+"\n");
    pe_info_str.append("Date time stamp:"+QString::number(pehdr->date_time_stamp)+"\n");
    pe_info_str.append("Symbol table pointer:0x"+QString::number(pehdr->symtab_pointer,16)+"\n");
    pe_info_str.append("Number of symbols:"+QString::number(pehdr->num_symbols)+"\n");
    pe_info_str.append("Size of Optional header:"+QString::number(pehdr->opt_header_size)+" bytes\n");
    QString characteristicstr;
    if(pehdr->characteristic & 0x02)
        characteristicstr.append("Executable");
    if(pehdr->characteristic & 0x200)
        characteristicstr.append(" ,Non relocatable");
    if(pehdr->characteristic & 0x2000)
        characteristicstr.append(", DLL library");
    pe_info_str.append("Characteristic:"+characteristicstr+"\n");
    QString optsigstr;
    if(opthdr->signature==267)
        optsigstr="32-bit";
    if(opthdr->signature==523)
        optsigstr="64-bit";
    if(opthdr->signature==263)
        optsigstr="ROM image";
    pe_info_str.append("Signatute:"+optsigstr+"\n");
    QString linkervstr;
    linkervstr=QString::number(opthdr->MajorLinkerVersion);
    linkervstr.append(".");
    linkervstr +=QString::number(opthdr->MinorLinkerVersion);
    pe_info_str.append("Linker version:"+linkervstr+'\n');
    QString osvstr;
    osvstr.append("OS Version:").append(QString::number(opthdr->MajorOSVersion)).append(".").append(QString::number(opthdr->MinorOSVersion));
    pe_info_str.append(osvstr+"\n");
    pe_info_str.append("Sum of all code sections:"+QString::number(opthdr->SizeOfCode)+" bytes\n");
    pe_info_str.append("Sum of all initialized data sections:"+QString::number(opthdr->SizeOfInitializedData)+" bytes\n");
    pe_info_str.append("Sum of Uninitialized data sections:"+QString::number(opthdr->SizeOfUninitializedData)+" bytes\n");
    pe_info_str.append("Address of Entry point:0x"+QString::number(opthdr->AddressOfEntryPoint,16)+" relative to image base\n");
    pe_info_str.append("Address of Begining of Code section:0x"+QString::number(opthdr->BaseOfCode,16)+" relative to image base\n");
    pe_info_str.append("Address of begining Data:0x"+QString::number(opthdr->BaseOfData,16)+" relative to image base\n");
    pe_info_str.append("Address of Image base:0x"+QString::number(opthdr->ImageBase,16)+" \n");
    pe_info_str.append("Sectionalignment:0x"+QString::number(opthdr->SectionAlignment,16)+"\n");
    pe_info_str.append("File Alignment:0x"+QString::number(opthdr->FileAlignment,16)+"\n");
    pe_info_str.append("Image version:"+QString::number(opthdr->MajorImageVersion)+"."+QString::number(opthdr->MinorImageVersion)+"\n");
    pe_info_str.append("Subsystem Version:"+QString::number(opthdr->MajorSubsystemVersion)+"."+QString::number(opthdr->MinorSubsystemVersion)+"\n");
    pe_info_str.append("WIN32 Version:"+QString::number(opthdr->Win32VersionValue)+"\n");
    pe_info_str.append("Size of Image:"+QString::number(opthdr->SizeOfImage)+"\n");
    pe_info_str.append("Sum(e_lfanew,4byte sig,PE, opt, all section headers):"+QString::number(opthdr->SizeOfHeaders)+"\n");
    pe_info_str.append("Image Checksum:"+QString::number(opthdr->Checksum)+"\n");
    QString subsysstr;
    for(int i=0;i<13;i++)
        if(opthdr->Subsystem==subsys[i].id)
            subsysstr=subsys[i].sname;
    pe_info_str.append("Subsystem:"+subsysstr+"\n");
    pe_info_str.append("Size of stack reserved:"+QString::number(opthdr->SizeOfStackReserve)+" bytes max\n");
    pe_info_str.append("Size of stack allocated at loading:"+QString::number(opthdr->SizeOfStackCommit)+" bytes\n");
    pe_info_str.append("Size of heap reserved:"+QString::number(opthdr->SizeOfHeapReserve)+" bytes max\n");
    pe_info_str.append("Size of heap allocated at loading:"+QString::number(opthdr->SizeOfHeapCommit)+" bytes\n");
    pe_info_str.append("Number of Directory entries:"+QString::number(opthdr->NumberOfRvaAndSizes)+"\n");
    QString DLLCharacterstr="";
    short DLLc=opthdr->DLLCharacteristics;
    //qDebug()<<DLLc;
    if(DLLc & 0x01)
        DLLCharacterstr.append("Per Process Library Initalization|");
    if(DLLc & 0x02)
        DLLCharacterstr.append("Per Process Library Termination|");
    if(DLLc & 0x04)
        DLLCharacterstr.append("Per Thread Library Initialization|");
    if(DLLc & 0x08)
        DLLCharacterstr.append("Per Thread Library Termination|");
    if(DLLc & 0x40)
        DLLCharacterstr.append("DLL can be relocated at load time|");
    if(DLLc & 0x80)
        DLLCharacterstr.append("Code integrity check forced|");
    if(DLLc & 0x100)
        DLLCharacterstr.append("Image compatible with Data Execution Prevention|");
    if(DLLc & 0x200)
        DLLCharacterstr.append("Image is Isolation aware, but should not be Isolated|");
    if(DLLc & 0x400)
        DLLCharacterstr.append("Image doesn't use Structured Exeception Handling|");
    if(DLLc & 0x800)
        DLLCharacterstr.append("Do not Bind Image|");
    if(DLLc & 0x1000)
        DLLCharacterstr.append("Reserved|");
    if(DLLc & 0x2000)
        DLLCharacterstr.append("A WDM driver|");
    if(DLLc & 0x4000)
        DLLCharacterstr.append("Reserved|");
    if(DLLc & 0x8000)
        DLLCharacterstr.append("Image is Terminal Server Aware");
    pe_info_str.append("DLL characteristic:"+DLLCharacterstr+"\n");
    //pe_info_str.append("###==============================================\n");

    pe_info_str.append(list_data_dir());
    //pe_info_str.append("###==============================================\n");

    pe_info_str.append(Sections());
    return(pe_info_str);
}
QString Exefile::Sections()
{
    // get the section headers and print it
    //just after the datadir section table starts
    QString secstr="";
    QString seccharstr="";
    //char *buffer =new char [sizeof(section_header) * pehdr->num_sections];
    section_header *shdr=0;//= new section_header();
    if(!f.isOpen())
    {
        qDebug()<<"File is not opened";
        return(secstr);
    }
    long offset=0;
    //qDebug()<<sizeof(section_header);
    offset=get_peoffset()+sizeof(pe_header)+sizeof(PEOptHeader);
    secstr.append("Name:Vadr\tVsize\tRaw addr\tRaw size\tLineNum\tAddrs\tCharacteristic\n");
    for(int i=0;i<pehdr->num_sections;i++)
    {
        shdr=(section_header*)f.map(offset,sizeof(section_header));
        secstr.append((char*)shdr->mName).append(":0x").append(QString::number(shdr->mVirtualAddress,16)).append("\t").append(QString::number(shdr->mVirtualSize)).append("\t0x");
        secstr.append(QString::number(shdr->mPointerToRawData,16)).append("\t").append(QString::number(shdr->mSizeOfRawData)).append("\t");
        secstr.append(QString::number(shdr->mNumberOfLinenumbers)).append("\t0x").append(QString::number(shdr->mPointerToLinenumbers,16));
        if(shdr->mCharacteristics&0x20)
            seccharstr.append("C|");
        if(shdr->mCharacteristics&0x40)
            seccharstr.append("ID|");
        if(shdr->mCharacteristics&80)
            seccharstr.append("UD|");
        if(shdr->mCharacteristics&0x200)
            seccharstr.append("Com|");
        if(shdr->mCharacteristics&0x800)
            seccharstr.append("CompInf|");
        if(shdr->mCharacteristics&0x2000000)
            seccharstr.append("Disc|");
        if(shdr->mCharacteristics&0x10000000)
            seccharstr.append("Shr|");
        if(shdr->mCharacteristics&0x20000000)
            seccharstr.append("EX|");
        if(shdr->mCharacteristics&0x40000000)
            seccharstr.append("R|");
        if(shdr->mCharacteristics&0x80000000)
            seccharstr.append("W");
        secstr.append(seccharstr).append("\n");
        offset+=sizeof(section_header);
        seccharstr="";
    }
    return(secstr);
}
