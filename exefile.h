#ifndef EXEFILE_H
#define EXEFILE_H
#include <QFile>
#include <QVector>
#include "Headers.h"

class Exefile
{
public:
                        Exefile();
                        ~Exefile();
                        Exefile(QString);
    void                set_file(QString filename);
    bool                is_valid();             // check if it is MZ exe or not
    QString exeinfo();              // info from EXE header
    generic_header      *get_MZ_header(){return (exe_header);};       // return EXE file generic header
    ext_header          *get_MZ_extraheader(){return(extra_header);};  // return EXE file extended header
    bool                is_borland();           // checks if it is a borland compiled file
    QString             get_borland_version();  // get borland linker version if borland compiled
    bool                is_pe_ne();             // is it pe or ne file
    unsigned int        get_peoffset();         // returns PE offset
    QString             get_tlink_version();
    bool                is_pe();                // is a PE file
    QString             get_pe_info();          // get the PE info from pe header and opt header
    QString             list_data_dir();        // list the data directories in PE image
    QString             Sections();
private:
    generic_exe_header  *exe_header;
    ext_header          *extra_header;
    pe_header           *pehdr;
    PEOptHeader         *opthdr;
    QFile               f;
};

#endif // EXEFILE_H
