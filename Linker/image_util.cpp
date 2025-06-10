#include "std.h"
#include "image_util.h"

#include <winnt.h>

#ifndef DEMO

static void PrintPEInfo(const char* filename);
static void PrintSectionHeaders(std::ifstream& file, std::streamoff sectionOffset, WORD numberOfSections);

#pragma pack( push,1 )

struct Head{
	short machine,num_sects;
	int timedata,sym_table,num_syms;
	short opt_size,chars;
};

struct Opts{
	short magic;
	char major,minor;
	int code_size,data_size,udata_size;
	int entry,code_base,data_base;

	int image_base,sect_align,file_align;
	short major_os,minor_os,major_image,minor_image,major_subsys,minor_subsys;

	int reserved;
	int image_size,headers_size,checksum;

	short subsys,dllchars;

	int stack_reserve,stack_commit,heap_reserve,heap_commit,loadflags;

	int dir_entries;
};

struct DDir{
	int rva,size;
};

struct Sect{
	char name[8];
	int virt_size,virt_addr;	//in mem
	int data_size,data_addr;	//on disk
	int relocs,lines;			//file ptrs
	short num_relocs,num_lines;
	int chars;
};

struct Rdir{
	int chars,timedata;
	short major,minor,num_names,num_ids;
};

struct Rent{
	int id,data;
};

struct Rdat{
	int addr,size,cp,zero;
};

#pragma pack( pop )

struct Rsrc{
	int id;
	void *data;
	int data_sz;
	vector<Rsrc*> kids;

	Rsrc( int id,Rsrc *p ):id(id),data(0),data_sz(0){
		if( p ) p->kids.push_back( this );
//		cout<<"res id:"<<dec<<id<<hex<<endl;
	}

	~Rsrc(){
		for( ;kids.size();kids.pop_back() ) delete kids.back();
		delete data;
	}
};

struct Section{
	Sect sect;
	char *data;

	Section():data(0){}
	~Section(){ delete[] data; }
};

static char *stub;
static int stub_sz;

static Head *head;
static int head_sz;

static Opts *opts;
static int opts_sz;

static DDir *ddir;
static int ddir_sz;

static vector<Section*> sections;

static Rsrc *rsrc_root;

static const char *img_file;

static void openRsrcDir( Section *s,int off,Rsrc *p ){
	char *data=(char*)s->data;

	Rdir *dir=(Rdir*)(data+off);
	Rent *ent=(Rent*)(dir+1);
	for( int k=0;k<dir->num_ids;++ent,++k ){
		Rsrc *r=d_new Rsrc( ent->id,p );
		if( ent->data<0 ){	//a node - offset is another dir
			openRsrcDir( s,ent->data&0x7fffffff,r );
		}else{				//a leaf
			Rdat *dat=(Rdat*)( data+ent->data );
//			cout<<"dat addr:"<<dat->addr<<" size:"<<dat->size<<endl;
			int sz=dat->size;
			void *src=dat->addr-s->sect.virt_addr+data;
			void *dest=d_new char[sz];
			memcpy( dest,src,sz );
			r->data=dest;
			r->data_sz=sz;
		}
	}

}

static void openRsrcTree( Section *s ){
	rsrc_root=d_new Rsrc( 0,0 );
	openRsrcDir( s,0,rsrc_root );
}

static int rsrcSize( Rsrc *r ){
	if( r->data ) return (sizeof(Rdat)+r->data_sz+7)&~7;
	int sz=sizeof( Rdir );
	for( int k=0;k<r->kids.size();++k ){
		sz+=sizeof( Rent )+rsrcSize( r->kids[k] );
	}
	return sz;
}

static void closeRsrcDir( Section *s,int off,Rsrc *p ){

	int t,k;

	char *data=(char*)s->data;

	Rdir *dir=(Rdir*)(data+off);
	memset( dir,0,sizeof(Rdir) );
	dir->num_ids=p->kids.size();
	Rent *ent=(Rent*)(dir+1);

	//to end of dir...
	off+=sizeof(Rdir)+sizeof(Rent)*p->kids.size();

	t=off;

	//write entries
	for( k=0;k<p->kids.size();++ent,++k ){
		Rsrc *r=p->kids[k];
		ent->id=r->id;
		ent->data=t;
		if( !r->data ) ent->data|=0x80000000;
		t+=rsrcSize( r );
	}

	t=off;

	//write kids...
	for( k=0;k<p->kids.size();++k ){
		Rsrc *r=p->kids[k];
		if( !r->data ){
			closeRsrcDir( s,t,r );
		}else{
			Rdat *dat=(Rdat*)(data+t);
			dat->addr=s->sect.virt_addr+t+sizeof(Rdat);
			dat->size=r->data_sz;
			dat->zero=dat->cp=0;
			memcpy( data+t+sizeof(Rdat),r->data,r->data_sz );
		}
		t+=rsrcSize( r );
	}
}

static int fileAlign( int n ){
	return (n+(opts->file_align-1))&~(opts->file_align-1);
}

static int sectAlign( int n ){
	return (n+(opts->sect_align-1))&~(opts->sect_align-1);
}

static void closeRsrcTree( Section *s ){

	int virt_sz=rsrcSize( rsrc_root );
	int data_sz=fileAlign( virt_sz );

	int virt_delta=sectAlign(virt_sz)-sectAlign(s->sect.virt_size);
	int data_delta=fileAlign(virt_sz)-fileAlign(s->sect.virt_size);


	for( int k=0;k<sections.size();++k ){
		Section *t=sections[k];
		if( t->sect.virt_addr>s->sect.virt_addr ){
			t->sect.virt_addr+=virt_delta;
			if( !strcmp( t->sect.name,".reloc" ) ){
				ddir[5].rva=t->sect.virt_addr;
			}
		}
		if( t->sect.data_addr>s->sect.data_addr ){
			t->sect.data_addr+=data_delta;
		}
	}

	ddir[2].size=virt_sz;
	opts->image_size+=virt_delta;

	s->sect.virt_size=virt_sz;
	s->sect.data_size=data_sz;

	delete[] s->data;
	s->data=d_new char[data_sz];
	closeRsrcDir( s,0,rsrc_root );

	delete rsrc_root;
	rsrc_root=0;
}

static Rsrc *findRsrc( int id,Rsrc *p ){
	for( int k=0;k<p->kids.size();++k ){
		if( p->kids[k]->id==id ) return p->kids[k];
	}
	return 0;
}

static Rsrc *findRsrc( int type,int id,int lang ){
	Rsrc *r=findRsrc( type,rsrc_root );if( !r ) return 0;
	r=findRsrc( id,r );if( !r ) return 0;
	return findRsrc( lang,r );
}

static void loadImage( istream &in ){

	int k;

	//read stub
	in.seekg( 0x3c );
	in.read( (char*)&stub_sz,4 );
	stub_sz+=4;stub=d_new char[stub_sz];
	in.seekg( 0 );in.read( stub,stub_sz );

	//read head
	head=d_new Head;
	head_sz=sizeof(Head);
	in.read( (char*)head,head_sz );

	//read opts
	opts=d_new Opts;
	opts_sz=sizeof(Opts);
	in.read( (char*)opts,opts_sz );

	//read data dirs
	ddir_sz=opts->dir_entries * sizeof(DDir);
	ddir=(DDir*)d_new char[ddir_sz];
	in.read( (char*)ddir,ddir_sz );

	//read sects...
	for( k=0;k<head->num_sects;++k ){
		Section *s=d_new Section;
		in.read( (char*)&s->sect,sizeof(Sect) );
		sections.push_back( s );
	}

	for( k=0;k<head->num_sects;++k ){
		Section *s=sections[k];
		if( !s->sect.data_addr ) continue;
		int data_sz=s->sect.data_size;
		s->data=d_new char[data_sz];//char[s->sect.virt_size];
		//memset( s->data,0,s->sect.virt_size );
		in.seekg( s->sect.data_addr );
		in.read( s->data,data_sz );
	}
}

static void saveImage( ostream &out ){

	int k;


// same as the MSVC one except no Rich header of course
	out.write( (char*)stub,stub_sz );
///////////////////////////////////////////////////////

//cout << "HEAD============================" << endl;
//cout << "MACHINE: " << head->machine << endl;
//cout << "SECTIONS: " << head->num_sects << endl;
//cout << "TIMEDATA: " << head->timedata << endl;
//cout << "SYM_TABLE: " << head->sym_table << endl;
//cout << "NUM_SYMS: " << head->num_syms << endl;
//cout << "OPT_SIZE: " << head->opt_size << endl;
//cout << "CHARS: " << head->chars << endl;
//cout << "================================" << endl;
//cout << "OPTS-0x============================" << endl;
//cout << "MAGIC: " << opts->magic << endl;
//cout << "MAJOR: " << opts->major << endl;
//cout << "MINOR: " << opts->minor << endl;
//cout << "================================" << endl;



//PrintPEInfo("C:\\Users\\donovan\\Desktop\\blitzcc\\_release\\bin\\Debug\\runtime.dll");


//	out.write( (char*)head,head_sz );
//	out.write( (char*)opts,opts_sz );
//	out.write( (char*)ddir,ddir_sz );


//	for( k=0;k<head->num_sects;++k ){
//		Section *s=sections[k];
//		out.write( (char*)&s->sect,sizeof(Sect) );
//	}

//	for( k=0;k<head->num_sects;++k ){
//
//		Section *s=sections[k];
////		 cout << s->sect.data_addr << endl;
//		if( !s->sect.data_addr ) continue;
//
////		assumes sect data is in order!!!!!
//		while( out.tellp()<s->sect.data_addr ) out.put( (char)0xbb );
//		out.seekp( s->sect.data_addr );
//		out.write( s->data,s->sect.data_size );
//	}
}


static void saveImage_test( ostream &out ){

	int k;


// same as the MSVC one except no Rich header of course
	out.write( (char*)stub,stub_sz );
	out.write( (char*)head,head_sz );
	out.write( (char*)opts,opts_sz );
	out.write( (char*)ddir,ddir_sz );


	for( k=0;k<head->num_sects;++k ){
		Section *s=sections[k];
		out.write( (char*)&s->sect,sizeof(Sect) );
	}

////	for( k=0;k<head->num_sects;++k ){
////
////		Section *s=sections[k];
//////		 cout << s->sect.data_addr << endl;
////		//if( !s->sect.data_addr ) continue;
////		if( strcmp( s->sect.name,".rsrc" ) ) continue;
//////		assumes sect data is in order!!!!!
////		//while( out.tellp()<s->sect.data_addr ) out.put( (char)0xbb );
////		//out.seekp( s->sect.data_addr );
////		out.seekp( 0 );
////		out.write( s->data,s->sect.data_size );
////	}

	for( k=0;k<head->num_sects;++k ){

		Section *s=sections[k];
		if( !s->sect.data_addr ) continue;
//		assumes sect data is in order!!!!!
        while( out.tellp()<s->sect.data_addr ) out.put( (char)0xbb );
        out.seekp( s->sect.data_addr );
		out.write( s->data,s->sect.data_size );
	}


}

/********************** DEBUG STUFF ***********************/

static void PrintPEInfo(const char* filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << "Failed to open file.\n";
        return;
    }

    IMAGE_DOS_HEADER dos;
    file.read(reinterpret_cast<char*>(&dos), sizeof(dos));
    std::cout << "== DOS HEADER ==\n";
    std::cout << "e_magic: 0x" << std::hex << dos.e_magic << "\n";
    std::cout << "e_cblp: " << std::dec << dos.e_cblp << "\n";
    std::cout << "e_cp: " << dos.e_cp << "\n";
    std::cout << "e_crlc: " << dos.e_crlc << "\n";
    std::cout << "e_cparhdr: " << dos.e_cparhdr << "\n";
    std::cout << "e_minalloc: " << dos.e_minalloc << "\n";
    std::cout << "e_maxalloc: " << dos.e_maxalloc << "\n";
    std::cout << "e_ss: " << dos.e_ss << "\n";
    std::cout << "e_sp: " << dos.e_sp << "\n";
    std::cout << "e_csum: " << dos.e_csum << "\n";
    std::cout << "e_ip: " << dos.e_ip << "\n";
    std::cout << "e_cs: " << dos.e_cs << "\n";
    std::cout << "e_lfarlc: " << dos.e_lfarlc << "\n";
    std::cout << "e_ovno: " << dos.e_ovno << "\n";
    std::cout << "e_res[4]: ";
    for (int i = 0; i < 4; ++i) std::cout << dos.e_res[i] << " ";
    std::cout << "\ne_oemid: " << dos.e_oemid << "\n";
    std::cout << "e_oeminfo: " << dos.e_oeminfo << "\n";
    std::cout << "e_res2[10]: ";
    for (int i = 0; i < 10; ++i) std::cout << dos.e_res2[i] << " ";
    std::cout << "\ne_lfanew: 0x" << std::hex << dos.e_lfanew << "\n\n";





    file.seekg(dos.e_lfanew, std::ios::beg);
    DWORD signature;
    file.read(reinterpret_cast<char*>(&signature), sizeof(signature));
    std::cout << "== NT HEADERS ==\n";
    std::cout << "Signature: 0x" << std::hex << signature << "\n";

    IMAGE_FILE_HEADER fileHeader;
    file.read(reinterpret_cast<char*>(&fileHeader), sizeof(fileHeader));
    std::cout << "\n== FILE HEADER ==\n";
    std::cout << "Machine: 0x" << std::hex << fileHeader.Machine << "\n";
    std::cout << "NumberOfSections: " << std::dec << fileHeader.NumberOfSections << "\n";
    std::cout << "TimeDateStamp: 0x" << std::hex << fileHeader.TimeDateStamp << "\n";
    std::cout << "PointerToSymbolTable: 0x" << fileHeader.PointerToSymbolTable << "\n";
    std::cout << "NumberOfSymbols: " << std::dec << fileHeader.NumberOfSymbols << "\n";
    std::cout << "SizeOfOptionalHeader: " << fileHeader.SizeOfOptionalHeader << "\n";
    std::cout << "Characteristics: 0x" << std::hex << fileHeader.Characteristics << "\n";

    IMAGE_OPTIONAL_HEADER32 opt;
    file.read(reinterpret_cast<char*>(&opt), sizeof(opt));
    std::cout << "\n== OPTIONAL HEADER ==\n";
    std::cout << "Magic: 0x" << std::hex << opt.Magic << "\n";
    std::cout << "MajorLinkerVersion: " << std::dec << (int)opt.MajorLinkerVersion << "\n";
    std::cout << "MinorLinkerVersion: " << (int)opt.MinorLinkerVersion << "\n";
    std::cout << "SizeOfCode: 0x" << std::hex << opt.SizeOfCode << "\n";
    std::cout << "SizeOfInitializedData: 0x" << opt.SizeOfInitializedData << "\n";
    std::cout << "SizeOfUninitializedData: 0x" << opt.SizeOfUninitializedData << "\n";
    std::cout << "AddressOfEntryPoint: 0x" << opt.AddressOfEntryPoint << "\n";
    std::cout << "BaseOfCode: 0x" << opt.BaseOfCode << "\n";
    std::cout << "BaseOfData: 0x" << opt.BaseOfData << "\n";
    std::cout << "ImageBase: 0x" << opt.ImageBase << "\n";
    std::cout << "SectionAlignment: 0x" << opt.SectionAlignment << "\n";
    std::cout << "FileAlignment: 0x" << opt.FileAlignment << "\n";
    std::cout << "MajorOperatingSystemVersion: " << opt.MajorOperatingSystemVersion << "\n";
    std::cout << "MinorOperatingSystemVersion: " << opt.MinorOperatingSystemVersion << "\n";
    std::cout << "MajorImageVersion: " << opt.MajorImageVersion << "\n";
    std::cout << "MinorImageVersion: " << opt.MinorImageVersion << "\n";
    std::cout << "MajorSubsystemVersion: " << opt.MajorSubsystemVersion << "\n";
    std::cout << "MinorSubsystemVersion: " << opt.MinorSubsystemVersion << "\n";
    std::cout << "Win32VersionValue: 0x" << opt.Win32VersionValue << "\n";
    std::cout << "SizeOfImage: 0x" << opt.SizeOfImage << "\n";
    std::cout << "SizeOfHeaders: 0x" << opt.SizeOfHeaders << "\n";
    std::cout << "CheckSum: 0x" << opt.CheckSum << "\n";
    std::cout << "Subsystem: 0x" << opt.Subsystem << "\n";
    std::cout << "DllCharacteristics: 0x" << opt.DllCharacteristics << "\n";
    std::cout << "SizeOfStackReserve: 0x" << opt.SizeOfStackReserve << "\n";
    std::cout << "SizeOfStackCommit: 0x" << opt.SizeOfStackCommit << "\n";
    std::cout << "SizeOfHeapReserve: 0x" << opt.SizeOfHeapReserve << "\n";
    std::cout << "SizeOfHeapCommit: 0x" << opt.SizeOfHeapCommit << "\n";
    std::cout << "LoaderFlags: 0x" << opt.LoaderFlags << "\n";
    std::cout << "NumberOfRvaAndSizes: " << std::dec << opt.NumberOfRvaAndSizes << "\n";
    std::cout << "\n== DATA DIRECTORIES ==\n";

    const char* directoryNames[IMAGE_NUMBEROF_DIRECTORY_ENTRIES] = {
        "Export Table", "Import Table", "Resource Table", "Exception Table",
        "Certificate Table", "Base Relocation Table", "Debug", "Architecture",
        "Global Ptr", "TLS Table", "Load Config Table", "Bound Import",
        "IAT", "Delay Import Descriptor", "CLR Runtime Header", "Reserved"
    };

    for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; ++i) {
        std::cout << directoryNames[i] << ":\n";
        std::cout << "  VirtualAddress: 0x" << std::hex << opt.DataDirectory[i].VirtualAddress << "\n";
        std::cout << "  Size: 0x" << opt.DataDirectory[i].Size << "\n\n";
    }
std::streamoff sectionOffset = dos.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + fileHeader.SizeOfOptionalHeader;
PrintSectionHeaders(file, sectionOffset, fileHeader.NumberOfSections);

}

static void PrintSectionHeaders(std::ifstream& file, std::streamoff sectionOffset, WORD numberOfSections) {
    file.seekg(sectionOffset, std::ios::beg);

    std::cout << "\n== SECTION HEADERS ==\n";

    for (int i = 0; i < numberOfSections; ++i) {
        IMAGE_SECTION_HEADER section{};
        file.read(reinterpret_cast<char*>(&section), sizeof(section));

        std::cout << "Section "  << std::dec <<  i + 1 << ":\n";
        std::cout << "  Name: " << std::string(reinterpret_cast<char*>(section.Name), 8) << "\n";
        std::cout << "  VirtualSize: 0x" << std::hex << section.Misc.VirtualSize << "\n";
        std::cout << "  VirtualAddress: 0x" << section.VirtualAddress << "\n";
        std::cout << "  SizeOfRawData: 0x" << section.SizeOfRawData << "\n";
        std::cout << "  PointerToRawData: 0x" << section.PointerToRawData << "\n";
        std::cout << "  PointerToRelocations: 0x" << section.PointerToRelocations << "\n";
        std::cout << "  PointerToLinenumbers: 0x" << section.PointerToLinenumbers << "\n";
        std::cout << "  NumberOfRelocations: " << std::dec << section.NumberOfRelocations << "\n";
        std::cout << "  Characteristics: 0x" << std::hex << section.Characteristics << "\n\n";
    }
}



/********************** PUBLIC STUFF ***********************/

bool openImage( const char *img ){
	img_file=img;

	fstream in( img_file,ios_base::binary|ios_base::in );
	loadImage( in );
	in.close();
	return true;
}

bool makeExe( int entry ){

	//head->chars&=~0x0004;     // not LINE_NUMS_STRIPPED
	//cout << head->chars << endl;
	//cout << entry << endl;

    if( !img_file ) return false;

	head->chars|=0x0002;		//executable
	head->chars&=~0x2000;		//not Dll
	opts->entry=entry;
//	opts->image_base=0x400000;	//have to deal to fix-ups to do this properly.
	return true;
}

bool replaceRsrc( int type,int id,int lang,void *data,int data_sz ){
	if( !img_file ) return false;

	for( int k=0;k<sections.size();++k ){
		Section *s=sections[k];
		if( strcmp( s->sect.name,".rsrc" ) ) continue;

		openRsrcTree( s );
		if( Rsrc *r=findRsrc( type,id,lang ) ){
			delete[] r->data;
			r->data_sz=data_sz;
			r->data=d_new char[data_sz];
			memcpy( r->data,data,data_sz );
			closeRsrcTree( s );
			return true;
		}
		closeRsrcTree( s );
	}
	return false;
}

void closeImage(){
	if( !img_file ) return;

	fstream out( img_file,ios_base::binary|ios_base::out|ios_base::trunc );
	//saveImage( out );
	saveImage_test( out );
	out.close();

	for( ;sections.size();sections.pop_back() ) delete sections.back();
	delete[] ddir;
	delete opts;
	delete head;
	delete[] stub;
	img_file=0;
}


#endif



