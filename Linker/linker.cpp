#include "std.h"
#include "linker.h"
#include "image_util.h"



class BBModule : public Module {

public:
    BBModule();
	BBModule( istream &in );
	~BBModule();

	void *link( Module *libs );
	bool createExe( const char *exe_file,const char *dll_file );
    bool createExe_test( const char *exe_file,const char *dll_file );
	int getPC();

	void emit( int byte );
	void emitw( int word );
	void emitd( int dword );
	void emitx( void *mem,int sz );
	bool addSymbol( const char *sym,int pc );
	bool addReloc( const char *dest_sym,int pc,bool pcrel );

	bool findSymbol( const char *sym,int *pc );

private:
    char *data = nullptr;
    int data_sz = 0, pc = 0;
    bool linked = false;

    map<string, int> symbols;
    map<int, string> rel_relocs, abs_relocs;

    bool findSym(const string &t, Module *libs, int *n) {
        if (findSymbol(t.c_str(), n)) return true;
        if (libs && libs->findSymbol(t.c_str(), n)) return true;
        cerr << "Blitz Linker Error: Symbol '" << t << "' not found" << endl;
        return false;
    }

    void ensure(int n) {
        if (pc + n <= data_sz) return;
        data_sz = data_sz / 2 + data_sz;
        if (data_sz < pc + n) data_sz = pc + n;
        char *old_data = data;
        data = new char[data_sz];
        if (old_data) {
            memcpy(data, old_data, pc);
            delete[] old_data;
        }
    }

};

BBModule::BBModule():data(0),data_sz(0),pc(0),linked(false){
}

BBModule::~BBModule(){
	if( linked ) VirtualFree( data,0,MEM_RELEASE );
	else delete[] data;
}

void *BBModule::link(Module *libs) {
	if( linked ) return data;

	int dest;
	map<int,string>::iterator it;

	char *p=(char*)VirtualAlloc( 0,pc,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE );
    memcpy( p,data,pc );
	delete[] data;
	data=p;

	linked=true;

	for( it=rel_relocs.begin();it!=rel_relocs.end();++it ){
		if( !findSym( it->second,libs,&dest ) ) return 0;
		int *p=(int*)(data+it->first);*p+=(dest-(int)p);
	}

	for( it=abs_relocs.begin();it!=abs_relocs.end();++it ){
		if( !findSym( it->second,libs,&dest ) ) return 0;
		int *p=(int*)(data+it->first);*p+=dest;
	}

	return data;
}

int BBModule::getPC(){
	return pc;
}

//NOT USED
/*BBModule::BBModule( istream &in ){

}*/

void BBModule::emit( int byte ){
	ensure(1);data[pc++]=byte;
}

void BBModule::emitw( int word ){
	ensure(2);*(short*)(data+pc)=word;pc+=2;
}

void BBModule::emitd( int dword ){
	ensure(4);*(int*)(data+pc)=dword;pc+=4;
}

void BBModule::emitx( void *mem,int sz ){
	ensure(sz);memcpy( data+pc,mem,sz );pc+=sz;
}
bool BBModule::addSymbol( const char *sym,int pc ){
	string t(sym);
	if( symbols.find( t )!=symbols.end() ) return false;
	symbols[t]=pc;return true;
}

bool BBModule::addReloc( const char *dest_sym,int pc,bool pcrel ){
	map<int,string> &rel=pcrel ? rel_relocs : abs_relocs;
	if( rel.find( pc )!=rel.end() ) return false;
	rel[pc]=string(dest_sym);return true;
}


bool BBModule::findSymbol( const char *sym,int *pc ){
        string t=string(sym);
        map<string,int>::iterator it=symbols.find( t );
        if( it==symbols.end() ) return false;
        // *pc=it->second + (int)data;
        *pc = it->second + reinterpret_cast<intptr_t>(data);
        return true;

}

int Linker::version(){
	return VERSION;
}


bool Linker::canCreateExe(){
#ifdef DEMO
        return false;
#else
        return true;
#endif
}

Module *Linker::createModule(){
       return d_new BBModule();
}

void Linker::deleteModule( Module *mod ){
       if (mod) delete mod;
}

Linker * linkerGetLinker(){
	static Linker linker;return &linker;
}

bool BBModule::createExe( const char *exe_file,const char *dll_file )   {
#ifdef DEMO
	return false;
#else

	//find proc address of bbWinMain
	HMODULE hmod=LoadLibrary( dll_file );if( !hmod ) return false;
	//int proc=(int)GetProcAddress( hmod,"_bbWinMain@0" );
	int proc=(int)GetProcAddress( hmod,"bbWinMain@0" );
    //cout << proc << endl;
		// Cast proc to a function pointer and call it
	//typedef void(__stdcall * bbWinMainFunc)();
	//bbWinMainFunc bbWinMain = (bbWinMainFunc)proc;
	//bbWinMain(); // Calls the bbWinMain function

	int entry=proc-(int)hmod;FreeLibrary( hmod );if( !proc ) return false;


    if( !CopyFile( dll_file,exe_file,false ) ) return false;

if( !openImage( exe_file ) ) return false;

makeExe( entry );
    qstreambuf buf;
	iostream out( &buf );

	map<string,int>::iterator it;
	map<int,string>::iterator rit;

	//write the code
	int sz=pc;out.write( (char*)&sz,4 );out.write( data,pc );
//
//	//write symbols
//	sz=symbols.size();out.write( (char*)&sz,4 );
//	for( it=symbols.begin();it!=symbols.end();++it ){
//		string t=it->first+'\0';
//		out.write( t.data(),t.size() );
//		sz=it->second;out.write( (char*)&sz,4 );
//	}
//
//	//write relative relocs
//	sz=rel_relocs.size();out.write( (char*)&sz,4 );
//	for( rit=rel_relocs.begin();rit!=rel_relocs.end();++rit ){
//		string t=rit->second+'\0';
//		out.write( t.data(),t.size() );
//		sz=rit->first;out.write( (char*)&sz,4 );
//	}
//
//	//write absolute relocs
//	sz=abs_relocs.size();out.write( (char*)&sz,4 );
//	for( rit=abs_relocs.begin();rit!=abs_relocs.end();++rit ){
//		string t=rit->second+'\0';
//		out.write( t.data(),t.size() );
//		sz=rit->first;out.write( (char*)&sz,4 );
//	}
//
//	replaceRsrc( 10,1111,1033,buf.data(),buf.size() );

	closeImage();

	return true;

#endif
 }


bool BBModule::createExe_test( const char *exe_file,const char *dll_file )   {
#ifdef DEMO
	return false;
#else
//HMODULE hmod=LoadLibrary( ".\\_release\\bin\\Debug\\runtime.dll" );
HMODULE hmod=LoadLibrary( dll_file );if( !hmod ) return false;
int proc=(int)GetProcAddress( hmod,"_bbWinMain@0" );
//int proc=(int)GetProcAddress( hmod,"bbWinMain@0" );
//
int entry=proc-(int)hmod;FreeLibrary( hmod );if( !proc ) return false;
//
//
if( !CopyFile( dll_file,exe_file,false ) ) return false;
//
if( !openImage( exe_file ) ) return false;
//
	makeExe( entry );

	//create module
	//code size: code...
	//num_syms:  name,val...
	//num_rels:  name,val...
	//num_abss:  name,val...
	//
	qstreambuf buf;
	 //streambuf buf;
	iostream out( &buf );

	map<string,int>::iterator it;
	map<int,string>::iterator rit;

	//pc = 0x137; //0x70;
	//data = new char[0x137];
    //memset(data,0xFF,0x137);

	int sz=pc;out.write( (char*)&sz,4 );out.write( data,pc );

//	write symbols
	sz=symbols.size();out.write( (char*)&sz,4 );
	//cout << symbols.size()<< endl;
	for( it=symbols.begin();it!=symbols.end();++it ){
		string t=it->first+'\0';
		out.write( t.data(),t.size() );
		sz=it->second;out.write( (char*)&sz,4 );
	}

	//write relative relocs
	if (rel_relocs.size()) {
	sz=rel_relocs.size();out.write( (char*)&sz,4 );
	//cout << rel_relocs.size()<< endl;
	for( rit=rel_relocs.begin();rit!=rel_relocs.end();++rit ){
		string t=rit->second+'\0';
		out.write( t.data(),t.size() );
		sz=rit->first;out.write( (char*)&sz,4 );
	}
    }else{
    cout << "no rel_relocs" << endl;
    }

	//write absolute relocs
	if (abs_relocs.size()) {

	sz=abs_relocs.size();out.write( (char*)&sz,4 );
	//cout << abs_relocs.size() << endl;
	for( rit=abs_relocs.begin();rit!=abs_relocs.end();++rit ){
		string t=rit->second+'\0';
		out.write( t.data(),t.size() );
		sz=rit->first;out.write( (char*)&sz,4 );
	}
	    }else{
    cout << "no abs_relocs" << endl;
    }

	replaceRsrc( 10,1111,1033,buf.data(),buf.size() );

	closeImage();

	return true;

#endif
 }

