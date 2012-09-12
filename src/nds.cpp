/*
	IDA Loader module for Nintendo DS (NDS) ROM files.
	Written by Dennis Elser.
	Fixed / Updated by Franck Charlet (hitchhikr@australia.edu).

	Comments:
	---------
	This is the first loader module for IDA
	I have written so far. It might therefore
	give inaccurate results.
	Feedback, bugreports and donations are welcome =)

	dennis[at]backtrace[dot]de / www[dot]backtrace[dot]de


	Credits:
	--------
	-	Rafael Vuijk for the CRC16 Code and the
		NDS ROM Header layout
	-	DataRescue for providing loader sourcecode
		with the IDA SDK

	History:
	--------

	2004/12/29 initial version
	
	- can disassemble arm7 or arm9 code
	- can add additional information about
	  the ROM to database

	2005/01/01 version 1.1

	- creates a section for the whole RAM area
	  and maps the cartridge's code into it
	- adds more additional information about
	  the ROM to database

	2006/01/17 version 1.11

	- updated sourcecode to be compatible with IDA4.8 SDK

	2007/10/29 version 1.12

	- updated sourcecode to be compatible with IDA5.x SDK
	- added more infos in header structure
	- fixed the allowed memory ranges
	- added more infos in disassembled header

	2008/07/17 version 1.13

   - correctly positioned at program's entry point
   - corrected the selection of processors

*/

#include <windows.h>
#include "../idaldr.h"
#include "nds.h"

//defines
#define version "v1.13"

//global data
nds_hdr hdr;

//--------------------------------------------------------------------------
//
//		the code of CalcCRC16() has been taken from Rafael Vuijk's "ndstool"
//		and slightly been modified by me
//
unsigned short CalcCRC16(nds_hdr *ndshdr)
{
	unsigned short crc16 = 0xFFFF;
	for(int i = 0; i < 350; i++)
	{
		unsigned char data = *((unsigned char *) ndshdr + i);
		crc16 = (crc16 >> 8) ^ crc16tab[(crc16 ^ data) & 0xFF];
	}
	return crc16;
}

//--------------------------------------------------------------------------
//
//      check input file format. if recognized, then return 1
//      and fill 'fileformatname'.
//      otherwise return 0
//
int idaapi accept_file(linput_t *li, char fileformatname[MAX_FILE_FORMAT_NAME], int n)
{

	ulong filelen;

	if( n!= 0 )
		return 0;

	// get filesize
	filelen = qlsize(li);

	// quit, if file is smaller than size of NDS header
	if (filelen < sizeof(nds_hdr))
		return 0;

	// set filepos to offset 0
	qlseek(li, 0, SEEK_SET);

	// read whole NDS header
	if(qlread(li, &hdr, sizeof(nds_hdr)) != sizeof(nds_hdr))
		return 0;

	// check validity of CRC16 value of header
	// this is used to determine if this file is an NDS file
	if (CalcCRC16(&hdr) != hdr.headerCRC16)
		return 0;

	// this is the name of the file format which will be
	// displayed in IDA's dialog
	qstrncpy(fileformatname, "Nintendo DS ROM", MAX_FILE_FORMAT_NAME);

   // Default processor
   set_processor_type("ARM", SETPROC_ALL);

	return (1 | ACCEPT_FIRST);
}

//--------------------------------------------------------------------------
//
//      load file into the database.
//
void load_file(linput_t *li, ushort /*neflag*/, const char * /*fileformatname*/)
{

   int i;
	ea_t startEA;
	ea_t endEA;
	long offset;
	int ARM9;
   int found_mem_block;
   ea_t entry_point;

   // go to file-offset 0
	qlseek(li, 0, SEEK_SET);

	// and read the whole header
	qlread(li, &hdr, sizeof(nds_hdr));

	// display a messagebox asking the user for details
	//  1 - Yes
	//  0 - No
	// -1 - Cancel
	int answer = askyn_cv(1,
		"NDS Loader by Dennis Elser.\n\n"
		"This file possibly contains ARM7 *and* ARM9 code.\n"
		"Choose \"Yes\" to load the ARM9 executable,\n"
		"\"No\" to load the ARM7 executable\n\n"
		"Please note that this loader has not been thoroughly tested!\n"
		"If you discover a bug, please let me know: dennis@backtrace.de\n"
		"\nDo you want to load the ARM9 code?\n\n"
		,NULL
	);

	// user chose "cancel" ?
	if(answer==BADADDR)
   {
		qexit(1);
   }

	// user chose "yes" = arm9
	if(answer)
	{
		set_processor_type("ARM", SETPROC_ALL);
		// init
		inf.startIP = inf.beginEA = hdr.arm9_entry_address;
		startEA = hdr.arm9_ram_address;
		endEA = hdr.arm9_ram_address + hdr.arm9_size;
		offset = hdr.arm9_rom_offset;
		ARM9 = TRUE;
		// sanitycheck
		if (qlsize(li) < offset+hdr.arm9_size)
      {
			qexit(1);
      }
	}
	// user chose "no" = arm7
	else
	{
		set_processor_type("ARM710A", SETPROC_ALL);
		// init
		inf.startIP = inf.beginEA = hdr.arm7_entry_address;
		startEA = hdr.arm7_ram_address;
		endEA = hdr.arm7_ram_address + hdr.arm7_size;
		offset = hdr.arm7_rom_offset;
		ARM9 = FALSE;
		// sanitycheck
		if(qlsize(li) < offset+hdr.arm7_size)
      {
			qexit(1);
      }
	}
	
	// check if segment lies within legal RAM blocks
	found_mem_block = FALSE;
   for(i = 0; i < sizeof(memory) / sizeof(MEMARRAY); i++) {
      if(startEA >= memory[i].start || endEA <= memory[i].end) 
      {
         found_mem_block = TRUE;
         break;
      }
   }
   if(!found_mem_block)
   {
	   qexit(1);
   }

	// map selector
	set_selector(1, 0);
	inf.start_cs = 1;

	// create a segment for the legal RAM blocks
	for(i = 0; i < sizeof(memory) / sizeof(MEMARRAY); i++) {
	   if (!add_segm(1, memory[i].start, memory[i].end, "RAM", CLASS_CODE))
      {
		   qexit(1);
      }
   }

	// enable 32bit addressing
	set_segm_addressing(getseg( startEA ), 1);

	// load file into RAM area
	file2base(li, offset, startEA, endEA, FILEREG_PATCHABLE);
	
   entry_point = ARM9 == TRUE ? hdr.arm9_entry_address : hdr.arm7_entry_address;

	// add additional information about the ROM to the database
	describe(startEA, true, ";   Created with NDS Loader %s.\n", version);
	describe(startEA, true, ";   Author 1:           dennis@backtrace.de");
	describe(startEA, true, ";   Author 2:           hitchhikr@australia.edu\n");
	describe(startEA, true, ";   Game Title:         %s\n", hdr.title);
	describe(startEA, true, ";   Processor:          ARM%c", ARM9 == TRUE ? '9' : '7');
	describe(startEA, true, ";   ROM Header size:    0x%08X", hdr.headerSize);
	describe(startEA, true, ";   Header CRC:         0x%04X\n", hdr.headerCRC16);
	describe(startEA, true, ";   Offset in ROM:      0x%08X", ARM9 == TRUE ? hdr.arm9_rom_offset : hdr.arm7_rom_offset);
	describe(startEA, true, ";   Array:              0x%08X - 0x%08X (%d bytes)", startEA, endEA, ARM9 == TRUE ? hdr.arm9_size : hdr.arm7_size);
	describe(startEA, true, ";   Entry point:        0x%08X\n", entry_point);

	describe(startEA, true, ";   --- Beginning of ROM content ---", NULL);
	if(entry_point != startEA)
   {
      describe(entry_point, true, ";   --- Entry point ---", NULL);
	}
   describe(endEA, true, ";   --- End of ROM content ---", NULL);
   if(entry_point != BADADDR)
   {
      inf.start_cs = 0;
      inf.startIP = entry_point;
   }
}

//----------------------------------------------------------------------
//
//      LOADER DESCRIPTION BLOCK
//
//----------------------------------------------------------------------
loader_t LDSC =
{
  IDP_INTERFACE_VERSION,
  0,                            // loader flags
//
//      check input file format. if recognized, then return 1
//      and fill 'fileformatname'.
//      otherwise return 0
//
  accept_file,
//
//      load file into the database.
//
  load_file,
//
//      create output file from the database.
//      this function may be absent.
//
  NULL,
  NULL,
  NULL,
};
