package yetmorecode.ghidra.format.lx.model;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import yetmorecode.file.format.lx.LinearExecutable;
import yetmorecode.file.format.lx.LinearObjectTableEntry;
import yetmorecode.ghidra.lx.InvalidHeaderException;
import yetmorecode.ghidra.lx.Options;


public class Executable extends LinearExecutable {
    private BinaryReader reader;
    
    public boolean isUnbound = false;
    
    // MZ header
    public DOSHeader mz;
    
    // DOS/16 headers
    public HashMap<Long, Dos16Header> dos16Headers =  new HashMap<Long, Dos16Header>();
    public DOSHeader mzSecondary;
    
    // VxD version resource (i.e. e32_winresoff)
    public VxDVersionResource vxd;

    // LE/LX metadata tables used to recover symbols and entry points
    public ImportTables imports;
    public EntryTable entryTable;
    public NameTable residentNames;
    public NameTable nonResidentNames;
    
    // When there is no MZ header (i.e. unbound LE-Style executables), the new file header starts at 0
    public long lfanew = 0;
    public long lfamz = 0;
    
	public Executable(ByteProvider bp, Options options) throws IOException, InvalidHeaderException {
    	reader = new BinaryReader(bp, true);
    	try {
	    	// Try reading MZ header
	        mz = DOSHeader.createDOSHeader(reader);
	        if (mz.isDosSignature()) {
	        	if (mz.e_lfarlc() == 0x40) {
	        		// New exe style (with e_lfanew)
	        		lfanew = mz.e_lfanew();
	        	} else {
	        		// Old exe style (without e_lfanew)
	        		long secondaryOffset = (mz.e_cp()-1)*512 + mz.e_cblp();
	        		Dos16Header bwHeader;
	        		try {
	        			do {
	        				bwHeader = new Dos16Header(reader, secondaryOffset);
	        				dos16Headers.put(secondaryOffset, bwHeader);
	        				secondaryOffset = bwHeader.next_header_pos;
	        			} while (secondaryOffset > 0);
	        		} catch (InvalidHeaderException exception) {
	        			// Done walking BW headers
	        		}
	        		reader.setPointerIndex(secondaryOffset);
	        		mzSecondary = DOSHeader.createDOSHeader(reader);
	        		lfamz = secondaryOffset;
	        		lfanew = secondaryOffset + mzSecondary.e_lfanew();
	        	}
	        }
    	} catch (Exception e) {}
    	
    	// LX header
    	header = new Header(reader, lfanew);
    	if (header.winresoff > 0 && header.winreslen > 0) {
    		vxd = new VxDVersionResource(reader, lfamz + header.winresoff);
    	}
    	
    	// Object record table
    	for (int object = 0; object < header.objectCount; object++) {
    		objects.add(new ObjectTableEntry(this, object));
    	}
    	
    	// Page record table
    	for (int page = 0; page < header.pageCount; page++) {
    		if (header.isLe()) {
    			pageRecords.add(new LePageMapEntry(this, page));	
    		} else {
    			pageRecords.add(new LxPageMapEntry(this, page));
    		}
    		
    	}
    	
    	// Read fixup page table
    	fixupTable = new long[header.pageCount+1];
    	var tableOffset = lfanew + header.fixupPageTableOffset;
    	for (int i = 0; i <= header.pageCount; i++) {
    		fixupTable[i] = getReader().readInt(tableOffset + i * 4);
    	}
    	
    	// Read fixups
    	var fixupRecordOffset = lfanew + header.fixupRecordTableOffset;
    	fixupCount = 0;
    	for (var object : objects) {
    		for (int i = 0; i < object.pageCount; i++) {
    			var page = object.pageTableIndex + i;
        		fixups.put(page, new ArrayList<>());
        		var fixupBegin = getFixupBegin(page);
        		var fixupEnd = getFixupEnd(page);
        		var fixupDataSize = fixupEnd - fixupBegin;
        		var current = 0;
    			while (current < fixupDataSize) {
    				var fixup = new FixupRecord(
						reader, 
						fixupRecordOffset + fixupBegin + current, 
						++fixupCount, 
						options.getBaseAddress(object),
						i
    				);
    				fixups.get(page).add(fixup);
    				current += fixup.size;
    			}
    		}
    	}

		//	Import Module / Procedure Name Tables (header relative).
		//	The procedure table ends right before the data pages section.
		if (header.importModuleNameCount > 0 && header.importModuleNameTableOffset > 0) {
			long procTableEnd = (lfamz + header.dataPagesOffset) - lfanew;
			long procTableLength = Math.max(0, procTableEnd - header.importProcedureNameTableOffset);
			imports = new ImportTables(
				reader,
				lfanew + header.importModuleNameTableOffset,
				header.importModuleNameCount,
				lfanew + header.importProcedureNameTableOffset,
				procTableLength
			);
		}

		//	Resident Name Table sits between the resource table and the entry table
		//	(header relative).
		if (header.residentNameTableOffset > 0 && header.entryTableOffset > header.residentNameTableOffset) {
			residentNames = new NameTable(
				reader,
				lfanew + header.residentNameTableOffset,
				lfanew + header.entryTableOffset
			);
		}

		//	Entry Table (header relative). It is terminated by a zero count, but the
		//	module directives table / fixup page table gives a hard upper bound.
		if (header.entryTableOffset > 0) {
			int entryEnd = (header.directivesTableOffset > header.entryTableOffset)
				? header.directivesTableOffset
				: header.fixupPageTableOffset;
			entryTable = new EntryTable(reader, lfanew + header.entryTableOffset, lfanew + entryEnd);
		}

		//	Non-Resident Name Table (file relative per the OS/2 spec).
		if (header.nameTableOffset > 0 && header.nameTableLength > 0) {
			long nonResidentOffset = lfanew + header.nameTableOffset;
			nonResidentNames = new NameTable(reader, nonResidentOffset, nonResidentOffset + header.nameTableLength);
		}
    }
	
	/**
	 * Returns the best name available for an entry table ordinal, consulting the
	 * non-resident name table first and the resident name table second.
	 */
	public String getEntryName(int ordinal) {
		if (nonResidentNames != null) {
			String name = nonResidentNames.byOrdinal.get(ordinal);
			if (name != null) {
				return name;
			}
		}
		if (residentNames != null) {
			return residentNames.byOrdinal.get(ordinal);
		}
		return null;
	}
	
    /**
     * Returns the underlying binary reader.
     * @return the underlying binary reader
     */
    public BinaryReader getBinaryReader() {
        return reader;
    }

    public BinaryReader getReader() {
		return reader;
	}

	public long getFixupBegin(int page) {
		return fixupTable[page-1];
	}
	
	public long getFixupEnd(int page) {
		return fixupTable[page];
	}
	
	public int totalFixups() {
		int total = 0;
		for (var i = 1; i <= header.pageCount; i++) {
			total += fixups.get(i).size();
		}
		return total;
	}
	
	public boolean objectHasFixups(LinearObjectTableEntry object) {
		var total = 0;
		for (int i = 0; i < object.pageCount; i++) {
			var page = object.pageTableIndex + i;
			total += getFixupEnd(page) - getFixupBegin(page);
		}
		return total > 0;
	}
}

