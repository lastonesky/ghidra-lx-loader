package yetmorecode.ghidra.lx;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.*;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.program.model.reloc.RelocationTable;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.MemReferenceImpl;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.UsrException;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.data.ArrayDataType;
import yetmorecode.file.format.lx.LinearFixupRecord;
import yetmorecode.file.format.lx.LinearObjectTableEntry;
import yetmorecode.ghidra.format.lx.datatype.FixupSectionType;
import yetmorecode.ghidra.format.lx.datatype.LoaderSectionType;
import yetmorecode.ghidra.format.lx.model.FixupRecord;
import yetmorecode.ghidra.format.lx.model.Header;
import yetmorecode.ghidra.format.lx.model.Executable;

/**
 * LxLoader - LX/LE/LC executable format loader
 * 
 * This loader is able to to load executable files of the LX/LE/LC format.
 * 
 * Linear Executable is an executable file format. 
 * It is used by OS/2, MS-DOS (DOS extender), and by MS Windows VxD files. 
 * It is a successor to NE (New Executable). 
 * There are two main varieties of it: LX (32-bit), and LE (mixed 16/32-bit).
 * LC variety is using compression (hence the C).
 * 
 * @author yetmorecode@posteo.net
 */
public abstract class LinearLoader extends AbstractLibrarySupportLoader {

	/**
	 * Preferred language/compiler for DOS extenders.  The Watcom ABI is provided by
	 * this extension (see data/languages/x86-watcom.ldefs) and is a good default for
	 * DOS/4GW and DOS/16 style programs.
	 */
	private static final String WATCOM_LANGUAGE = "watcom:LE:32:default";
	private static final String WATCOM_COMPILER_SPEC = "watcom";

	/**
	 * Fallback to the built-in x86 language.  Ghidra 12.1 removed the generic
	 * "default" compiler spec, so a concrete compiler spec must be used.
	 */
	private static final String X86_LANGUAGE = "x86:LE:32:default";
	private static final String X86_COMPILER_SPEC = "gcc";

	/**
	 * Additional built-in x86 compiler specs offered as alternatives, so the user
	 * can pick the ABI that actually produced the module (Borland C++, MSVC,
	 * Delphi, ...) instead of being forced into the Watcom register convention.
	 * A wrong ABI makes every recovered function signature systematically wrong,
	 * which is a common source of bogus decompiler output for LE/LX modules.
	 */
	private static final String X86_BORLAND_COMPILER_SPEC = "borlandcpp";
	private static final String X86_DELPHI_COMPILER_SPEC = "borlanddelphi";
	private static final String X86_MSVC_COMPILER_SPEC = "windows";

	protected final static String CHECK = " " + (new String(new int[] { 0x2713 }, 0, 1)) + " ";
	protected final static String CLOCK = " " + (new String(new int[] { 0x231b }, 0, 1)) + " ";
	protected final static String HORSE = " " + (new String(new int[] { 0x2658 }, 0, 1)) + " ";
	protected final static String ARROW = " " + (new String(new int[] { 0x2794 }, 0, 1)) + " ";
	
	protected MessageLog messageLog;
	protected Options loaderOptions = new Options();
	
	@Override
	public abstract String getName();

	public abstract void checkFormat(BinaryReader reader) throws IOException, InvalidHeaderException;
	
	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();
		if (provider.length() < 4) {
			return loadSpecs;
		}
		var reader = new BinaryReader(provider, true);
			try {
			checkFormat(reader);
			// Ghidra 12.1 no longer resolves the old "x86:LE:32:default/default"
			// pair, so every offered spec must name a concrete compiler spec.
			//
			// The Watcom ABI (shipped with this extension, see
			// data/languages/x86-watcom.ldefs) stays the preferred default because
			// DOS/4GW and DOS/16 modules are most commonly Watcom-built.  The
			// remaining built-in x86 specs are offered as alternatives so a Borland,
			// MSVC or Delphi module can be loaded with the matching calling
			// convention instead of being forced into the Watcom register ABI.
			loadSpecs.add(new LoadSpec(this, 0,
				new LanguageCompilerSpecPair(WATCOM_LANGUAGE, WATCOM_COMPILER_SPEC), true));
			loadSpecs.add(new LoadSpec(this, 0,
				new LanguageCompilerSpecPair(X86_LANGUAGE, X86_BORLAND_COMPILER_SPEC), false));
			loadSpecs.add(new LoadSpec(this, 0,
				new LanguageCompilerSpecPair(X86_LANGUAGE, X86_MSVC_COMPILER_SPEC), false));
			loadSpecs.add(new LoadSpec(this, 0,
				new LanguageCompilerSpecPair(X86_LANGUAGE, X86_DELPHI_COMPILER_SPEC), false));
			loadSpecs.add(new LoadSpec(this, 0,
				new LanguageCompilerSpecPair(X86_LANGUAGE, X86_COMPILER_SPEC), false));
		} catch (IOException e) {
			Msg.error(this, String.format("IOException while parsing LxExecutable: %s", e.getMessage()));
			e.printStackTrace();
		} catch (InvalidHeaderException e) {
			// Everything is ok, but the provided data is not a valid LX/LE/LC
		}
		return loadSpecs;
	}
	
	public abstract void onLoadSuccess(Program program);

	@Override
	protected void load(Program program, ImporterSettings settings) throws CancelledException, IOException {
		var monitor = settings.monitor();
		var provider = settings.provider();

		if (monitor.isCancelled()) {
			return;
		}
		messageLog = settings.log();
		messageLog.clear();
		log(CLOCK + "Loading '%s'", program.getDomainFile());
		
		// Try parsing the executable
		int id = program.startTransaction(ARROW + "Loading..");
		monitor.setIndeterminate(true);
		monitor.setMessage(String.format(ARROW + "Loading %s", getName()));
		try {
			// Parse EXE from file
			var executable = new Executable(provider, loaderOptions);
			
			// Map IMAGE data (MZ, LX)
			createImageMappings(executable, program, provider, monitor);
			
			// Map objects
			createObjects(executable, program, monitor);
			
			// Add entrypoint, disassemble, ..
			createEntrypoint(executable, program, monitor);

			// Recover exported entry points from the Entry Table and external
			// references from the import fixups.
			createEntryTableSymbols(executable, program, monitor);
			createImportSymbols(executable, program, monitor);
			
			onLoadSuccess(program);
			program.endTransaction(id, true);
		} catch (Exception e) {
			Msg.error(this, String.format("Exception in `load` while parsing LxExecutable: %s", e.getMessage()));
			e.printStackTrace();
			program.endTransaction(id, false);
		}
	}
	
	/**
	 * Creates MZ and LE exe image memory block (in OTHER space) and types the data
	 * 
	 * LX/LE have 3 main regions:
	 * - header (aka information section)
	 * - loader section (mostly fixup/relocation data)
	 * - data pages section
	 */
	private void createImageMappings(Executable e, Program program, ByteProvider provider, TaskMonitor monitor) throws CancelledException, IOException, AddressOverflowException, UsrException {
		var header = (Header)e.header;
		var dosHeader = e.mz;
		var fileBytes = MemoryBlockUtils.createFileBytes(program, provider, monitor);
		Address addr;		
		monitor.setMessage(String.format(ARROW + "Mapping Image data", header.getTypePrefix().toUpperCase()));

		// Map the whole image for inspection
		var b = MemoryBlockUtils.createInitializedBlock(
			program, 
			true, 
			".image", AddressSpace.OTHER_SPACE.getAddress(0), 
			fileBytes, 0, fileBytes.getSize(), 
			"Raw EXE image data", 
			null, 
			false, false, false, 
			null
		);
		
		if (e.mz.isDosSignature()) {
			// MZ image
			addr = b.getStart();
			createData(program, addr, dosHeader.toDataType());
			program.getSymbolTable().createLabel(b.getStart(), String.format("IMG_%08X_MZ_HEADER", 0), SourceType.USER_DEFINED);
			log(CHECK + "MZ Header");			
		}
		for (var s : e.dos16Headers.entrySet()) {
			// BW DOS/16 image
			addr = b.getStart().add(s.getKey());
			createData(program, addr, s.getValue().toDataType());
			program.getSymbolTable().createLabel(addr, String.format("IMG_%08X_DOS16_HEADER", s.getKey()), SourceType.USER_DEFINED);
			log(CHECK + "BW DOS/16 Header");
		}
		
		if (e.mzSecondary != null) {
			// MZ image
			addr = b.getStart().add(e.lfamz);
			createData(program, addr, e.mzSecondary.toDataType());
			program.getSymbolTable().createLabel(addr, String.format("IMG_%08X_MZ_HEADER", e.lfamz), SourceType.USER_DEFINED);
			log(CHECK + "MZ Header");			
		}

		// LE header
		addr = b.getStart().add(e.lfanew);
		createData(program, addr, header.toDataType());
		program.getSymbolTable().createLabel(addr, String.format("IMG_%08X_LE_HEADER", e.lfanew), SourceType.USER_DEFINED);
		log(CHECK + "LX Header");
		
		if (loaderOptions.mapExtra) {
			// LE loader section
			addr = b.getStart().add(e.lfanew + header.objectTableOffset);
			monitor.setMessage(String.format(ARROW + "Mapping LX Loader section"));
			createData(
				program, 
				addr,
				new LoaderSectionType(e, header.fixupPageTableOffset - header.objectTableOffset)
			);
			program.getSymbolTable().createLabel(addr, String.format("IMG_%08X_LE_LOADER", e.lfanew + header.objectTableOffset), SourceType.USER_DEFINED);
			log(CHECK + "LX Loader Section");
		
			// LE fixup section
			var dm = program.getDataTypeManager();
			var cat = dm.createCategory(new CategoryPath("/_le/_fixup"));
			addr = b.getStart().add(e.lfanew + header.fixupPageTableOffset);
			monitor.setMessage(String.format(ARROW + "Mapping Fixups (%d total)", e.fixupCount));
			monitor.setIndeterminate(true);
			monitor.setMaximum(e.fixupCount);
			monitor.setProgress(0);
			var ft = new FixupSectionType(
				e, 
				(int) (e.lfamz + header.dataPagesOffset - e.lfanew - header.fixupPageTableOffset),
				loaderOptions,
				cat,
				program,
				b,
				monitor
			);
			createData(program, addr, ft);
			program.getSymbolTable().createLabel(addr, String.format("IMG_%08X_LE_FIXUP", e.lfanew + header.fixupPageTableOffset), SourceType.USER_DEFINED);
			log(CHECK + "LX Fixups");
		
			// LE Data Section
			addr = b.getStart().add(e.lfamz + header.dataPagesOffset);
			monitor.setMessage(String.format(ARROW + "Mapping data pages (%d total)", e.header.pageCount));
			var all = new StructureDataType("IMG_LE_DATA", 0);
			
			// Full size pages
			for (var i = 0; i < e.header.pageCount-1; i++) {
				var dt = new ArrayDataType(StructConverter.BYTE, header.pageSize, 0); 
				addr = b.getStart().add(e.lfamz + header.dataPagesOffset + i * header.pageSize);
				all.add(dt, "page_" + (i+1), "");
			}
			// Last page
			var dt = new ArrayDataType(StructConverter.BYTE, header.lastPageSize, 0);
			all.add(dt, "page_" + header.pageCount, "");
			
			addr = b.getStart().add(e.lfamz + header.dataPagesOffset);
			createData(program, addr, all);
			log(CHECK + "LX Data Pages");
			
			if (e.vxd != null) {
				// VxD Version Resource
				addr = b.getStart().add(e.lfamz + header.winresoff);
				createData(program, addr, e.vxd.toDataType());
				
				program.getSymbolTable().createLabel(addr, String.format("IMG_%08X_VXD_VERSION", e.lfamz + header.winresoff), SourceType.USER_DEFINED);
				log(CHECK + "VxD Windows VERSIONINFO");
			}
		}
	}
	
	private void createObjects(Executable executable, Program program, TaskMonitor monitor) throws IOException, UsrException {
		// Map each object
		var space = program.getAddressFactory().getDefaultAddressSpace();
		for (var object : executable.objects) {
			monitor.setMessage(String.format(ARROW + "Mapping .object%d", object.number));
			byte[] block = createObjectBlock(program, executable, object, object.number == executable.objects.size());
			var memoryBlock = program.getMemory().createInitializedBlock(
				".object" + object.number, 
				space.getAddress(loaderOptions.getBaseAddress(object)), 
				new ByteArrayInputStream(block), 
				object.size, 
				monitor, false
			);

			// Honour the object's own protection bits from the object table.  Ghidra
			// needs read access for analysis in every case, but the write/execute bits
			// are what tell the analyzer whether a block contains (disassemblable) code
			// or (constant) data, so they must come from the file and not from defaults.
			boolean readable = (object.flags & LinearObjectTableEntry.FLAG_READABLE) != 0;
			boolean writeable = (object.flags & LinearObjectTableEntry.FLAG_WRITEABLE) != 0;
			boolean executableFlag = (object.flags & LinearObjectTableEntry.FLAG_EXECUTABLE) != 0;
			memoryBlock.setRead(true);
			memoryBlock.setWrite(writeable);
			memoryBlock.setExecute(executableFlag);
			memoryBlock.setComment(String.format(
				"Object #%d, %s (flags %04x)",
				object.number,
				(readable ? "r" : "-") + (writeable ? "w" : "-") + (executableFlag ? "x" : "-"),
				object.flags
			));
		}
	}
	
	private Data createData(Program program, Address address, DataType dt) {
		try {
			Data d = program.getListing().getDataAt(address);
			if (d == null || !dt.isEquivalent(d.getDataType())) {
				program.getListing().createData(address, dt);
			}
			return d;
		}
		catch (CodeUnitInsertionException e) {
			Msg.warn(this, "LX data markup conflict at " + address + ": " + e.getMessage());
			e.printStackTrace();
		}
		return null;
	}
	
	private byte[] createObjectBlock(Program program, Executable le, LinearObjectTableEntry object, boolean isLastObject) throws IOException {
		var space = program.getAddressFactory().getDefaultAddressSpace();
		var relocationTable = program.getRelocationTable();

		var header = (Header)le.header;
		var pageSize = header.pageSize; 
		
		// Temporary memory to assemble all pages to one block
		byte block[] = new byte[object.size+4096];
		var blockIndex = 0;
		
		// Some statistics on fixups
		int fixupsHandled = 0;
		int fixupsUnhandled = 0;
		int fixupsByType[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0 };

		// Loop through all pages for this object, apply fixups per page and add them together
		for (var i = 0; i < object.pageCount; i++) {
			// Page map indices are one-based 
			var index = object.pageTableIndex + i;
			
			//LxPageMapEntry entry = new LxPageMapEntry(le, pageMapOffset + (index-1) * 4);
			var entry = le.pageRecords.get(index-1);
			var pageOffset  = le.lfamz + header.dataPagesOffset + (entry.getOffset()-1) * pageSize;
			
			// Read page from file
			BinaryReader r = le.getReader();
			r.setPointerIndex(pageOffset);
			byte[] pageData;
			var isLastPage = i == object.pageCount - 1;
			if (isLastObject && isLastPage) {
				pageData = r.readNextByteArray(header.lastPageSize);
			} else {
				pageData = r.readNextByteArray(pageSize);	
			}
			var originalPageData = pageData.clone();
			
			// Apply fixups to page
			for (var fix : le.fixups.get(index)) {
				var f = (FixupRecord)fix;
				var addr = space.getAddress(f.getSourceAddress());

				int targetType = f.targetFlags & LinearFixupRecord.TARGET_TYPE_MASK;
				boolean importTarget = targetType == LinearFixupRecord.TARGET_IMPORT_ORDINAL
						|| targetType == LinearFixupRecord.TARGET_IMPORT_NAME;
				int objectIndex = f.objectNumber - 1;
				if (importTarget || objectIndex < 0 || objectIndex >= le.objects.size()) {
					// Imported / forwarded fixups carry a module ordinal and an imported
					// ordinal (or procedure name offset) instead of an internal object
					// offset.  Their runtime value is resolved by the extender, so
					// patching the page with an internal base address would corrupt it.
					// Record the relocation and leave the bytes alone; the external
					// symbol/reference is added later by createImportSymbols().
					fixupsUnhandled++;
					if (!loaderOptions.relocationTableDisabled) {
						relocationTable.add(
							addr, Relocation.Status.UNSUPPORTED, f.getSourceType(),
							null, 0,
							String.format("import_%s_%08x", f.shortname(), f.getSourceAddress())
						);
					}
					continue;
				}

				// Apply the actual fixup
				int base = loaderOptions.getBaseAddress(le.objects.get(objectIndex));
				fixupsByType[f.getSourceType()]++;

				// A source-list fixup applies the same relocation at several offsets
				// inside the page.  Iterate over them by temporarily moving the
				// record's sourceOffset, so the per-type logic below is reused
				// unchanged and every listed offset is fixed up.
				short savedSourceOffset = f.sourceOffset;
				short[] sourceOffsets = f.hasSourceList() ? toSourceOffsets(f.sourceList) : new short[] { f.sourceOffset };
				for (int pass = 0; pass < sourceOffsets.length; pass++) {
					f.sourceOffset = sourceOffsets[pass];
					addr = space.getAddress(f.getSourceAddress());
				
				/*
				 * The sourceOffset for each fixup can range from -3 to pageData.length -1.
				 * If the source offset is negative, only a partial fixup is performed for
				 * the bytes actually on the page. The same holds for the end of the page.
				 * Thus of 32bit fixup can fix 1, 2, 3 or 4 bytes depending on the position
				 * of the fixup on the page. 
				 */
				int length = 0;
				var enabled = loaderOptions.enableType[f.getSourceType()];
				if (enabled) {
					fixupsHandled++;	
				} else {
					fixupsUnhandled++;
				}
				
				if (f.getSourceType() == LinearFixupRecord.SOURCE_32BIT_OFFSET_FIXUP) {
					int value = base + f.targetOffset;
					if (f.sourceOffset >= 0 && f.sourceOffset < pageData.length) {
						if (enabled) {
							pageData[f.sourceOffset] = (byte)(value & 0xff);	
						}
						length++;
					}
					if (f.sourceOffset+1 >= 0 && f.sourceOffset+1 < pageData.length) {
						if (enabled) {
							pageData[f.sourceOffset+1] = (byte)((value & 0xff00)>>8);	
						}
						length++;
					}
					if (f.sourceOffset+2 >= 0 && f.sourceOffset+2 < pageData.length) {
						if (enabled) {
							pageData[f.sourceOffset+2] = (byte)((value & 0xff0000)>>16);	
						}
						length++;
					}
					if (f.sourceOffset+3 >= 0 && f.sourceOffset+3 < pageData.length) {
						if (enabled) {
							pageData[f.sourceOffset+3] = (byte)((value & 0xff000000)>>24);	
						}
						length++;
					}
					addRelocation(relocationTable, addr, Relocation.Status.APPLIED, f, originalPageData, length, value);
				} else if (f.getSourceType() == LinearFixupRecord.SOURCE_16BIT_OFFSET_FIXUP) {
					int value = base + f.targetOffset;
					if (f.sourceOffset >= 0 && f.sourceOffset < pageData.length) {
						if (enabled) {
							pageData[f.sourceOffset] = (byte)(value & 0xff);
						}
						length++;
					}
					if (f.sourceOffset+1 >= 0 && f.sourceOffset+1 < pageData.length) {
						if (enabled) {
							pageData[f.sourceOffset+1] = (byte)((value & 0xff00)>>8);
						}
						length++;
					}
					addRelocation(relocationTable, addr, Relocation.Status.APPLIED, f, originalPageData, length, (short)value);
				} else if (f.getSourceType() == LinearFixupRecord.SOURCE_32BIT__SELF_REF_OFFSET_FIXUP) {
					int value = base + f.targetOffset;
					long address = loaderOptions.getBaseAddress(object) + i*pageSize + f.sourceOffset;
					value = (int) (value - address - 4);
					if (f.sourceOffset >= 0 && f.sourceOffset < pageData.length) {
						if (enabled) {
							pageData[f.sourceOffset] = (byte)(value & 0xff);
						}
						length++;
					}
					if (f.sourceOffset+1 >= 0 && f.sourceOffset+1 < pageData.length) {
						if (enabled) {
							pageData[f.sourceOffset+1] = (byte)((value & 0xff00)>>8);
						}
						length++;
													}
					if (f.sourceOffset+2 >= 0 && f.sourceOffset+2 < pageData.length) {
						if (enabled) {
							pageData[f.sourceOffset+2] = (byte)((value & 0xff0000)>>16);
						}
						length++;
					}
					if (f.sourceOffset+3 >= 0 && f.sourceOffset+3 < pageData.length) {
						if (enabled) {
							pageData[f.sourceOffset+3] = (byte)((value & 0xff000000)>>24);
						}
						length++;
					}
					addRelocation(relocationTable, addr, Relocation.Status.APPLIED, f, originalPageData, length, value);
				} else if (f.getSourceType() == LinearFixupRecord.SOURCE_1616PTR_FIXUP) {
					var off = f.targetOffset;
					var selector = loaderOptions.getSelector(f.objectNumber);
					if (f.sourceOffset >= 0 && f.sourceOffset < pageData.length) {
						if (enabled) {
							pageData[f.sourceOffset] = (byte)(off & 0xff);
						}
						length++;
					}
					if (f.sourceOffset+1 >= 0 && f.sourceOffset+1 < pageData.length) {
						if (enabled) {
							pageData[f.sourceOffset+1] = (byte)((off & 0xff00)>>8);
						}
						length++;
					}
					if (f.sourceOffset+2 >= 0 && f.sourceOffset+2 < pageData.length) {
						if (enabled) {
							pageData[f.sourceOffset+2] = (byte)(selector & 0xff);
						}
						length++;
					}
					if (f.sourceOffset+3 >= 0 && f.sourceOffset+3 < pageData.length) {
						if (enabled) {
							pageData[f.sourceOffset+3] = (byte)((selector & 0xff00)>>8);
						}
						length++;
					}
					addRelocation(relocationTable, addr, Relocation.Status.APPLIED, f, originalPageData, length, selector);
				} else if (f.getSourceType() == LinearFixupRecord.SOURCE_1632PTR_FIXUP) {
					var off = f.targetOffset;
					var selector = loaderOptions.getSelector(f.objectNumber);
					if (f.sourceOffset >= 0 && f.sourceOffset < pageData.length) {
						if (enabled) {
							pageData[f.sourceOffset] = (byte)(off & 0xff);
						}
						length++;
					}
					if (f.sourceOffset+1 >= 0 && f.sourceOffset+1 < pageData.length) {
						if (enabled) {
							pageData[f.sourceOffset+1] = (byte)((off & 0xff00)>>8);
						}
						length++;
					}
					if (f.sourceOffset+2 >= 0 && f.sourceOffset+2 < pageData.length) {
						if (enabled) {
							pageData[f.sourceOffset+2] = (byte)((off & 0xff0000)>>16);
						}
						length++;
					}
					if (f.sourceOffset+3 >= 0 && f.sourceOffset+3 < pageData.length) {
						if (enabled) {
							pageData[f.sourceOffset+3] = (byte)((off & 0xff000000)>>24);
						}
						length++;
					}
					if (f.sourceOffset+4 >= 0 && f.sourceOffset+4 < pageData.length) {
						if (enabled) {
							pageData[f.sourceOffset+4] = (byte)(selector & 0xff);
						}
						length++;
					}
					if (f.sourceOffset+5 >= 0 && f.sourceOffset+5 < pageData.length) {
						if (enabled) {
							pageData[f.sourceOffset+5] = (byte)((selector & 0xff00)>>8);
						}
						length++;
					}
					addRelocation(relocationTable, addr, Relocation.Status.APPLIED, f, originalPageData, length, off, (short)selector);
				} else if (f.getSourceType() == LinearFixupRecord.SOURCE_16BIT_SELECTOR_FIXUP) {
					var selector = loaderOptions.getSelector(f.objectNumber);
					if (f.sourceOffset >= 0 && f.sourceOffset < pageData.length) {
						if (enabled) {
							pageData[f.sourceOffset] = (byte)(selector & 0xff);
						}
						length++;
					}
					if (f.sourceOffset+1 >= 0 && f.sourceOffset+1 < pageData.length) {
						if (enabled) {
							pageData[f.sourceOffset+1] = (byte)((selector & 0xff00)>>8);
						}
						length++;
					}
					addRelocation(relocationTable, addr, Relocation.Status.APPLIED, f, originalPageData, length, (short)selector);
				} else {
					Msg.warn(this, String.format(
						"WARNING: unhandled fixup %s (#%d) at %08x (type %02x): %s -> object#%x:%x",
						f.shortname(), f.index,
						f.getSourceAddress(),
						f.getSourceType(),
						f.hasSourceList() ? "source list " + f.sourceCount : String.format("%x", f.sourceOffset),
						f.objectNumber, f.targetOffset
					));
					relocationTable.add(
						addr, Relocation.Status.UNSUPPORTED, f.getSourceType(), 
						null, 0, 
						String.format("%s_%s_%08x",
							loaderOptions.fixupEnabled(f) ? "fix" : "nofix",
							f.shortname(), 
							f.getSourceAddress() 
						)
					);
					fixupsUnhandled++;
				}
				}
				f.sourceOffset = savedSourceOffset;
				
			}
			
			// Copy page into object block
			System.arraycopy(pageData, 0, block, blockIndex, pageData.length);
			blockIndex += pageSize;
		}
		
		log(CHECK + "Mapped .object%d into memory: %08x - %08x [%08x] (selector %03x)", 
			object.number, 
			loaderOptions.getBaseAddress(object),
			loaderOptions.getBaseAddress(object) + object.size,
			object.size,
			loaderOptions.getSelector(object)
		);
		
		// Log fixup statistics
		if (loaderOptions.logFixupStats) {
			ArrayList<String> byType = new ArrayList<>();
			for (int i = 0; i < 9; i++) {
				if (fixupsByType[i] > 0) {
					byType.add(String.format("%s: %d", FixupRecord.shortnames[i], fixupsByType[i]));
				}
			}
			if (fixupsHandled + fixupsUnhandled > 0) {
				log(
					"  " + HORSE + "%d fixups [%s]",
					fixupsHandled + fixupsUnhandled,
					String.join(", ", byType)
				);
			}
		}
		return block;
	}
	

	
	
	private void addRelocation(RelocationTable relocationTable, Address addr, Status applied, FixupRecord f,
			byte[] originalPageData, int length, int value) {
		if (!loaderOptions.relocationTableDisabled) {
			var originalBytes = new byte[length];
			System.arraycopy(originalPageData, Math.max(0, f.sourceOffset), originalBytes, 0, length);
			relocationTable.add(
				addr, Relocation.Status.APPLIED, f.getSourceType(), 
				null, originalBytes, 
				String.format("%s_%s_%08x_%08x",
					loaderOptions.fixupEnabled(f) ? "fix" : "nofix",
					f.shortname(), 
					f.getSourceAddress(),
					value
				)
			);	
		}
	}
	
	private void addRelocation(RelocationTable relocationTable, Address addr, Status applied, FixupRecord f,
			byte[] originalPageData, int length, short value) {
		if (!loaderOptions.relocationTableDisabled) {
			var originalBytes = new byte[length];
			System.arraycopy(originalPageData, Math.max(0, f.sourceOffset), originalBytes, 0, length);
			relocationTable.add(
				addr, Relocation.Status.APPLIED, f.getSourceType(), 
				null, originalBytes, 
				String.format("%s_%s_%08x_%04x",
					loaderOptions.fixupEnabled(f) ? "fix" : "nofix",
					f.shortname(), 
					f.getSourceAddress(),
					value
				)
			);
		}
	}
	
	private void addRelocation(RelocationTable relocationTable, Address addr, Status applied, FixupRecord f,
			byte[] originalPageData, int length, int offset, short selector) {
		if (!loaderOptions.relocationTableDisabled) {
			var originalBytes = new byte[length];
			System.arraycopy(originalPageData, Math.max(0, f.sourceOffset), originalBytes, 0, length);
			relocationTable.add(
				addr, Relocation.Status.APPLIED, f.getSourceType(), 
				null, originalBytes, 
				String.format("%s_%s_%08x_%04x_%08x",
					loaderOptions.fixupEnabled(f) ? "fix" : "nofix",
					f.shortname(), 
					f.getSourceAddress(),
					selector, offset
				)
			);
		}
	}

	private void createEntrypoint(Executable exe, Program program, TaskMonitor monitor) throws UsrException {
		var s = program.getAddressFactory().getDefaultAddressSpace();
		var header = exe.header;
		
		// Initialization (entry point, disassemble, ...)
		if (loaderOptions.addEntry && header.eipObject > 0) {
			monitor.setMessage(String.format(ARROW + "Setting entrypoint"));
			var api = new FlatProgramAPI(program, monitor);
			int eip = header.eip;
			var eipObject = exe.objects.get(header.eipObject-1);
			eip += loaderOptions.getBaseAddress(eipObject);			
			log(CHECK + "Entrypoint set @ %08x [base %08x + eip %08x]", 
				eip, 
				loaderOptions.getBaseAddress(eipObject), 
				header.eip
			);
			if (loaderOptions.disassembleEntry) {
				api.disassemble(api.toAddr(eip));	
			}
			program.getSymbolTable().createLabel(api.toAddr(eip), "_entry", SourceType.USER_DEFINED);
			api.createFunction(api.toAddr(eip), "_entry");
			api.addEntryPoint(api.toAddr(eip));
		}
		
		monitor.setMessage(String.format(ARROW + "Creating fixup xrefs & labels"));
		monitor.setIndeterminate(true);
		monitor.setProgress(0);
		monitor.setMaximum(exe.totalFixups());
		for (int i = 1; i <= header.pageCount; i++) {
			for (var fix : exe.fixups.get(i)) {
				var f = (FixupRecord)fix;
				
				monitor.incrementProgress(1);
				var addr = s.getAddress(f.getSourceAddress());
	
				if (loaderOptions.createFixupLabels) {
					// Label at original position
					program.getSymbolTable().createLabel(
						addr, 
						String.format("%s_%s_%08x",
							loaderOptions.fixupEnabled(f) ? "fix" : "nofix",
							f.shortname(), 
							f.getSourceAddress() 
						), 
						SourceType.ANALYSIS
					);
				}
				
				// Next at code unit position
				var unit = program.getListing().getCodeUnitContaining(addr);
				if (unit != null) {
					addr = unit.getAddress();
				}
				
				if (loaderOptions.fixupEnabled(f) && f.is1616PointerFixup()) {
					// 16:16 pointer fixups are weird since they involve segment selectors
					// and Ghidra only knows DOS segmented memory (no protected mode segmentation),
					// so we remove the old ref and place one calculated by ourself
					var to = s.getAddress(loaderOptions.getBaseAddress(f.objectNumber) + f.targetOffset);
					program.getReferenceManager().removeAllReferencesFrom(addr);
					var ref = new MemReferenceImpl(addr, to, RefType.JUMP_OVERRIDE_UNCONDITIONAL, SourceType.USER_DEFINED, 0, true);
					program.getReferenceManager().addReference(ref);	
				}
				
				if (loaderOptions.createFixupLabels) {	
					program.getListing().setComment(
						addr, 
						CommentType.PRE, 
						String.format(
							"fixup to -> %08x",
							loaderOptions.getBaseAddress(f.objectNumber) + f.targetOffset
						)
					);
				}
			}
		}

		// Create a label for each page
		if (loaderOptions.createPageLabels) {
			for (var i = 1; i <= exe.header.pageCount; i++) {
				var addr = s.getAddress(header.dataPagesOffset - exe.lfanew).add((i-1)*header.pageSize);
				program.getSymbolTable().createLabel(addr, "LE_PAGE_" + i, SourceType.USER_DEFINED);
			}
		}
	}
	
	/**
	 * Creates functions, labels and entry points for the exported entries of the
	 * LE/LX Entry Table.  The Entry Table is authoritative about call targets, so
	 * this recovers function starts that a plain disassembly sweep would miss.
	 */
	private void createEntryTableSymbols(Executable exe, Program program, TaskMonitor monitor) {
		var entryTable = exe.entryTable;
		if (entryTable == null || entryTable.entries.isEmpty()) {
			return;
		}
		monitor.setMessage(String.format(ARROW + "Creating entry table symbols (%d entries)", entryTable.entries.size()));
		var space = program.getAddressFactory().getDefaultAddressSpace();
		var api = new FlatProgramAPI(program, monitor);
		int created = 0;
		for (var entry : entryTable.entries) {
			String name = exe.getEntryName(entry.ordinal);
			if (name == null) {
				name = "ENTRY_" + entry.ordinal;
			}
			if (entry.isForwarder()) {
				// Forwarded entry: the target lives in another module.
				createExternalFunction(program, "module_" + entry.moduleOrdinal, name);
				continue;
			}
			if (entry.objectNumber < 1 || entry.objectNumber > exe.objects.size()) {
				continue;
			}
			var object = exe.objects.get(entry.objectNumber - 1);
			long offset = entry.offset & 0xffffffffL;
			if (offset >= (object.size & 0xffffffffL)) {
				// Entry points outside the object are malformed; do not create a
				// function at a bogus address.
				continue;
			}
			long address = (loaderOptions.getBaseAddress(object) & 0xffffffffL) + offset;
			var addr = space.getAddress(address);
			try {
				program.getSymbolTable().createLabel(addr, name, SourceType.IMPORTED);
			} catch (Exception e) {
				// A label may already exist (e.g. _entry at the same address).
			}
			try {
				api.createFunction(addr, name);
				if (entry.isExported()) {
					api.addEntryPoint(addr);
				}
				created++;
			} catch (Exception e) {
				Msg.warn(this, String.format("Could not create function %s at %s: %s", name, addr, e.getMessage()));
			}
		}
		log(CHECK + "Entry table: %d functions created", created);
	}

	/**
	 * Resolves import fixups (imported by ordinal or by name) into Ghidra external
	 * symbols and adds a reference from the fixup site, so imported calls are named
	 * instead of showing up as raw offsets.
	 */
	private void createImportSymbols(Executable exe, Program program, TaskMonitor monitor) {
		if (exe.imports == null || exe.imports.isEmpty()) {
			return;
		}
		int references = 0;
		for (int page = 1; page <= exe.header.pageCount; page++) {
			for (var fix : exe.fixups.get(page)) {
				var f = (FixupRecord)fix;
				int targetType = f.targetFlags & LinearFixupRecord.TARGET_TYPE_MASK;
				if (targetType != LinearFixupRecord.TARGET_IMPORT_ORDINAL
						&& targetType != LinearFixupRecord.TARGET_IMPORT_NAME) {
					continue;
				}
				String module = exe.imports.getModuleName(f.ordinalIndex);
				if (module == null || module.isEmpty()) {
					module = "module_" + f.ordinalIndex;
				}
				String procedure = null;
				if (targetType == LinearFixupRecord.TARGET_IMPORT_NAME) {
					procedure = exe.imports.getProcedureName(f.ordinalNumber);
				}
				if (procedure == null || procedure.isEmpty()) {
					procedure = "Ordinal_" + f.ordinalNumber;
				}
				var location = createExternalFunction(program, module, procedure);
				if (location == null) {
					continue;
				}
				var from = program.getAddressFactory().getDefaultAddressSpace().getAddress(f.getSourceAddress());
				var unit = program.getListing().getCodeUnitContaining(from);
				if (unit != null) {
					from = unit.getAddress();
				}
				program.getReferenceManager().addMemoryReference(
					from, location.getAddress(), RefType.DATA, SourceType.IMPORTED, 0);
				references++;
			}
		}
		log(CHECK + "Import fixups: %d external references created", references);
	}

	private ExternalLocation createExternalFunction(Program program, String libraryName, String functionName) {
		try {
			return program.getExternalManager().addExtFunction(libraryName, functionName, null, SourceType.IMPORTED);
		} catch (Exception e) {
			Msg.warn(this, String.format("Could not create external %s::%s: %s", libraryName, functionName, e.getMessage()));
			return null;
		}
	}

	private static short[] toSourceOffsets(java.util.List<Short> list) {
		short[] result = new short[list.size()];
		for (int i = 0; i < list.size(); i++) {
			result[i] = (short) (list.get(i) & 0xffff);
		}
		return result;
	}

	private void log(String format, Object... args)  {
		messageLog.appendMsg(String.format(format, args));
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram, boolean mirrorFsLayout) {
		return loaderOptions.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {
		loaderOptions.validateOptions(provider, loadSpec, options, program);
		return super.validateOptions(provider, loadSpec, options, program);
	}
}
