package yetmorecode.ghidra.format.lx.model;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;

/**
 * The Import Module Name Table and the Import Procedure Name Table of an LE/LX
 * module.
 *
 * <p>
 * Both tables live in the fixup section of the linear EXE and consist of
 * length-prefixed ASCII strings:
 * </p>
 * <ul>
 * <li>The <b>Import Module Name Table</b> holds one entry per imported module
 * (the header field {@code e32_impmodcnt} gives the exact count).</li>
 * <li>The <b>Import Procedure Name Table</b> holds the procedure names. Fixup
 * records that resolve an import by name store a byte offset into this table
 * (the {@code PROCEDURE NAME OFFSET} field).</li>
 * </ul>
 *
 * <p>
 * Reading these tables lets the loader attach real names (and therefore
 * references) to import fixups instead of leaving raw ordinals behind.
 * </p>
 */
public class ImportTables {

	/** Module names, indexed by (ordinalIndex - 1). */
	public final List<String> moduleNames = new ArrayList<String>();

	/** Raw bytes of the Import Procedure Name Table (may be empty). */
	public byte[] procedureNameTable = new byte[0];

	public boolean isEmpty() {
		return moduleNames.isEmpty() && procedureNameTable.length == 0;
	}

	/**
	 * Parses both import tables.
	 *
	 * @param reader            reader over the image
	 * @param moduleTableOffset absolute file offset of the Import Module Name Table
	 * @param moduleCount       number of module names (header e32_impmodcnt)
	 * @param procedureOffset   absolute file offset of the Import Procedure Name Table
	 * @param procedureLength   byte length of the Import Procedure Name Table
	 */
	public ImportTables(BinaryReader reader, long moduleTableOffset, int moduleCount,
			long procedureOffset, long procedureLength) throws IOException {
		long oldIndex = reader.getPointerIndex();
		try {
			if (moduleCount > 0 && moduleTableOffset > 0) {
				reader.setPointerIndex(moduleTableOffset);
				for (int i = 0; i < moduleCount; i++) {
					moduleNames.add(readLengthPrefixedString(reader));
				}
			}
			if (procedureLength > 0 && procedureOffset > 0) {
				reader.setPointerIndex(procedureOffset);
				procedureNameTable = reader.readNextByteArray((int) procedureLength);
			}
		} finally {
			reader.setPointerIndex(oldIndex);
		}
	}

	/**
	 * Returns the name of the imported module referenced by a one-based
	 * {@code ordinalIndex}, or {@code null} when the index is out of range.
	 */
	public String getModuleName(int ordinalIndex) {
		int index = ordinalIndex - 1;
		if (index < 0 || index >= moduleNames.size()) {
			return null;
		}
		return moduleNames.get(index);
	}

	/**
	 * Returns the procedure name stored at {@code offsetInTable} bytes from the
	 * start of the Import Procedure Name Table, or {@code null} when the offset is
	 * out of range or the string is not terminated within the table.
	 */
	public String getProcedureName(int offsetInTable) {
		return readLengthPrefixedString(procedureNameTable, offsetInTable);
	}

	private static String readLengthPrefixedString(BinaryReader reader) throws IOException {
		int length = reader.readNextByte() & 0xff;
		byte[] bytes = reader.readNextByteArray(length);
		return new String(bytes, StandardCharsets.US_ASCII);
	}

	static String readLengthPrefixedString(byte[] table, int offset) {
		if (offset < 0 || offset >= table.length) {
			return null;
		}
		int length = table[offset] & 0xff;
		if (length == 0 || offset + 1 + length > table.length) {
			return null;
		}
		return new String(table, offset + 1, length, StandardCharsets.US_ASCII);
	}
}
