package yetmorecode.ghidra.format.lx.model;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

import ghidra.app.util.bin.BinaryReader;

/**
 * A Resident or Non-Resident Name Table of an LE/LX module.
 *
 * <p>
 * The table is a sequence of {@code length(1) name(length) ordinal(2)} records,
 * terminated by a zero length byte. The record with ordinal {@code 0} is the
 * module name; the remaining records map exported ordinals onto names and
 * therefore link the Entry Table to human readable symbols.
 * </p>
 */
public class NameTable {

	/** Ordinal (as stored in the table) to name. */
	public final Map<Integer, String> byOrdinal = new LinkedHashMap<Integer, String>();

	public String moduleName;

	public boolean isEmpty() {
		return byOrdinal.isEmpty() && moduleName == null;
	}

	public NameTable(BinaryReader reader, long offset, long endOffset) throws IOException {
		long oldIndex = reader.getPointerIndex();
		try {
			long pos = offset;
			while (pos < endOffset) {
				reader.setPointerIndex(pos);
				int length = reader.readNextByte() & 0xff;
				pos += 1;
				if (length == 0) {
					break;
				}
				byte[] bytes = reader.readNextByteArray(length);
				pos += length;
				if (pos + 2 > endOffset) {
					break;
				}
				int ordinal = reader.readNextShort() & 0xffff;
				pos += 2;
				String name = new String(bytes, StandardCharsets.US_ASCII);
				// Reject clearly non-textual data so a wrong offset cannot inject garbage.
				if (!isPlausibleName(name)) {
					continue;
				}
				if (ordinal == 0) {
					moduleName = name;
				} else {
					byOrdinal.put(ordinal, name);
				}
			}
		} finally {
			reader.setPointerIndex(oldIndex);
		}
	}

	private static boolean isPlausibleName(String s) {
		if (s.isEmpty()) {
			return false;
		}
		for (int i = 0; i < s.length(); i++) {
			char c = s.charAt(i);
			if (c < 0x20 || c > 0x7e) {
				return false;
			}
		}
		return true;
	}
}
