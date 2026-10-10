package yetmorecode.ghidra.format.lx.model;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;

/**
 * The Entry Table of an LE/LX module.
 *
 * <p>
 * The Entry Table is a sequence of entry bundles. Each bundle starts with a
 * count and a type, followed (for every type except {@code EMPTY}) by a 16-bit
 * object number that all entries of the bundle belong to:
 * </p>
 *
 * <pre>
 * bundle := count(1) type(1) [object(2) if type != 0] entry[count]
 * entry  := (type dependent)
 * </pre>
 *
 * <ul>
 * <li>{@code 1 = ENTRY16}: flags(1) offset(2)</li>
 * <li>{@code 2 = GATE16}: flags(1) offset(2) callgate(2)</li>
 * <li>{@code 3 = ENTRY32}: flags(1) offset(4)</li>
 * <li>{@code 4 = ENTRYFWD}: flags(1) moduleOrdinal(2) value(4) (forwarded entry)</li>
 * </ul>
 *
 * A count of zero ends the table. Entries are numbered with a running, one-based
 * ordinal; the Resident/Non-Resident Name Table maps names onto these ordinals.
 * See Open Watcom {@code bld/watcom/h/exeflat.h} for the upstream definitions.
 */
public class EntryTable {

	public static final int TYPE_EMPTY = 0;
	public static final int TYPE_ENTRY16 = 1;
	public static final int TYPE_GATE16 = 2;
	public static final int TYPE_ENTRY32 = 3;
	public static final int TYPE_FORWARD = 4;

	/** Flag bit 0: the entry is exported. */
	public static final int FLAG_EXPORTED = 0x01;

	public static class Entry {
		/** One-based running ordinal, used to look names up in the name tables. */
		public int ordinal;
		public int type;
		/** Object the entry lives in (0 for forwarded entries). */
		public int objectNumber;
		public int flags;
		public int offset;
		/** 16:16 call gate selector (type GATE16). */
		public int callgate;
		/** Imported module ordinal (type FORWARD). */
		public int moduleOrdinal;
		/** Imported ordinal / name offset (type FORWARD). */
		public int value;
		/** Resolved from the name tables, may be {@code null}. */
		public String name;

		public boolean isExported() {
			return (flags & FLAG_EXPORTED) != 0;
		}

		public boolean isForwarder() {
			return type == TYPE_FORWARD;
		}
	}

	public final List<Entry> entries = new ArrayList<Entry>();

	public EntryTable(BinaryReader reader, long offset, long endOffset) throws IOException {
		long oldIndex = reader.getPointerIndex();
		try {
			long pos = offset;
			int ordinal = 1;
			while (pos < endOffset) {
				reader.setPointerIndex(pos);
				int count = reader.readNextByte() & 0xff;
				pos += 1;
				if (count == 0) {
					break;
				}
				if (pos >= endOffset) {
					break;
				}
				int type = reader.readNextByte() & 0xff;
				pos += 1;

				int objectNumber = 0;
				if (type != TYPE_EMPTY) {
					objectNumber = reader.readNextShort() & 0xffff;
					pos += 2;
				}

				if (type == TYPE_EMPTY) {
					// Unused bundle: reserves ordinals without any payload.
					ordinal += count;
					continue;
				}

				for (int i = 0; i < count; i++) {
					Entry entry = new Entry();
					entry.ordinal = ordinal++;
					entry.type = type;
					entry.objectNumber = objectNumber;
					entry.flags = reader.readNextByte() & 0xff;
					pos += 1;
					switch (type) {
					case TYPE_ENTRY16:
						entry.offset = reader.readNextShort() & 0xffff;
						pos += 2;
						break;
					case TYPE_GATE16:
						entry.offset = reader.readNextShort() & 0xffff;
						entry.callgate = reader.readNextShort() & 0xffff;
						pos += 4;
						break;
					case TYPE_ENTRY32:
						entry.offset = reader.readNextInt();
						pos += 4;
						break;
					case TYPE_FORWARD:
						entry.moduleOrdinal = reader.readNextShort() & 0xffff;
						entry.value = reader.readNextInt();
						pos += 6;
						break;
					default:
						// Unknown bundle type: bail out rather than desync.
						return;
					}
					entries.add(entry);
				}
			}
		} finally {
			reader.setPointerIndex(oldIndex);
		}
	}
}
