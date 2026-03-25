// LoadExternalOverlay.java — Ghidra script to load Borland external .OVR overlay files
//
// This script loads a Borland Pascal/C++ external overlay file (.OVR with FBOV
// header) into the current Ghidra project as additional memory blocks. It:
//   1. Reads the .OVR file (skipping the 8-byte FBOV header)
//   2. Parses bosh_t overlay headers from INT 3F stubs in the already-loaded EXE
//   3. Creates a memory block for the overlay code at a configurable base segment
//   4. Uses bosh_t boundaries for precise overlay region identification
//   5. Creates functions at trap entry points (known overlay entry offsets)
//   6. Scans for additional function prologues (push bp; mov bp, sp)
//   7. Creates thunk references from EXE stub segments to overlay functions
//
// Usage:
//   analyzeHeadless ... -postScript LoadExternalOverlay.java <ovr-file-path>
//
// The overlay code is loaded at segment 0x8000 by default, which is above
// the typical EXE code range (0x1000-0x7000). Each overlay in the OVR file
// is contiguous (code + fixup data), and the script uses the bosh_t headers
// from the EXE's INT 3F stubs to determine exact boundaries.
//
// Borland overlays share runtime memory buffers (multiple overlays load into
// the same segment at different times), so the stub segment addresses cannot
// be used directly. Instead, the script:
//   - Loads all overlay code at flat offsets under 0x8000
//   - Patches the EXE's INT 3F trap entries to be far JMPs to the overlay code
//   - This resolves EXE → overlay cross-references in the decompiled output
//
// For Borland DOS executables that use external overlays (e.g., LORD 4.08),
// run this BEFORE DecompileAll.java so both EXE and OVR functions are decompiled.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import java.io.*;
import java.util.*;

public class LoadExternalOverlay extends GhidraScript {

    // Default base segment for overlay code.
    // Placed well above typical EXE code (0x1000-0x7000).
    private static final int OVR_BASE_SEG = 0x8000;

    // bosh_t header structure parsed from EXE INT 3F stubs
    private static class OverlayHeader {
        int stubSeg;      // segment paragraph of EXE stub
        int fileOfs;      // offset of code in OVR (relative to end of FBOV header)
        int codeSz;       // code size in bytes
        int fixupSz;      // fixup table size in bytes
        int jmpCnt;       // number of trap entries
        int[] trapOffsets; // entry point offsets within overlay code

        @Override
        public String toString() {
            return String.format("OVR seg=0x%04x fileOfs=0x%06x codeSz=0x%04x fixupSz=0x%04x jmpCnt=%d",
                stubSeg, fileOfs, codeSz, fixupSz, jmpCnt);
        }
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args == null || args.length < 1) {
            printerr("Usage: LoadExternalOverlay.java <ovr-file-path>");
            return;
        }

        String ovrPath = args[0];
        File ovrFile = new File(ovrPath);
        if (!ovrFile.exists()) {
            printerr("OVR file not found: " + ovrPath);
            return;
        }

        println("Loading external overlay: " + ovrPath);

        // Read the OVR file
        byte[] ovrBytes;
        try (FileInputStream fis = new FileInputStream(ovrFile)) {
            ovrBytes = fis.readAllBytes();
        }

        // Validate FBOV header
        if (ovrBytes.length < 8 ||
            ovrBytes[0] != 'F' || ovrBytes[1] != 'B' ||
            ovrBytes[2] != 'O' || ovrBytes[3] != 'V') {
            printerr("Not a valid FBOV overlay file (missing FBOV magic)");
            return;
        }

        // Read the declared data size from FBOV header (LE uint32 at offset 4)
        int declaredSize = readLE32(ovrBytes, 4);
        println("FBOV declared size: " + declaredSize + " bytes");

        int dataOffset = 8;  // FBOV header is 8 bytes
        int dataSize = ovrBytes.length - dataOffset;
        println("Overlay data size: " + dataSize + " bytes");

        // Parse bosh_t overlay headers from EXE's INT 3F stubs
        List<OverlayHeader> headers = parseOverlayHeaders();
        println("Found " + headers.size() + " overlay segments from EXE stubs");

        // Create the overlay memory block
        Memory memory = currentProgram.getMemory();
        AddressSpace addressSpace = currentProgram.getAddressFactory().getDefaultAddressSpace();
        long baseAddr = (long) OVR_BASE_SEG * 16;
        Address blockStart = addressSpace.getAddress(baseAddr);

        // Remove existing overlay block if present
        MemoryBlock existingBlock = memory.getBlock(blockStart);
        if (existingBlock != null) {
            println("Removing existing block at " + blockStart);
            memory.removeBlock(existingBlock, monitor);
        }

        // Create the memory block with the full OVR data (code + fixups interleaved)
        try (ByteArrayInputStream bais = new ByteArrayInputStream(ovrBytes, dataOffset, dataSize)) {
            MemoryBlock block = memory.createInitializedBlock(
                "OVERLAY", blockStart, bais, dataSize, monitor, false);
            block.setRead(true);
            block.setWrite(false);
            block.setExecute(true);
            println("Created overlay block: [" + block.getStart() + " - " + block.getEnd() + "]");
        }

        // Create functions using bosh_t header information
        int funcCount = 0;

        if (!headers.isEmpty()) {
            // Create functions at trap entry points (precise entry points from bosh_t)
            funcCount += createTrapFunctions(headers, blockStart, memory);

            // Scan for additional prologues within each overlay's code region
            funcCount += createPrologueFunctions(headers, blockStart, dataSize, memory);

            // Patch EXE stub traps to redirect to overlay functions
            patchStubTraps(headers, blockStart, memory);
        } else {
            // Fallback: no bosh_t headers found, scan entire block for prologues
            println("WARNING: No bosh_t headers found, falling back to prologue scan");
            funcCount = scanAllPrologues(memory, blockStart, dataSize);
        }

        println("Created " + funcCount + " functions in overlay");

        // Run auto-analysis on the new block
        println("Triggering re-analysis...");
        analyzeAll(currentProgram);
        println("LoadExternalOverlay complete.");
    }

    /**
     * Parse bosh_t overlay headers from INT 3F stubs in the EXE.
     * Searches the already-loaded EXE memory for CD 3F (INT 3Fh) instructions
     * that have valid bosh_t header fields following them.
     */
    private List<OverlayHeader> parseOverlayHeaders() throws Exception {
        List<OverlayHeader> headers = new ArrayList<>();
        Memory memory = currentProgram.getMemory();

        // Search all memory blocks that are part of the EXE (not our overlay block)
        for (MemoryBlock block : memory.getBlocks()) {
            if (block.getName().equals("OVERLAY")) continue;
            if (!block.isExecute()) continue;

            Address start = block.getStart();
            Address end = block.getEnd();
            long blockSize = end.subtract(start) + 1;

            // Scan for INT 3F (CD 3F) patterns
            for (long offset = 0; offset < blockSize - 14; offset++) {
                Address addr = start.add(offset);
                try {
                    byte b0 = memory.getByte(addr);
                    byte b1 = memory.getByte(addr.add(1));

                    if (b0 != (byte) 0xCD || b1 != (byte) 0x3F) continue;

                    // Check if this is paragraph-aligned (real-mode segment boundary)
                    long linearAddr = addr.getOffset();
                    if ((linearAddr % 16) != 0) continue;

                    // Read bosh_t fields: saveret(2), fileofs(4), codesz(2), fixupsz(2), jmpcnt(2)
                    int saveret = readLE16(memory, addr.add(2));
                    int fileOfs = readLE32(memory, addr.add(4));
                    int codeSz  = readLE16(memory, addr.add(8));
                    int fixupSz = readLE16(memory, addr.add(10));
                    int jmpCnt  = readLE16(memory, addr.add(12));

                    // Validate: overlay file offset and sizes must be reasonable
                    if (fileOfs > 200000 || codeSz == 0 || codeSz > 0x8000 ||
                        fixupSz > 0x8000 || jmpCnt > 200) continue;

                    OverlayHeader hdr = new OverlayHeader();
                    hdr.stubSeg = (int) (linearAddr / 16);
                    hdr.fileOfs = fileOfs;
                    hdr.codeSz  = codeSz;
                    hdr.fixupSz = fixupSz;
                    hdr.jmpCnt  = jmpCnt;

                    // Parse trap entries (5 bytes each, starting 32 bytes after bosh_t start)
                    hdr.trapOffsets = new int[jmpCnt];
                    for (int j = 0; j < jmpCnt; j++) {
                        Address trapAddr = addr.add(32 + j * 5);
                        int trapCode = readLE16(memory, trapAddr);
                        if (trapCode == 0x3FCD) {
                            hdr.trapOffsets[j] = readLE16(memory, trapAddr.add(2));
                        }
                    }

                    headers.add(hdr);
                    println("  " + hdr);

                    // Skip past this header
                    offset += 31;
                } catch (Exception e) {
                    // Skip
                }
            }
        }

        // Sort by fileOfs for ordered processing
        headers.sort(Comparator.comparingInt(h -> h.fileOfs));
        return headers;
    }

    /**
     * Create functions at the known trap entry points from bosh_t headers.
     * These are the precisely-known entry points into each overlay.
     */
    private int createTrapFunctions(List<OverlayHeader> headers, Address blockStart,
            Memory memory) throws Exception {
        Listing listing = currentProgram.getListing();
        int count = 0;

        for (OverlayHeader hdr : headers) {
            for (int j = 0; j < hdr.jmpCnt; j++) {
                int entryOffset = hdr.trapOffsets[j];
                // The entry offset is within the overlay code; add to OVR file position
                int ovrFileOffset = hdr.fileOfs + entryOffset;
                Address funcAddr = blockStart.add(ovrFileOffset);

                try {
                    // Disassemble
                    DisassembleCommand disCmd = new DisassembleCommand(funcAddr, null, true);
                    disCmd.applyTo(currentProgram, monitor);

                    // Create function
                    Function existing = listing.getFunctionContaining(funcAddr);
                    if (existing != null && existing.getEntryPoint().equals(funcAddr)) continue;

                    CreateFunctionCmd funcCmd = new CreateFunctionCmd(funcAddr);
                    if (funcCmd.applyTo(currentProgram, monitor)) {
                        count++;
                        // Label with stub segment info for cross-reference
                        String label = String.format("OVR_%04X_trap%d", hdr.stubSeg, j);
                        currentProgram.getSymbolTable().createLabel(funcAddr, label,
                            SourceType.USER_DEFINED);
                    }
                } catch (Exception e) {
                    println("  Warning: Failed to create trap function at " + funcAddr + ": " + e.getMessage());
                }
            }
        }

        println("Created " + count + " trap entry functions");
        return count;
    }

    /**
     * Scan for function prologues within each overlay's code region,
     * and also in gaps between overlays.
     */
    private int createPrologueFunctions(List<OverlayHeader> headers, Address blockStart,
            int totalDataSize, Memory memory) throws Exception {
        Listing listing = currentProgram.getListing();
        int count = 0;

        // Build a set of ranges that are overlay code (not fixup data)
        List<int[]> codeRanges = new ArrayList<>();

        for (int i = 0; i < headers.size(); i++) {
            OverlayHeader hdr = headers.get(i);
            // Overlay code starts at hdr.fileOfs, goes for hdr.codeSz bytes
            codeRanges.add(new int[]{hdr.fileOfs, hdr.fileOfs + hdr.codeSz});

            // Gap between this overlay's end (code + fixups) and next overlay's start
            int thisEnd = hdr.fileOfs + hdr.codeSz + hdr.fixupSz;
            int nextStart;
            if (i + 1 < headers.size()) {
                nextStart = headers.get(i + 1).fileOfs;
            } else {
                nextStart = totalDataSize;
            }
            if (nextStart > thisEnd) {
                // There's a gap — scan it for functions too
                codeRanges.add(new int[]{thisEnd, nextStart});
            }
        }

        // Also scan before the first overlay (if any data there)
        if (!headers.isEmpty() && headers.get(0).fileOfs > 0) {
            codeRanges.add(new int[]{0, headers.get(0).fileOfs});
        }

        for (int[] range : codeRanges) {
            int rangeStart = range[0];
            int rangeEnd = range[1];

            for (int offset = rangeStart; offset < rangeEnd - 2; offset++) {
                Address addr = blockStart.add(offset);
                try {
                    byte b0 = memory.getByte(addr);
                    byte b1 = memory.getByte(addr.add(1));
                    byte b2 = memory.getByte(addr.add(2));

                    boolean isPrologue = false;
                    if (b0 == 0x55) { // PUSH BP
                        if ((b1 == (byte) 0x89 && b2 == (byte) 0xE5) ||  // MOV BP, SP
                            (b1 == (byte) 0x8B && b2 == (byte) 0xEC)) {  // MOV BP, SP (alt)
                            isPrologue = true;
                        }
                    }

                    if (!isPrologue) continue;

                    Function existing = listing.getFunctionContaining(addr);
                    if (existing != null) continue;

                    DisassembleCommand disCmd = new DisassembleCommand(addr, null, true);
                    disCmd.applyTo(currentProgram, monitor);

                    CreateFunctionCmd funcCmd = new CreateFunctionCmd(addr);
                    if (funcCmd.applyTo(currentProgram, monitor)) {
                        count++;
                    }
                } catch (Exception e) {
                    // Skip errors
                }
            }
        }

        println("Created " + count + " prologue-detected functions");
        return count;
    }

    /**
     * Patch INT 3F trap entries in the EXE to be far JMPs to the overlay code.
     * This allows Ghidra to resolve cross-references from EXE code to overlay functions.
     *
     * Original trap format: CD 3F <entry_offset:16> <pad:8>  (5 bytes)
     * Patched to:           EA <offset:16> <segment:16>      (5 bytes, far JMP)
     *
     * Also patches the bosh_t header itself (the first INT 3F at offset 0 of the stub)
     * to redirect to the first function in the overlay code.
     */
    private void patchStubTraps(List<OverlayHeader> headers, Address blockStart,
            Memory memory) throws Exception {
        int patched = 0;

        for (OverlayHeader hdr : headers) {
            // The stub segment's address in Ghidra
            long stubLinearAddr = (long) hdr.stubSeg * 16;

            for (int j = 0; j < hdr.jmpCnt; j++) {
                int entryOffset = hdr.trapOffsets[j];
                // Calculate the overlay function's address in the OVERLAY block
                int ovrFileOffset = hdr.fileOfs + entryOffset;
                Address ovrFuncAddr = blockStart.add(ovrFileOffset);

                // The trap entry is at stub_seg:0x0020 + j*5
                // (bosh_t is 32 bytes = 0x20, each trap is 5 bytes)
                long trapLinearAddr = stubLinearAddr + 0x20 + j * 5;
                Address trapAddr;
                try {
                    trapAddr = currentProgram.getAddressFactory()
                        .getDefaultAddressSpace().getAddress(trapLinearAddr);
                } catch (Exception e) {
                    continue;
                }

                // Check if this address is in a writable memory block
                MemoryBlock trapBlock = memory.getBlock(trapAddr);
                if (trapBlock == null) continue;

                try {
                    // Patch: EA <ofs_lo> <ofs_hi> <seg_lo> <seg_hi>
                    // The target in real-mode segmented form:
                    long ovrLinear = ovrFuncAddr.getOffset();
                    int ovrSeg = (int) (ovrLinear / 16);
                    int ovrOfs = (int) (ovrLinear % 16);

                    // For function at 0x80000 + X, segment is 0x8000 + X/16, offset is X%16
                    // But Ghidra uses flat addresses internally. We need seg:ofs encoding.
                    // Use the overlay base segment + file offset in paragraphs
                    int targetSeg = OVR_BASE_SEG + (ovrFileOffset / 16);
                    int targetOfs = ovrFileOffset % 16;

                    memory.setByte(trapAddr, (byte) 0xEA);              // JMP FAR
                    memory.setByte(trapAddr.add(1), (byte) (targetOfs & 0xFF));
                    memory.setByte(trapAddr.add(2), (byte) ((targetOfs >> 8) & 0xFF));
                    memory.setByte(trapAddr.add(3), (byte) (targetSeg & 0xFF));
                    memory.setByte(trapAddr.add(4), (byte) ((targetSeg >> 8) & 0xFF));

                    patched++;

                    // Add a label at the trap entry for clarity
                    String label = String.format("jmp_OVR_%04X_trap%d", hdr.stubSeg, j);
                    currentProgram.getSymbolTable().createLabel(trapAddr, label,
                        SourceType.USER_DEFINED);

                    // Disassemble the JMP instruction
                    DisassembleCommand disCmd = new DisassembleCommand(trapAddr, null, true);
                    disCmd.applyTo(currentProgram, monitor);
                } catch (Exception e) {
                    println("  Warning: Failed to patch trap at " + trapAddr + ": " + e.getMessage());
                }
            }
        }

        println("Patched " + patched + " stub traps with far JMPs to overlay code");
    }

    /**
     * Fallback: scan entire overlay block for function prologues.
     * Used when no bosh_t headers are found in the EXE.
     */
    private int scanAllPrologues(Memory memory, Address blockStart, int dataSize)
            throws Exception {
        Listing listing = currentProgram.getListing();
        int count = 0;

        for (int offset = 0; offset < dataSize - 2; offset++) {
            Address addr = blockStart.add(offset);
            try {
                byte b0 = memory.getByte(addr);
                byte b1 = memory.getByte(addr.add(1));
                byte b2 = memory.getByte(addr.add(2));

                boolean isPrologue = false;
                if (b0 == 0x55) {
                    if ((b1 == (byte) 0x89 && b2 == (byte) 0xE5) ||
                        (b1 == (byte) 0x8B && b2 == (byte) 0xEC)) {
                        isPrologue = true;
                    }
                }

                if (!isPrologue) continue;

                Function existing = listing.getFunctionContaining(addr);
                if (existing != null) continue;

                DisassembleCommand disCmd = new DisassembleCommand(addr, null, true);
                disCmd.applyTo(currentProgram, monitor);

                CreateFunctionCmd funcCmd = new CreateFunctionCmd(addr);
                if (funcCmd.applyTo(currentProgram, monitor)) {
                    count++;
                }
            } catch (Exception e) {
                // Skip
            }
        }

        return count;
    }

    // ── Helper methods for reading little-endian values ──

    private int readLE16(byte[] data, int offset) {
        return (data[offset] & 0xFF) | ((data[offset + 1] & 0xFF) << 8);
    }

    private int readLE32(byte[] data, int offset) {
        return (data[offset] & 0xFF) | ((data[offset + 1] & 0xFF) << 8)
             | ((data[offset + 2] & 0xFF) << 16) | ((data[offset + 3] & 0xFF) << 24);
    }

    private int readLE16(Memory memory, Address addr) throws Exception {
        return (memory.getByte(addr) & 0xFF) | ((memory.getByte(addr.add(1)) & 0xFF) << 8);
    }

    private int readLE32(Memory memory, Address addr) throws Exception {
        return (memory.getByte(addr) & 0xFF) | ((memory.getByte(addr.add(1)) & 0xFF) << 8)
             | ((memory.getByte(addr.add(2)) & 0xFF) << 16) | ((memory.getByte(addr.add(3)) & 0xFF) << 24);
    }
}
