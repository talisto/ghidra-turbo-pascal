// CreateBPSignatures.java — Build hash-based signature database from FLIRT-identified functions
//
// Run AFTER ApplySigHeadless.py has applied FLIRT signatures. This script:
//   1. Iterates all functions in the current program
//   2. For each FLIRT-identified function, looks up its human-readable name
//   3. Hashes the function body with Ghidra's FidService
//   4. Writes/appends the hash→name mapping to a JSON file
//
// The resulting JSON is used by Decompile.java for library function matching,
// replacing the IDA FLIRT signature pipeline entirely.
//
// Usage:
//   analyzeHeadless <proj> <name> -process <EXE> \
//     -postScript CreateBPSignatures.java <output.json> \
//     -scriptPath scripts
//
// The script appends to existing JSON, so run it on multiple programs to
// build comprehensive coverage.
//
//@category FunctionID
import ghidra.app.script.GhidraScript;
import ghidra.feature.fid.service.FidService;
import ghidra.feature.fid.hash.FidHashQuad;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import java.io.*;
import java.util.*;
import java.util.regex.*;

public class CreateBPSignatures extends GhidraScript {

    // ── FLIRT name → [shortName, description] ──
    // (Identical to Decompile.java's FLIRT_DESCRIPTIONS)
    private static final Map<String, String[]> FLIRT_DESCRIPTIONS = new HashMap<>();
    private static final Map<String, String[]> FLIRT_PLAIN_DESCRIPTIONS = new HashMap<>();

    static {
        // Standard I/O
        FLIRT_DESCRIPTIONS.put("_Write_qm4Textm6String4Word",   new String[]{"bp_write_str",    "Write(Text, String, Word) — write string to text file"});
        FLIRT_DESCRIPTIONS.put("_Write_qm4Text4Word",           new String[]{"bp_write_word",    "Write(Text, Word) — write word to text file"});
        FLIRT_DESCRIPTIONS.put("_Write_qm4Text7Longint",        new String[]{"bp_write_longint", "Write(Text, Longint) — write longint to text file"});
        FLIRT_DESCRIPTIONS.put("_Write_qm4Text7Integer",        new String[]{"bp_write_int",     "Write(Text, Integer) — write integer to text file"});
        FLIRT_DESCRIPTIONS.put("_Write_qm4Text4Char",           new String[]{"bp_write_char",    "Write(Text, Char) — write char to text file"});
        FLIRT_DESCRIPTIONS.put("_Write_qm4Text7Boolean",        new String[]{"bp_write_bool",    "Write(Text, Boolean) — write boolean to text file"});
        FLIRT_DESCRIPTIONS.put("_Write_qm4Text4Real4Word4Word", new String[]{"bp_write_real",    "Write(Text, Real, Word, Word) — write real to text file"});
        FLIRT_DESCRIPTIONS.put("_WriteLn_qm4Text",              new String[]{"bp_writeln",       "WriteLn(Text) — write newline"});
        FLIRT_DESCRIPTIONS.put("_ReadLn_qm4Text",               new String[]{"bp_readln",        "ReadLn(Text) — read line from text file"});
        FLIRT_DESCRIPTIONS.put("_Read_qm4Text",                 new String[]{"bp_read",          "Read(Text) — read from text file"});
        FLIRT_DESCRIPTIONS.put("_Read_qm4Textm6String",         new String[]{"bp_read_str",      "Read(Text, String) — read string from text file"});
        FLIRT_DESCRIPTIONS.put("_Read_qm4Textm7Longint",        new String[]{"bp_read_longint",  "Read(Text, Longint) — read longint"});
        FLIRT_DESCRIPTIONS.put("_Read_qm4Textm7Integer",        new String[]{"bp_read_int",      "Read(Text, Integer) — read integer"});
        FLIRT_DESCRIPTIONS.put("_Write_qm4Text4Char4Word",      new String[]{"bp_write_char",    "Write(Text, Char, Word) — write char with field width"});
        FLIRT_DESCRIPTIONS.put("_Write_qm4Text7Longint4Word",   new String[]{"bp_write_longint", "Write(Text, Longint, Word) — write longint with width"});
        FLIRT_DESCRIPTIONS.put("_Write_qm4Text7Boolean4Word",   new String[]{"bp_write_bool",    "Write(Text, Boolean, Word) — write boolean with width"});
        FLIRT_DESCRIPTIONS.put("_Write_qm4Text4Real4Wordt3",    new String[]{"bp_write_real",    "Write(Text, Real, Word, Word) — write real number"});
        FLIRT_DESCRIPTIONS.put("_Read_qm4Text4Char",            new String[]{"bp_read_char",     "Read(Text, Char) — read character"});
        FLIRT_DESCRIPTIONS.put("_Read_qm4Text7Longint",         new String[]{"bp_read_longint",  "Read(Text, Longint) — read longint"});
        FLIRT_DESCRIPTIONS.put("_Read_qm4Textm6String4Word",    new String[]{"bp_read_str",      "Read(Text, String, Word) — read string with max length"});
        // String operations
        FLIRT_DESCRIPTIONS.put("_Concat_qm6Stringt1",           new String[]{"bp_concat",        "Concat(String, String) — string concatenation"});
        FLIRT_DESCRIPTIONS.put("_Copy_qm6Stringt17Integert3",   new String[]{"bp_copy",          "Copy(String, String, Integer, Integer) — substring"});
        FLIRT_DESCRIPTIONS.put("_Pos_qm6Stringt1",              new String[]{"bp_pos",           "Pos(String, String) — find substring position"});
        FLIRT_DESCRIPTIONS.put("_Delete_qm6String7Integert2",   new String[]{"bp_delete",        "Delete(String, Integer, Integer) — delete substring"});
        FLIRT_DESCRIPTIONS.put("_Insert_qm6Stringt14Word7Integer", new String[]{"bp_insert",     "Insert(String, String, Word, Integer) — insert substring"});
        FLIRT_DESCRIPTIONS.put("_Str_q7Longint4Wordm6String4Byte", new String[]{"bp_str_long",   "Str(Longint, Word, String, Byte) — longint to string"});
        FLIRT_DESCRIPTIONS.put("_Random_q4Word",                new String[]{"bp_random",        "Random(Word) — random integer 0..N-1"});
        FLIRT_DESCRIPTIONS.put("_GetMem_q4Word",                new String[]{"bp_getmem",        "GetMem(Word) — allocate raw memory"});
        FLIRT_DESCRIPTIONS.put("_AssignCrt_qm4Text",            new String[]{"crt_assigncrt",    "AssignCrt(Text) — assign text to CRT"});
        FLIRT_DESCRIPTIONS.put("_GotoXY_q4Bytet1",              new String[]{"crt_gotoxy",       "GotoXY(Byte, Byte) — position cursor"});
        FLIRT_DESCRIPTIONS.put("_Window_q4Bytet1t2t3",          new String[]{"crt_window",       "Window(X1,Y1,X2,Y2) — set text window"});
        FLIRT_DESCRIPTIONS.put("_GetDate_qm4Wordt1t1t1",        new String[]{"dos_getdate",      "GetDate(Word,Word,Word,Word)"});
        FLIRT_DESCRIPTIONS.put("_GetTime_qm4Wordt1t1t1",        new String[]{"dos_gettime",      "GetTime(Word,Word,Word,Word)"});
        FLIRT_DESCRIPTIONS.put("_FindFirst_q7PathStr4Wordm9SearchRec", new String[]{"dos_findfirst", "FindFirst(PathStr,Word,SearchRec)"});
        FLIRT_DESCRIPTIONS.put("_GetEnv_q6String",              new String[]{"dos_getenv",       "GetEnv(String) — get environment variable"});
        FLIRT_DESCRIPTIONS.put("_basg_qm6Stringt1",             new String[]{"bp_str_assign",    "String assignment"});
        FLIRT_DESCRIPTIONS.put("_basg_qm6Stringt14Byte",        new String[]{"bp_str_assign_n",  "String assignment with max length"});
        FLIRT_DESCRIPTIONS.put("__basg_qm6Stringt1",            new String[]{"bp_str_assign",    "String assignment"});
        FLIRT_DESCRIPTIONS.put("__basg_qm6Stringt14Byte",       new String[]{"bp_str_assign_n",  "String assignment with max length"});
        FLIRT_DESCRIPTIONS.put("_bp_stackcheck_q4Word",         new String[]{"bp_unit_init",     "Unit initialization / stack check"});
        FLIRT_DESCRIPTIONS.put("_IOResult_qv",                  new String[]{"bp_ioresult",      "IOResult — last I/O result code"});
        FLIRT_DESCRIPTIONS.put("_UpCase_q4Char",                new String[]{"bp_upcase",        "UpCase(Char) — convert to uppercase"});
        FLIRT_DESCRIPTIONS.put("_RunError_q4Byte",              new String[]{"bp_runerror",      "RunError(Byte) — trigger runtime error"});
        FLIRT_DESCRIPTIONS.put("_Concat_qm6Stringm6String",     new String[]{"bp_concat",        "Concat(String, String) — string concatenation"});
        FLIRT_DESCRIPTIONS.put("_Copy_qm6String7Integer7Integer", new String[]{"bp_copy",        "Copy(String, Index, Count) — substring"});
        FLIRT_DESCRIPTIONS.put("_Length_qm6String",              new String[]{"bp_length",        "Length(String) — string length"});
        FLIRT_DESCRIPTIONS.put("_Pos_qm6Stringm6String",        new String[]{"bp_pos",           "Pos(Substr, S) — find substring"});
        FLIRT_DESCRIPTIONS.put("_Delete_qm6String7Integer7Integer", new String[]{"bp_delete",    "Delete(S, Index, Count) — delete substring"});
        FLIRT_DESCRIPTIONS.put("_Insert_qm6Stringm6String7Integer", new String[]{"bp_insert",    "Insert(Source, S, Index) — insert substring"});
        FLIRT_DESCRIPTIONS.put("_Val_qm6Stringm7Integerm7Integer",  new String[]{"bp_val_int",   "Val(S, V, Code) — string to integer"});
        FLIRT_DESCRIPTIONS.put("_Val_qm6Stringm7Longintm7Integer",  new String[]{"bp_val_long",  "Val(S, V, Code) — string to longint"});
        FLIRT_DESCRIPTIONS.put("_Str_q7Integerm6String",         new String[]{"bp_str_int",       "Str(I, S) — integer to string"});
        FLIRT_DESCRIPTIONS.put("_Str_q7Longintm6String",         new String[]{"bp_str_long",      "Str(L, S) — longint to string"});
        FLIRT_DESCRIPTIONS.put("_Random_q7Integer",              new String[]{"bp_random",        "Random(N) — random integer 0..N-1"});
        FLIRT_DESCRIPTIONS.put("_Randomize_qv",                  new String[]{"bp_randomize",     "Randomize — seed from system clock"});
        FLIRT_DESCRIPTIONS.put("_Halt_q4Word",                   new String[]{"bp_halt",          "Halt(ExitCode) — terminate program"});
        FLIRT_DESCRIPTIONS.put("_Rename_qm4Filem6String",        new String[]{"bp_rename",        "Rename(File, NewName)"});
        FLIRT_DESCRIPTIONS.put("_Erase_qm4File",                 new String[]{"bp_erase",         "Erase(File) — delete file"});
        FLIRT_DESCRIPTIONS.put("_Assign_qm4Filem6String",        new String[]{"bp_assign",        "Assign(File, Name) — bind filename to file var"});
        FLIRT_DESCRIPTIONS.put("_Reset_qm4File",                 new String[]{"bp_reset",         "Reset(File) — open for reading"});
        FLIRT_DESCRIPTIONS.put("_Rewrite_qm4File",               new String[]{"bp_rewrite",       "Rewrite(File) — open for writing"});
        FLIRT_DESCRIPTIONS.put("_Close_qm4File",                 new String[]{"bp_close",         "Close(File)"});
        FLIRT_DESCRIPTIONS.put("_Seek_qm4File7Longint",          new String[]{"bp_seek",          "Seek(File, Position)"});
        FLIRT_DESCRIPTIONS.put("_FileSize_qm4File",              new String[]{"bp_filesize",      "FileSize(File) — number of records"});
        FLIRT_DESCRIPTIONS.put("_FilePos_qm4File",               new String[]{"bp_filepos",       "FilePos(File) — current position"});
        FLIRT_DESCRIPTIONS.put("_Eof_qm4File",                   new String[]{"bp_eof",           "Eof(File) — end of file check"});
        FLIRT_DESCRIPTIONS.put("_Eof_qm4Text",                   new String[]{"bp_eof_text",      "Eof(Text) — end of text file"});
        FLIRT_DESCRIPTIONS.put("_ParamCount_qv",                  new String[]{"bp_paramcount",    "ParamCount — number of command line args"});
        FLIRT_DESCRIPTIONS.put("_ParamStr_q4Word",                new String[]{"bp_paramstr",      "ParamStr(Index) — command line argument"});
        FLIRT_DESCRIPTIONS.put("_GetEnv_qm6String",               new String[]{"bp_getenv",        "GetEnv(Name) — get environment variable"});
        FLIRT_DESCRIPTIONS.put("_New_qm7Pointer",                 new String[]{"bp_new",           "New(Ptr) — allocate on heap"});
        FLIRT_DESCRIPTIONS.put("_Dispose_qm7Pointer",             new String[]{"bp_dispose",       "Dispose(Ptr) — free heap memory"});
        FLIRT_DESCRIPTIONS.put("_GetMem_qm7Pointer4Word",         new String[]{"bp_getmem",        "GetMem(Ptr, Size) — allocate raw memory"});
        FLIRT_DESCRIPTIONS.put("_FreeMem_qm7Pointer4Word",        new String[]{"bp_freemem",       "FreeMem(Ptr, Size) — free raw memory"});
        FLIRT_DESCRIPTIONS.put("_MemAvail_qv",                    new String[]{"bp_memavail",      "MemAvail — available heap memory"});
        FLIRT_DESCRIPTIONS.put("_MaxAvail_qv",                    new String[]{"bp_maxavail",      "MaxAvail — largest free block"});
        FLIRT_DESCRIPTIONS.put("_ClrScr_qv",                      new String[]{"crt_clrscr",       "ClrScr — clear screen"});
        FLIRT_DESCRIPTIONS.put("_GotoXY_q4Byte4Byte",             new String[]{"crt_gotoxy",       "GotoXY(X, Y) — position cursor"});
        FLIRT_DESCRIPTIONS.put("_WhereX_qv",                      new String[]{"crt_wherex",       "WhereX — current cursor column"});
        FLIRT_DESCRIPTIONS.put("_WhereY_qv",                      new String[]{"crt_wherey",       "WhereY — current cursor row"});
        FLIRT_DESCRIPTIONS.put("_TextColor_q4Byte",               new String[]{"crt_textcolor",    "TextColor(Color) — set foreground"});
        FLIRT_DESCRIPTIONS.put("_TextBackground_q4Byte",          new String[]{"crt_textbg",       "TextBackground(Color) — set background"});
        FLIRT_DESCRIPTIONS.put("_Delay_q4Word",                   new String[]{"crt_delay",        "Delay(MS) — millisecond pause"});
        FLIRT_DESCRIPTIONS.put("_Sound_q4Word",                   new String[]{"crt_sound",        "Sound(Hz) — start speaker tone"});
        FLIRT_DESCRIPTIONS.put("_NoSound_qv",                     new String[]{"crt_nosound",      "NoSound — stop speaker"});
        FLIRT_DESCRIPTIONS.put("_ReadKey_qv",                     new String[]{"crt_readkey",      "ReadKey — read character from keyboard"});
        FLIRT_DESCRIPTIONS.put("_KeyPressed_qv",                  new String[]{"crt_keypressed",   "KeyPressed — check if key available"});
        FLIRT_DESCRIPTIONS.put("_TextMode_q7Integer",             new String[]{"crt_textmode",     "TextMode(Mode) — set text video mode"});
        FLIRT_DESCRIPTIONS.put("_Window_q4Byte4Byte4Byte4Byte",   new String[]{"crt_window",       "Window(X1,Y1,X2,Y2) — set text window"});
        FLIRT_DESCRIPTIONS.put("_InsLine_qv",                     new String[]{"crt_insline",      "InsLine — insert line at cursor"});
        FLIRT_DESCRIPTIONS.put("_DelLine_qv",                     new String[]{"crt_delline",      "DelLine — delete line at cursor"});
        FLIRT_DESCRIPTIONS.put("_GetDate_qm4Wordm4Wordm4Wordm4Word", new String[]{"dos_getdate",  "GetDate(Year,Month,Day,DOW)"});
        FLIRT_DESCRIPTIONS.put("_GetTime_qm4Wordm4Wordm4Wordm4Word", new String[]{"dos_gettime",  "GetTime(Hour,Min,Sec,Sec100)"});
        FLIRT_DESCRIPTIONS.put("_FindFirst_qm6String4Wordm9SearchRec", new String[]{"dos_findfirst", "FindFirst(Path,Attr,SR)"});
        FLIRT_DESCRIPTIONS.put("_FindNext_qm9SearchRec",          new String[]{"dos_findnext",     "FindNext(SR) — find next matching file"});
        FLIRT_DESCRIPTIONS.put("_DiskFree_q4Byte",                new String[]{"dos_diskfree",     "DiskFree(Drive) — free disk space"});
        FLIRT_DESCRIPTIONS.put("_DiskSize_q4Byte",                new String[]{"dos_disksize",     "DiskSize(Drive) — total disk size"});
        FLIRT_DESCRIPTIONS.put("_DosVersion_qv",                  new String[]{"dos_dosversion",   "DosVersion — DOS version number"});
        FLIRT_DESCRIPTIONS.put("_EnvCount_qv",                    new String[]{"dos_envcount",     "EnvCount — number of environment strings"});
        FLIRT_DESCRIPTIONS.put("_EnvStr_q7Integer",               new String[]{"dos_envstr",       "EnvStr(Index) — environment string by index"});
        FLIRT_DESCRIPTIONS.put("_SwapVectors_qv",                 new String[]{"dos_swapvectors",  "SwapVectors — swap interrupt vectors"});
        FLIRT_DESCRIPTIONS.put("_Exec_qm6Stringm6String",         new String[]{"dos_exec",         "Exec(Path, CmdLine) — run external program"});
        FLIRT_DESCRIPTIONS.put("_OvrInit_qm6String",              new String[]{"ovr_init",         "OvrInit(FileName) — initialize overlay system"});
        FLIRT_DESCRIPTIONS.put("_OvrInitEMS_qv",                  new String[]{"ovr_initems",      "OvrInitEMS — use EMS for overlays"});
        // DDPlus
        FLIRT_DESCRIPTIONS.put("_sclrscr_qv",                    new String[]{"ddp_sclrscr",      "DDPlus sclrscr — clear screen"});
        FLIRT_DESCRIPTIONS.put("_sclreol_qv",                    new String[]{"ddp_sclreol",      "DDPlus sclreol — clear to end of line"});
        FLIRT_DESCRIPTIONS.put("_swrite_q6String",               new String[]{"ddp_swrite",       "DDPlus swrite(s) — send string"});
        FLIRT_DESCRIPTIONS.put("_swriteln_q6String",             new String[]{"ddp_swriteln",     "DDPlus swriteln(s) — send string + CR/LF"});
        FLIRT_DESCRIPTIONS.put("_swritec_q4Char",                new String[]{"ddp_swritec",      "DDPlus swritec(ch) — send single character"});
        FLIRT_DESCRIPTIONS.put("_swritexy_q7Integert16String",   new String[]{"ddp_swritexy",     "DDPlus swritexy(x,y,s) — position then write"});
        FLIRT_DESCRIPTIONS.put("_sgoto_xy_q7Integert1",          new String[]{"ddp_sgoto_xy",     "DDPlus sgoto_xy(x,y) — ANSI cursor move"});
        FLIRT_DESCRIPTIONS.put("_sendtext_q6String",             new String[]{"ddp_sendtext",     "DDPlus sendtext(s) — raw string to modem"});
        FLIRT_DESCRIPTIONS.put("_set_foreground_q4Byte",         new String[]{"ddp_set_foreground", "DDPlus set_foreground(color)"});
        FLIRT_DESCRIPTIONS.put("_set_background_q4Byte",         new String[]{"ddp_set_background", "DDPlus set_background(color)"});
        FLIRT_DESCRIPTIONS.put("_set_color_q4Bytet1",            new String[]{"ddp_set_color",    "DDPlus set_color(fg,bg)"});
        FLIRT_DESCRIPTIONS.put("_Clear_Region_q4Bytet1t2",       new String[]{"ddp_clear_region", "DDPlus Clear_Region(x,r1,r2)"});
        FLIRT_DESCRIPTIONS.put("_Propeller_q4Byte",              new String[]{"ddp_propeller",    "DDPlus Propeller(v)"});
        FLIRT_DESCRIPTIONS.put("_display_status_qv",             new String[]{"ddp_display_status", "DDPlus display_status"});
        FLIRT_DESCRIPTIONS.put("_Displayfile_q6String",          new String[]{"ddp_displayfile",  "DDPlus Displayfile(name)"});
        FLIRT_DESCRIPTIONS.put("_SelectAnsi_q4Char6String",      new String[]{"ddp_selectansi",   "DDPlus SelectAnsi(flag,name)"});
        FLIRT_DESCRIPTIONS.put("_sread_char_qm4Char",            new String[]{"ddp_sread_char",   "DDPlus sread_char(var ch)"});
        FLIRT_DESCRIPTIONS.put("_sread_char_filtered_qm4Char",   new String[]{"ddp_sread_char_filt", "DDPlus sread_char_filtered"});
        FLIRT_DESCRIPTIONS.put("_speedread_qm4Char",             new String[]{"ddp_speedread",    "DDPlus speedread(var ch)"});
        FLIRT_DESCRIPTIONS.put("_sread_qm6String",               new String[]{"ddp_sread",        "DDPlus sread(var s)"});
        FLIRT_DESCRIPTIONS.put("_sread_num_qm7Integer",          new String[]{"ddp_sread_num",    "DDPlus sread_num(var n)"});
        FLIRT_DESCRIPTIONS.put("_sread_num_byte_qm4Byte",        new String[]{"ddp_sread_num_byte", "DDPlus sread_num_byte(var b)"});
        FLIRT_DESCRIPTIONS.put("_sread_num_word_qm4Word",        new String[]{"ddp_sread_num_word", "DDPlus sread_num_word(var w)"});
        FLIRT_DESCRIPTIONS.put("_sread_num_longint_qm7Longint",  new String[]{"ddp_sread_num_long", "DDPlus sread_num_longint(var l)"});
        FLIRT_DESCRIPTIONS.put("_prompt_qm6String7Integer7Boolean", new String[]{"ddp_prompt",    "DDPlus prompt(var s, maxlen, passmode)"});
        FLIRT_DESCRIPTIONS.put("_get_stacked_qm6String",         new String[]{"ddp_get_stacked",  "DDPlus get_stacked"});
        FLIRT_DESCRIPTIONS.put("_skeypressed_qv",                new String[]{"ddp_skeypressed",  "DDPlus skeypressed — non-blocking key check"});
        FLIRT_DESCRIPTIONS.put("_time_left_qv",                  new String[]{"ddp_time_left",    "DDPlus time_left — BBS minutes remaining"});
        FLIRT_DESCRIPTIONS.put("_Time_used_qv",                  new String[]{"ddp_time_used",    "DDPlus Time_used — minutes used in door"});
        FLIRT_DESCRIPTIONS.put("_elapsed_q7Longintt1t2t3t4t5m4Wordt1t2", new String[]{"ddp_elapsed", "DDPlus elapsed — time difference"});
        FLIRT_DESCRIPTIONS.put("_InitDoorDriver_q6String",       new String[]{"ddp_init",         "DDPlus InitDoorDriver(cfg)"});
        FLIRT_DESCRIPTIONS.put("_DDAssignSoutput_qm4Text",       new String[]{"ddp_assign_soutput", "DDPlus DDAssignSoutput(f)"});
        FLIRT_DESCRIPTIONS.put("_open_async_port_qv",            new String[]{"ddp_open_async",   "DDPlus open_async_port"});
        FLIRT_DESCRIPTIONS.put("_close_async_port_qv",           new String[]{"ddp_close_async",  "DDPlus close_async_port"});
        FLIRT_DESCRIPTIONS.put("_ReleaseTimeSlice_qv",           new String[]{"ddp_timeslice",    "DDPlus ReleaseTimeSlice"});
        FLIRT_DESCRIPTIONS.put("_DV_Aware_On_qv",                new String[]{"ddp_dv_aware",     "DDPlus DV_Aware_On"});
        // COMIO
        FLIRT_DESCRIPTIONS.put("_AsyncSendChar_q4Char",          new String[]{"comio_send_char",  "COMIO AsyncSendChar(ch)"});
        FLIRT_DESCRIPTIONS.put("_AsyncReceiveChar_qm4Char",      new String[]{"comio_recv_char",  "COMIO AsyncReceiveChar(var ch)"});
        FLIRT_DESCRIPTIONS.put("_AsyncCarrierPresent_qv",        new String[]{"comio_carrier",    "COMIO AsyncCarrierPresent"});
        FLIRT_DESCRIPTIONS.put("_AsyncCharPresent_qv",           new String[]{"comio_char_ready", "COMIO AsyncCharPresent"});
        FLIRT_DESCRIPTIONS.put("_AsyncSetBaud_q7Longint",        new String[]{"comio_set_baud",   "COMIO AsyncSetBaud(n)"});
        FLIRT_DESCRIPTIONS.put("_AsyncSetDTR_q7Boolean",         new String[]{"comio_set_dtr",    "COMIO AsyncSetDTR(state)"});
        FLIRT_DESCRIPTIONS.put("_AsyncFlushOutput_qv",           new String[]{"comio_flush",      "COMIO AsyncFlushOutput"});
        FLIRT_DESCRIPTIONS.put("_AsyncPurgeOutput_qv",           new String[]{"comio_purge",      "COMIO AsyncPurgeOutput"});
        FLIRT_DESCRIPTIONS.put("_AsyncSelectPort_q4Byte",        new String[]{"comio_select_port", "COMIO AsyncSelectPort(n)"});
        FLIRT_DESCRIPTIONS.put("_AsyncSetFlow_q7Booleant1t2",    new String[]{"comio_set_flow",   "COMIO AsyncSetFlow(soft_tx,hard,soft_rx)"});
        // Plain (non-mangled) FLIRT names
        FLIRT_PLAIN_DESCRIPTIONS.put("__ClearDSeg",     new String[]{"bp_clear_dseg",    "Clear data segment (BSS init)"});
        FLIRT_PLAIN_DESCRIPTIONS.put("__InOutProc",     new String[]{"bp_inoutproc",     "I/O procedure dispatcher"});
        FLIRT_PLAIN_DESCRIPTIONS.put("__PrintString",   new String[]{"bp_printstring",   "Print string to stdout"});
        FLIRT_PLAIN_DESCRIPTIONS.put("__IOCheck",       new String[]{"bp_iocheck",       "Check I/O result code"});
    }

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args == null || args.length == 0) {
            printerr("Usage: -postScript CreateBPSignatures.java <output.json>");
            return;
        }
        String jsonPath = args[0];

        // Load existing signatures (for incremental building from multiple programs)
        Map<String, String[]> sigs = new LinkedHashMap<>();
        File jsonFile = new File(jsonPath);
        if (jsonFile.exists()) {
            sigs = loadSignatures(jsonFile);
            println("Loaded " + sigs.size() + " existing signatures");
        }

        FidService fidService = new FidService();
        FunctionManager fm = currentProgram.getFunctionManager();
        FunctionIterator it = fm.getFunctions(true);
        int added = 0, skipped = 0, unhashed = 0;

        while (it.hasNext()) {
            Function func = it.next();
            String name = func.getName();

            // Look up FLIRT name → [shortName, description]
            String[] info = lookupFlirtName(name);
            if (info == null) continue;

            // Hash the function body
            try {
                FidHashQuad hash = fidService.hashFunction(func);
                if (hash == null) {
                    unhashed++;
                    println("  SKIP (unhashable): " + name + " → " + info[0]);
                    continue;
                }

                String hashKey = String.format("%016x", hash.getFullHash());
                if (!sigs.containsKey(hashKey)) {
                    sigs.put(hashKey, new String[]{info[0], info[1]});
                    added++;
                    println("  + " + info[0] + " (hash=" + hashKey
                        + ", size=" + hash.getCodeUnitSize() + ")");
                } else {
                    skipped++;
                }
            } catch (MemoryAccessException e) {
                unhashed++;
                println("  SKIP (memory error): " + name);
            }
        }

        // Write signatures
        writeSignatures(jsonFile, sigs);
        println("Program: " + currentProgram.getName()
            + " — added=" + added + " skipped=" + skipped
            + " unhashed=" + unhashed + " total=" + sigs.size());
    }

    /**
     * Look up a FLIRT mangled name and return [shortName, description],
     * or null if the name is not FLIRT-identified.
     *
     * FLIRT names in Ghidra use @ and $ (e.g. @Write$qm4Text4Word)
     * while FLIRT_DESCRIPTIONS keys use _ (e.g. _Write_qm4Text4Word)
     * because that's how Ghidra renders them in C output.
     */
    private String[] lookupFlirtName(String name) {
        // Normalize @ and $ to _ for lookup (Ghidra internal → C-rendered form)
        String cName = name.replace('@', '_').replace('$', '_');

        // Explicit FLIRT descriptions
        String[] info = FLIRT_DESCRIPTIONS.get(cName);
        if (info != null) return info;

        info = FLIRT_PLAIN_DESCRIPTIONS.get(cName);
        if (info != null) return info;

        // Also check original name (for names that already use _)
        info = FLIRT_DESCRIPTIONS.get(name);
        if (info != null) return info;
        info = FLIRT_PLAIN_DESCRIPTIONS.get(name);
        if (info != null) return info;

        // Generic decode for _Name_q... or @Name$q... patterns
        if ((cName.startsWith("_") && !cName.startsWith("__") && cName.contains("_q"))
            || (name.startsWith("@") && name.contains("$q"))) {
            String normalized = cName.startsWith("_") ? cName : cName;
            String[] parts = normalized.split("_q", 2);
            String funcPart = parts[0].startsWith("_") ? parts[0].substring(1) : parts[0];
            String params = parts.length > 1 ? parts[1] : "";
            return new String[]{
                "bp_" + funcPart.toLowerCase(),
                funcPart + "(" + params + ") — FLIRT-identified"
            };
        }

        // Double-underscore system functions
        if (cName.startsWith("__") && cName.length() > 2) {
            String baseName = cName.substring(2);
            return new String[]{
                "bp_" + baseName.toLowerCase(),
                baseName + " — system runtime function"
            };
        }

        return null;
    }

    /**
     * Load existing signatures from JSON file.
     * Format: { "hash": ["name", "description"], ... }
     */
    private Map<String, String[]> loadSignatures(File file) throws IOException {
        Map<String, String[]> sigs = new LinkedHashMap<>();
        Pattern p = Pattern.compile("\"([0-9a-f]{16})\"\\s*:\\s*\\[\"([^\"]+)\"\\s*,\\s*\"([^\"]*)\"\\]");
        BufferedReader br = new BufferedReader(new FileReader(file));
        String line;
        while ((line = br.readLine()) != null) {
            Matcher m = p.matcher(line);
            if (m.find()) {
                sigs.put(m.group(1), new String[]{m.group(2), m.group(3)});
            }
        }
        br.close();
        return sigs;
    }

    /**
     * Write signatures to JSON file.
     */
    private void writeSignatures(File file, Map<String, String[]> sigs) throws IOException {
        file.getParentFile().mkdirs();
        PrintWriter pw = new PrintWriter(new FileWriter(file));
        pw.println("{");
        boolean first = true;
        for (Map.Entry<String, String[]> e : sigs.entrySet()) {
            if (!first) pw.println(",");
            String[] v = e.getValue();
            pw.print("  \"" + e.getKey() + "\": [\""
                + escapeJson(v[0]) + "\", \""
                + escapeJson(v[1]) + "\"]");
            first = false;
        }
        pw.println();
        pw.println("}");
        pw.close();
    }

    private String escapeJson(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
