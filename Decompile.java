// Decompile.java — Consolidated Ghidra headless decompiler script
//
// Replaces the multi-pass pipeline (DecompileAll.java + annotate_strings.py +
// label_functions.py) with a single GhidraScript that produces a fully
// annotated and labeled decompiled output file in one pass.
//
// What this script does:
//   Phase 1: Find Pascal strings and define them as data types
//   Phase 2: Build string database (offset → text)
//   Phase 2.5: Register BP7 standard types (TextRec, FileRec, etc.)
//   Phase 3: Identify and label known library functions (offset-based + FLIRT)
//   Phase 4: Decompile all functions with inline string annotations
//   Phase 5: Apply function renames, clean up types, eliminate library bodies,
//            clean CONCAT11 artifacts, remove unused declarations, write output
//   Phase 6: Write strings.json
//
// Usage:
//   analyzeHeadless <proj-dir> <proj-name> -process <EXE> \
//     -postScript Decompile.java [output-file] \
//     -scriptPath .
//
// Arguments:
//   output-file  Path to write decompiled output (default: decompiled.c in cwd)
//
// Output:
//   - decompiled.c:  Fully annotated and labeled C pseudocode
//   - strings.json:  Quality-filtered Pascal strings with Ghidra addresses
//
// IMPORTANT: Run ApplySigHeadless.py BEFORE this script for FLIRT renaming.
//            FLIRT sig parsing requires Python and cannot be consolidated here.

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.*;
import ghidra.program.util.string.FoundString;
import java.io.*;
import java.util.*;
import java.util.regex.*;

public class Decompile extends GhidraScript {

    // ── String database: Ghidra linear address → string text ──
    private Map<Long, String> stringDb = new HashMap<>();
    // ── String address labels: linear address → "seg:off" string for JSON ──
    private Map<Long, String> stringAddrDb = new HashMap<>();

    // ── Registered BP7 data types ──
    private Map<String, DataType> bp7Types = new HashMap<>();

    // ── Label tables ──
    // Format: offset-within-segment → (short_name, description)

    // Borland Pascal 7 System RTL (large binary variant)
    private static final String[][] BP_SYSTEM_LABELS = {
        {"0530", "bp_unit_init",        "Unit initialization / stack check"},
        {"04f4", "bp_str_temp_free",    "Free temporary string (@LStrClr)"},
        {"3275", "bp_str_pos",          "Pos() — find substring position"},
        {"3646", "bp_str_compare",      "String comparison"},
        {"36c9", "bp_str_dispose",      "Dispose string memory"},
        {"371e", "bp_str_assign_var",   "Assign string from variable"},
        {"38fd", "bp_file_assign",      "Assign() — bind filename to file var"},
        {"393d", "bp_file_rewrite",     "Rewrite() — open file for writing"},
        {"395e", "bp_file_reset",       "Reset() — open file for reading"},
        {"3a61", "bp_file_close",       "Close() — close file"},
        {"39db", "bp_file_read",        "Read from file"},
        {"3ae9", "bp_file_write",       "Write to file"},
        {"3c24", "bp_blockread",        "BlockRead() — read binary block"},
        {"3e22", "bp_blockwrite",       "BlockWrite() — write binary block"},
        {"3f4b", "bp_str_assign",       "Assign string from constant"},
        {"3f65", "bp_str_copy",         "Copy string (bounded, like Copy())"},
        {"3f89", "bp_str_equal",        "String equality check"},
        {"3fca", "bp_str_concat",       "String concatenation (+)"},
        {"3ff6", "bp_str_concat_assign","Concat and assign"},
        {"403c", "bp_str_copy_far",     "Far string copy"},
        {"4067", "bp_char_to_str",      "Char-to-string conversion"},
        {"40f3", "bp_int_to_str",       "Integer-to-string (Str())"},
        {"46d0", "bp_random_seed",      "Random seed / RandSeed access"},
        {"46e4", "bp_random",           "Random(N) — generate random number"},
        {"48da", "bp_halt",             "Halt / RunError handler"},
        {"0549", "bp_textrec_init",     "TextRec buffer init"},
        {"05c7", "bp_output_init",      "Unit output initializer (thin wrapper)"},
        {"0621", "bp_text_open_check",  "Text file mode check / open for I/O"},
        {"0840", "bp_writeln_impl",     "WriteLn implementation (large RTL variant)"},
        {"0861", "bp_flush_text_cond",  "Conditional text buffer flush (large RTL)"},
        {"08de", "bp_write_char_buf",   "Write character to TextRec buffer"},
        {"0964", "bp_write_str_body",   "Write(Text, String, Word) inner body"},
        {"0e45", "bp_str_append",       "String append / concatenation"},
        {"0e71", "bp_str_val_scan",     "String scanning for Val()"},
        {"0eb7", "bp_str_assign_cap",   "String assignment with length cap"},
        {"0ee2", "bp_mkstr1",           "Build 1-char Pascal string from Char"},
        {"0f6e", "bp_str_delete",       "Delete() — remove substring from string"},
        {"1e6d", "bp_val_parse",        "Val() — parse string to integer value"},
    };

    // Core System RTL (present in ALL TP7 binaries)
    private static final String[][] BP_SYSTEM_CORE_LABELS = {
        {"00b1", "bp_module_init",      "Module initialization (sets unit flag)"},
        {"010f", "bp_exit_handler",     "Heap manager / exit handler"},
        {"0116", "bp_halt_handler",     "Halt handler with interrupt restore"},
        {"01f0", "bp_print_loop",       "Print character loop (null-terminated)"},
        {"01fe", "bp_print_decimal",    "Decimal digit printer"},
        {"020a", "bp_div_digit",        "Digit divider for decimal output"},
        {"0218", "bp_char_out_setup",   "Console character output setup"},
        {"0232", "bp_char_out",         "Single character output via INT 21h"},
        {"0291", "bp_iocheck",          "Check I/O result code (IOCheck)"},
        {"02cd", "bp_stack_check",      "Stack overflow check"},
        {"02e6", "bp_runtime_init",     "Runtime initialization"},
        {"0364", "bp_input_init",       "Input TextRec initialization"},
        {"0369", "bp_output_init",      "Output TextRec initialization"},
        {"0371", "bp_textrec_init",     "TextRec initialization helper"},
        {"03be", "bp_write_setup",      "Write buffer setup"},
        {"03fa", "bp_writeln_impl",     "WriteLn implementation"},
        {"04ed", "bp_str_temp_read",    "Atomic read & clear temporary string pointer"},
        {"0627", "bp_read_setup",       "Read buffer setup"},
        {"0701", "bp_write_str",        "Write(Text, String, Word) — write string"},
        {"07bd", "bp_longint_mul",      "Longint multiply (32-bit on 16-bit)"},
        {"07d7", "bp_str_assign_const", "Assign string from constant"},
        {"08ec", "bp_str_copy_const",   "Copy string from constant source"},
    };

    // RHP Display Library
    private static final String[][] RHP_DISPLAY_LABELS = {
        {"0002", "rhp_lw",      "lw() — write inline text (no newline)"},
        {"02a8", "rhp_lln",     "lln() — write line with newline"},
        {"054e", "rhp_sln",     "sln() — write blank line"},
    };

    // RHP Input Library
    private static final String[][] RHP_INPUT_LABELS = {
        {"0d37", "rhp_display_char",    "Display character with typewriter delay"},
        {"0de1", "rhp_display_slow",    "Slow display variant"},
        {"1168", "rhp_getkey",          "getkey() — read single keypress"},
        {"14e7", "rhp_readline",        "Read line of text input"},
        {"1cdb", "rhp_check_carrier",   "Check carrier detect / online status"},
        {"2516", "rhp_clear_screen",    "Clear screen / reset display"},
        {"0c54", "rhp_cls",             "Clear screen (alternate)"},
    };

    // Conversion / Math Library
    private static final String[][] CONV_LABELS = {
        {"0002", "bp_int_to_str_2",     "IntToStr — integer to string"},
        {"011d", "bp_longint_to_str",   "LongintToStr — longint to string"},
        {"04c7", "bp_str_to_int",       "Val() — string to integer"},
        {"0c6f", "bp_val_longint",      "Val() — string to longint"},
        {"0d7a", "bp_str_pad",          "String pad/format (right-justify)"},
        {"0df7", "bp_str_pad_left",     "String pad left"},
    };

    // Timer / System Library
    private static final String[][] TIMER_LABELS = {
        {"02fa", "rhp_delay",           "delay() / mswait — millisecond pause"},
        {"068c", "rhp_timer_check",     "Timer check / timeout detection"},
    };

    // Record / File Library
    private static final String[][] RECORD_LABELS = {
        {"00f5", "bp_file_open",        "Open file"},
        {"01ce", "bp_record_read",      "Read record from file"},
        {"02b6", "bp_record_write",     "Write record to file"},
    };

    // DDPlus 7.1 Door Driver Toolkit
    private static final String[][] DDPLUS_LABELS = {
        {"00bb", "ddp_str_input",       "DDPlus string input/copy helper"},
        {"0143", "ddp_str_parse",       "DDPlus string parse/scan helper"},
        {"0080", "ddp_clear_region",    "DDPlus Clear_Region(x,r1,r2) — blank rows"},
        {"06ad", "ddp_time_left",       "DDPlus time_left — BBS minutes remaining"},
        {"10bb", "ddp_sendtext",        "DDPlus sendtext(s) — raw string to modem"},
        {"1129", "ddp_morecheck",       "DDPlus morecheck — pause-per-screenful"},
        {"11b7", "ddp_sclrscr",         "DDPlus sclrscr — clear screen (ANSI+local)"},
        {"1209", "ddp_sclreol",         "DDPlus sclreol — clear to end of line"},
        {"12a4", "ddp_swritec",         "DDPlus swritec(ch) — send single character"},
        {"130c", "ddp_swrite",          "DDPlus swrite(s) — send string, no newline"},
        {"13b6", "ddp_swriteln",        "DDPlus swriteln(s) — send string + CR/LF"},
        {"14e0", "ddp_swritexy",        "DDPlus swritexy(x,y,s) — position then write"},
        {"1590", "ddp_propeller",       "DDPlus Propeller(v) — spinning progress indicator"},
        {"1d30", "ddp_ansi_dispatch",   "DDPlus ANSI color dispatch (internal)"},
        {"1d95", "ddp_set_foreground",  "DDPlus set_foreground(color) — ANSI fg color"},
        {"211f", "ddp_set_background",  "DDPlus set_background(color) — ANSI bg color"},
        {"21da", "ddp_set_color",       "DDPlus set_color(fg,bg) — set ANSI colors"},
        {"281e", "ddp_sgoto_xy",        "DDPlus sgoto_xy(x,y) — ANSI cursor move"},
    };

    // DDPlus IO utility unit
    private static final String[][] DDPLUS_IO_LABELS = {
        {"00bb", "ddp_str_input",    "DDPlus string input/copy helper"},
        {"0143", "ddp_str_parse",    "DDPlus string parse/scan helper"},
    };

    // Borland Pascal CRT unit
    private static final String[][] CRT_UNIT_LABELS = {
        {"021f", "crt_gotoxy_impl",   "GotoXY(X,Y) — cursor positioning with bounds check"},
        {"024b", "crt_wherex_impl",   "WhereX — current cursor column (window-relative)"},
        {"0257", "crt_wherey_impl",   "WhereY — current cursor row (window-relative)"},
        {"0263", "crt_textattr_set",  "TextColor/TextBackground — set color attribute byte"},
    };

    // ── FLIRT descriptions ──
    // Maps Ghidra's C-rendered FLIRT names to (short_name, description)
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
        FLIRT_DESCRIPTIONS.put("_Randomize_qv",                  new String[]{"bp_random",        "Random(Word) — FLIRT misidentifies Random as Randomize"});
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

    // ── Core offsets used to identify System RTL segment ──
    private static final Set<String> CORE_RTL_OFFSETS = new HashSet<>();
    static {
        for (String[] entry : BP_SYSTEM_CORE_LABELS) {
            CORE_RTL_OFFSETS.add(entry[0]);
        }
    }

    // ── Constants for address mapping ──
    private static final long EXE_IMAGE_BASE = 0x10000;
    private static final long OVR_IMAGE_BASE = 0x80000;
    private static final int GHIDRA_SEG_REBASE = 0x1000;

    // ── Label tracking ──
    // Maps function Ghidra address string → [short_name, description]
    private Map<String, String[]> functionLabels = new HashMap<>();
    // Maps FLIRT mangled name → [short_name, description]
    private Map<String, String[]> flirtLabels = new HashMap<>();

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outPath = (args != null && args.length > 0)
            ? args[0]
            : System.getProperty("user.dir") + "/decompiled.c";

        File outFile = new File(outPath);
        outFile.getParentFile().mkdirs();

        // ═══════════════════════════════════════════════════════════════════
        // Phase 1: Find and define Pascal strings
        // ═══════════════════════════════════════════════════════════════════
        List<FoundString> pascalStrings = findPascalStrings(null, 4, 1, false);
        int stringsCreated = 0;
        for (FoundString fs : pascalStrings) {
            Address addr = fs.getAddress();
            if (getDataAt(addr) != null) continue;
            if (getInstructionAt(addr) != null) continue;
            try {
                createData(addr, new PascalStringDataType());
                stringsCreated++;
            } catch (Exception e) {
                // Data conflict — skip
            }
        }
        println("Phase 1: Defined " + stringsCreated + " Pascal string data types (from "
            + pascalStrings.size() + " candidates)");

        // ═══════════════════════════════════════════════════════════════════
        // Phase 2: Build string database
        // ═══════════════════════════════════════════════════════════════════
        for (FoundString fs : pascalStrings) {
            String text = fs.getString(currentProgram.getMemory());
            if (text == null || !isQualityString(text)) continue;
            long linearAddr = fs.getAddress().getOffset();
            stringDb.put(linearAddr, renderString(text));
            stringAddrDb.put(linearAddr, fs.getAddress().toString());
        }

        // Phase 2b: Custom scan for Pascal strings in CODE segments
        // Ghidra's findPascalStrings() misses strings embedded in code regions —
        // Borland Pascal packs const strings at the start of code segments
        // before the first instruction, and findPascalStrings only scans
        // defined data areas.
        int customFound = scanCodeSegmentStrings();

        println("Phase 2: Built string database with " + stringDb.size()
            + " entries (" + customFound + " from code segment scan)");

        // ═══════════════════════════════════════════════════════════════════
        // Phase 2.5: Register BP7 standard types
        // ═══════════════════════════════════════════════════════════════════
        registerBP7Types();
        println("Phase 2.5: Registered " + bp7Types.size() + " BP7 data types");

        // ═══════════════════════════════════════════════════════════════════
        // Phase 3: Identify and label functions
        // ═══════════════════════════════════════════════════════════════════
        buildLabelTable();
        buildFlirtLabels();
        println("Phase 3: Identified " + functionLabels.size() + " offset/pattern labels, "
            + flirtLabels.size() + " FLIRT labels");

        // ═══════════════════════════════════════════════════════════════════
        // Phase 4: Decompile all functions with annotations
        // ═══════════════════════════════════════════════════════════════════
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        // First pass: decompile to detect patterns and collect raw output
        FunctionManager fm = currentProgram.getFunctionManager();
        FunctionIterator it = fm.getFunctions(true);
        int count = 0;

        // Store per-function: decompiled text
        List<String[]> functionOutputs = new ArrayList<>();  // [funcName, address, decompiledC]

        while (it.hasNext()) {
            Function func = it.next();
            DecompileResults res = decomp.decompileFunction(func, 60, monitor);
            String funcName = func.getName();
            String funcAddr = func.getEntryPoint().toString();

            if (res.decompileCompleted()) {
                String cCode = res.getDecompiledFunction().getC();
                functionOutputs.add(new String[]{funcName, funcAddr, cCode});
            } else {
                functionOutputs.add(new String[]{funcName, funcAddr, null});
            }
            count++;
        }
        decomp.dispose();
        println("Phase 4: Decompiled " + count + " functions");

        // Identify patterns from decompiled code bodies
        identifyByPatterns(functionOutputs);

        // ═══════════════════════════════════════════════════════════════════
        // Phase 5: Apply renames and write output
        // ═══════════════════════════════════════════════════════════════════

        // Build combined rename table with dedup (skip names used by >1 function)
        Map<String, String> renames = new HashMap<>();  // oldName → shortName
        Map<String, String> descriptions = new HashMap<>(); // oldName → description
        Map<String, Integer> nameCount = new HashMap<>();

        // Count short name usage (for dedup)
        for (Map.Entry<String, String[]> e : functionLabels.entrySet()) {
            String shortName = e.getValue()[0];
            nameCount.put(shortName, nameCount.getOrDefault(shortName, 0) + 1);
        }
        for (Map.Entry<String, String[]> e : flirtLabels.entrySet()) {
            String shortName = e.getValue()[0];
            nameCount.put(shortName, nameCount.getOrDefault(shortName, 0) + 1);
        }

        // Build rename + description maps (only unique names)
        for (Map.Entry<String, String[]> e : functionLabels.entrySet()) {
            String shortName = e.getValue()[0];
            String desc = e.getValue()[1];
            if (nameCount.getOrDefault(shortName, 0) == 1) {
                renames.put(e.getKey(), shortName);
            }
            descriptions.put(e.getKey(), desc);
        }
        for (Map.Entry<String, String[]> e : flirtLabels.entrySet()) {
            String shortName = e.getValue()[0];
            String desc = e.getValue()[1];
            if (nameCount.getOrDefault(shortName, 0) == 1) {
                renames.put(e.getKey(), shortName);
            }
            descriptions.put(e.getKey(), desc);
        }

        // Build output with annotations, labels, and renames
        StringBuilder sb = new StringBuilder();
        List<String[]> libraryFunctions = new ArrayList<>();  // [name, addr]

        for (String[] funcData : functionOutputs) {
            String funcName = funcData[0];
            String funcAddr = funcData[1];
            String cCode = funcData[2];

            // Determine the final display name (after renames)
            String displayName = renames.getOrDefault(funcName, funcName);

            sb.append("\n// ==========================================\n");
            sb.append("// Function: ").append(funcName)
              .append(" @ ").append(funcAddr).append("\n");
            sb.append("// ==========================================\n");

            if (isLibraryFunction(displayName)) {
                // Library function: emit marker only, no body
                sb.append("// [LIBRARY]\n\n");
                libraryFunctions.add(new String[]{displayName, funcAddr});
            } else if (cCode != null) {
                sb.append("\n");
                // Annotate each line with string references and function labels
                String[] lines = cCode.split("\n", -1);
                for (String line : lines) {
                    String annotated = annotateLine(line, descriptions);
                    sb.append(annotated).append("\n");
                }
            }
        }

        // Apply renames throughout the output
        String output = sb.toString();
        for (Map.Entry<String, String> e : renames.entrySet()) {
            output = output.replace(e.getKey(), e.getValue());
        }

        // Clean up Ghidra type artifacts — replace undefined types with
        // standard BP7 type names and strip calling convention noise
        output = output.replaceAll("\\bundefined1\\b", "byte");
        output = output.replaceAll("\\bundefined2\\b", "word");
        output = output.replaceAll("\\bundefined4\\b", "dword");
        output = output.replaceAll("\\bundefined8\\b", "qword");
        output = output.replace("__cdecl16near ", "");
        output = output.replace("__cdecl16far ", "");
        output = output.replace("__stdcall16far ", "");

        // Clean up CONCAT11(extraout_AH..., value) → value
        // In BP7, the AH portion is irrelevant; only the lower byte matters
        output = cleanupConcat11(output);

        // Clean up unused variable declarations (unaff_DS, extraout_AH)
        output = cleanupUnusedDeclarations(output);

        // Append library function summary section
        if (!libraryFunctions.isEmpty()) {
            StringBuilder libSummary = new StringBuilder();
            libSummary.append("\n// === Library Functions ===\n");
            libSummary.append("// ").append(libraryFunctions.size())
                      .append(" library functions identified (bodies omitted)\n");
            libSummary.append("//\n");
            for (String[] lib : libraryFunctions) {
                libSummary.append("//   ").append(lib[0]).append(" @ ").append(lib[1]).append("\n");
            }
            libSummary.append("// ===========================\n");
            output = output + libSummary.toString();
        }

        PrintWriter pw = new PrintWriter(new FileWriter(outFile));
        pw.print(output);
        pw.close();

        println("Phase 5: Written " + outFile.getAbsolutePath());

        // ═══════════════════════════════════════════════════════════════════
        // Phase 6: Write strings.json from stringDb
        // ═══════════════════════════════════════════════════════════════════
        File stringsFile = new File(outFile.getParentFile(), "strings.json");
        PrintWriter spw = new PrintWriter(new FileWriter(stringsFile));
        spw.println("[");
        boolean first = true;
        int keptCount = 0;

        // Sort by offset for stable output
        List<Long> sortedOffsets = new ArrayList<>(stringDb.keySet());
        Collections.sort(sortedOffsets);

        for (long offset : sortedOffsets) {
            String text = stringDb.get(offset);
            String addrStr = stringAddrDb.getOrDefault(offset, String.format("%04x:%04x", offset >> 4, offset & 0xF));
            String escaped = escapeJson(text);
            if (!first) spw.println(",");
            spw.print("  {\"address\": \"" + addrStr + "\", \"offset\": " + offset
                + ", \"string\": \"" + escaped + "\"}");
            first = false;
            keptCount++;
        }
        spw.println("\n]");
        spw.close();
        println("Phase 6: Wrote " + keptCount + " strings -> " + stringsFile.getAbsolutePath());
    }

    // ═══════════════════════════════════════════════════════════════════════
    // BP7 Type Registration
    // ═══════════════════════════════════════════════════════════════════════

    private void registerBP7Types() {
        DataTypeManager dtm = currentProgram.getDataTypeManager();
        CategoryPath bp7 = new CategoryPath("/BP7");

        DataType byteT = ByteDataType.dataType;
        DataType wordT = WordDataType.dataType;
        DataType charT = CharDataType.dataType;
        DataType sdwordT = SignedDWordDataType.dataType;
        // Far pointer (seg:off = 4 bytes) for 16-bit real mode
        DataType farPtrT = new PointerDataType(null, 4);

        // TextRec (256 bytes) — text file control block
        StructureDataType textRec = new StructureDataType(bp7, "TextRec", 0);
        textRec.add(wordT, "Handle", "File handle");
        textRec.add(wordT, "Mode", "File mode (fmClosed/fmInput/fmOutput/fmInOut)");
        textRec.add(wordT, "BufSize", "Buffer size");
        textRec.add(wordT, "Private", "Reserved");
        textRec.add(wordT, "BufPos", "Current buffer position");
        textRec.add(wordT, "BufEnd", "End of valid buffer data");
        textRec.add(farPtrT, "BufPtr", "Pointer to buffer");
        textRec.add(farPtrT, "OpenFunc", "Open function pointer");
        textRec.add(farPtrT, "InOutFunc", "I/O function pointer");
        textRec.add(farPtrT, "FlushFunc", "Flush function pointer");
        textRec.add(farPtrT, "CloseFunc", "Close function pointer");
        textRec.add(new ArrayDataType(byteT, 16, 1), "UserData", "User data area");
        textRec.add(new ArrayDataType(charT, 80, 1), "Name", "File name");
        textRec.add(new ArrayDataType(charT, 128, 1), "Buffer", "I/O buffer");
        bp7Types.put("TextRec", dtm.addDataType(textRec, DataTypeConflictHandler.REPLACE_HANDLER));

        // FileRec (128 bytes) — typed/untyped file control block
        StructureDataType fileRec = new StructureDataType(bp7, "FileRec", 0);
        fileRec.add(wordT, "Handle", "File handle");
        fileRec.add(wordT, "Mode", "File mode");
        fileRec.add(wordT, "RecSize", "Record size");
        fileRec.add(new ArrayDataType(byteT, 26, 1), "Private", "Reserved");
        fileRec.add(new ArrayDataType(byteT, 16, 1), "UserData", "User data area");
        fileRec.add(new ArrayDataType(charT, 80, 1), "Name", "File name");
        bp7Types.put("FileRec", dtm.addDataType(fileRec, DataTypeConflictHandler.REPLACE_HANDLER));

        // SearchRec (43 bytes) — DOS FindFirst/FindNext result
        StructureDataType searchRec = new StructureDataType(bp7, "SearchRec", 0);
        searchRec.add(new ArrayDataType(byteT, 21, 1), "Fill", "Reserved (DOS DTA)");
        searchRec.add(byteT, "Attr", "File attributes");
        searchRec.add(sdwordT, "Time", "Time stamp (packed)");
        searchRec.add(sdwordT, "Size", "File size");
        searchRec.add(new ArrayDataType(charT, 13, 1), "Name", "File name (String[12])");
        bp7Types.put("SearchRec", dtm.addDataType(searchRec, DataTypeConflictHandler.REPLACE_HANDLER));

        // DateTime (12 bytes) — packed date/time components
        StructureDataType dateTime = new StructureDataType(bp7, "DateTime", 0);
        dateTime.add(wordT, "Year", null);
        dateTime.add(wordT, "Month", null);
        dateTime.add(wordT, "Day", null);
        dateTime.add(wordT, "Hour", null);
        dateTime.add(wordT, "Min", null);
        dateTime.add(wordT, "Sec", null);
        bp7Types.put("DateTime", dtm.addDataType(dateTime, DataTypeConflictHandler.REPLACE_HANDLER));

        // Registers (20 bytes) — CPU registers for Intr()/MsDos()
        StructureDataType regs = new StructureDataType(bp7, "Registers", 0);
        regs.add(wordT, "AX", null);
        regs.add(wordT, "BX", null);
        regs.add(wordT, "CX", null);
        regs.add(wordT, "DX", null);
        regs.add(wordT, "BP_reg", "BP register");
        regs.add(wordT, "SI", null);
        regs.add(wordT, "DI", null);
        regs.add(wordT, "DS", null);
        regs.add(wordT, "ES", null);
        regs.add(wordT, "Flags", null);
        bp7Types.put("Registers", dtm.addDataType(regs, DataTypeConflictHandler.REPLACE_HANDLER));

        // ShortString (256 bytes) — Pascal string[255]
        StructureDataType shortStr = new StructureDataType(bp7, "ShortString", 0);
        shortStr.add(byteT, "Length", "String length (0..255)");
        shortStr.add(new ArrayDataType(charT, 255, 1), "Data", "String characters");
        bp7Types.put("ShortString", dtm.addDataType(shortStr, DataTypeConflictHandler.REPLACE_HANDLER));

        // FileMode enum
        EnumDataType fileMode = new EnumDataType(bp7, "FileMode", 2);
        fileMode.add("fmClosed", 0xD7B0);
        fileMode.add("fmInput", 0xD7B1);
        fileMode.add("fmOutput", 0xD7B2);
        fileMode.add("fmInOut", 0xD7B3);
        bp7Types.put("FileMode", dtm.addDataType(fileMode, DataTypeConflictHandler.REPLACE_HANDLER));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Label Table Builder
    // ═══════════════════════════════════════════════════════════════════════

    private void buildLabelTable() {
        // Collect all functions grouped by segment
        FunctionManager fm = currentProgram.getFunctionManager();
        FunctionIterator it = fm.getFunctions(true);
        Map<String, Set<String>> segFuncs = new HashMap<>();
        Map<String, String> funcNamesBySegOff = new HashMap<>();

        while (it.hasNext()) {
            Function func = it.next();
            String addr = func.getEntryPoint().toString();
            // Address format: "seg:off" (e.g., "1005:02cd")
            String[] parts = addr.split(":");
            if (parts.length == 2) {
                String seg = parts[0];
                String off = parts[1];
                segFuncs.computeIfAbsent(seg, k -> new HashSet<>()).add(off);
                funcNamesBySegOff.put(addr, func.getName());
            }
        }

        // Identify System RTL segment
        String systemSeg = null;
        int bestCoreCount = 0;
        for (Map.Entry<String, Set<String>> e : segFuncs.entrySet()) {
            Set<String> offsets = e.getValue();
            // Strong markers
            if (offsets.contains("3fca") || offsets.contains("3f65") || offsets.contains("04f4")) {
                systemSeg = e.getKey();
                break;
            }
            // Count core RTL offset matches
            int coreCount = 0;
            for (String off : offsets) {
                if (CORE_RTL_OFFSETS.contains(off)) coreCount++;
            }
            if (coreCount > bestCoreCount) {
                bestCoreCount = coreCount;
                systemSeg = e.getKey();
            }
        }

        // Apply System RTL labels
        if (systemSeg != null) {
            Set<String> offsets = segFuncs.get(systemSeg);
            applyLabelSet(systemSeg, offsets, BP_SYSTEM_LABELS, funcNamesBySegOff);
            applyLabelSet(systemSeg, offsets, BP_SYSTEM_CORE_LABELS, funcNamesBySegOff);
        }

        // Identify library segments
        for (Map.Entry<String, Set<String>> e : segFuncs.entrySet()) {
            String seg = e.getKey();
            if (seg.equals(systemSeg)) continue;
            Set<String> offsets = e.getValue();

            if (offsets.contains("02a8") && offsets.contains("054e")) {
                applyLabelSet(seg, offsets, RHP_DISPLAY_LABELS, funcNamesBySegOff);
            } else if (offsets.contains("1168")) {
                applyLabelSet(seg, offsets, RHP_INPUT_LABELS, funcNamesBySegOff);
            } else if (offsets.contains("0002") && offsets.contains("011d")) {
                applyLabelSet(seg, offsets, CONV_LABELS, funcNamesBySegOff);
            } else if (offsets.contains("02fa") && !offsets.contains("02a8") && !offsets.contains("054e")) {
                applyLabelSet(seg, offsets, TIMER_LABELS, funcNamesBySegOff);
            } else if (offsets.contains("01ce") && offsets.contains("02b6")) {
                applyLabelSet(seg, offsets, RECORD_LABELS, funcNamesBySegOff);
            } else if (offsets.contains("13b6") && offsets.contains("130c") && offsets.contains("11b7") && offsets.contains("281e")) {
                applyLabelSet(seg, offsets, DDPLUS_LABELS, funcNamesBySegOff);
            } else if (offsets.contains("0000") && offsets.contains("004a") && offsets.contains("00bb") && offsets.contains("0143")) {
                applyLabelSet(seg, offsets, DDPLUS_IO_LABELS, funcNamesBySegOff);
            } else if (offsets.contains("024b") && offsets.contains("0257")) {
                applyLabelSet(seg, offsets, CRT_UNIT_LABELS, funcNamesBySegOff);
            }
        }
    }

    private void applyLabelSet(String seg, Set<String> offsets, String[][] labelSet,
                               Map<String, String> funcNamesBySegOff) {
        for (String[] entry : labelSet) {
            String off = entry[0];
            if (offsets.contains(off)) {
                String addr = seg + ":" + off;
                String funcName = funcNamesBySegOff.get(addr);
                if (funcName != null) {
                    functionLabels.put(funcName, new String[]{entry[1], entry[2]});
                }
            }
        }
    }

    private void buildFlirtLabels() {
        // Find FLIRT-identified functions (named by ApplySigHeadless.py)
        FunctionManager fm = currentProgram.getFunctionManager();
        FunctionIterator it = fm.getFunctions(true);

        while (it.hasNext()) {
            Function func = it.next();
            String name = func.getName();
            // Check against known FLIRT names
            String[] desc = FLIRT_DESCRIPTIONS.get(name);
            if (desc != null) {
                flirtLabels.put(name, desc);
                continue;
            }
            desc = FLIRT_PLAIN_DESCRIPTIONS.get(name);
            if (desc != null) {
                flirtLabels.put(name, desc);
                continue;
            }
            // Generic decode for single-underscore _Name_q... patterns
            if (name.startsWith("_") && !name.startsWith("__") && name.contains("_q")) {
                String[] parts = name.split("_q", 2);
                String funcPart = parts[0].substring(1);  // strip leading _
                String params = parts.length > 1 ? parts[1] : "";
                String shortName = "bp_" + funcPart.toLowerCase();
                String description = funcPart + "(" + params + ") — FLIRT-identified";
                flirtLabels.put(name, new String[]{shortName, description});
                continue;
            }
            // @Name$q... patterns (alternate Borland mangled format)
            if (name.startsWith("@") && name.contains("$")) {
                // Convert @Name$qParams → _Name_qParams and look up
                String converted = name.replace('@', '_').replace('$', '_');
                desc = FLIRT_DESCRIPTIONS.get(converted);
                if (desc != null) {
                    flirtLabels.put(name, desc);
                    continue;
                }
                // Generic decode: extract Name from @Name$...
                int dollarIdx = name.indexOf('$');
                String funcPart = name.substring(1, dollarIdx);
                String params = dollarIdx + 1 < name.length() ? name.substring(dollarIdx + 1) : "";
                String shortName = "bp_" + funcPart.toLowerCase();
                String description = funcPart + "(" + params + ") — FLIRT-identified";
                flirtLabels.put(name, new String[]{shortName, description});
                continue;
            }
            // Double-underscore system functions
            if (name.startsWith("__") && name.length() > 2) {
                String baseName = name.substring(2);
                flirtLabels.put(name, new String[]{"bp_" + baseName.toLowerCase(),
                    baseName + " — system runtime function"});
            }
        }
    }

    // ── Pattern-based identification ──

    private void identifyByPatterns(List<String[]> functionOutputs) {
        for (String[] funcData : functionOutputs) {
            String funcName = funcData[0];
            String cCode = funcData[2];
            if (cCode == null) continue;
            if (!funcName.startsWith("FUN_")) continue;
            if (functionLabels.containsKey(funcName)) continue;

            String[] result = identifyByPattern(funcName, cCode);
            if (result != null) {
                functionLabels.put(funcName, result);
            }
        }
    }

    private String[] identifyByPattern(String funcName, String body) {
        int lineCount = body.split("\n", -1).length;

        // Stack check: checks stack pointer against a limit
        if (body.contains("stack0x0000") && body.contains("0x200") &&
            body.contains("FUN_") && lineCount < 15) {
            return new String[]{"bp_stack_check", "Stack overflow check"};
        }

        // Write(Text, String, Word): calls __WriteBlanks and __WriteBuffer
        if (body.contains("__WriteBlanks") && body.contains("__WriteBuffer") && lineCount < 25) {
            return new String[]{"bp_write_str", "Write(Text, String, Word) — write string"};
        }

        // Write(Text, String, Word) structural pattern
        if (body.contains("bVar1 = *param_2") &&
            body.contains("bVar1 < param_1") &&
            body.contains("bVar1 != 0") && lineCount < 25) {
            return new String[]{"bp_write_str", "Write(Text, String, Word) — write string"};
        }

        // BIOS INT 10h wrapper
        if (body.contains("swi(0x10)") && lineCount < 20) {
            int bracePos = body.indexOf('{');
            String codeBody = bracePos >= 0 ? body.substring(bracePos) : body;
            if (!codeBody.contains("FUN_")) {
                return new String[]{"bp_bios_int10", "BIOS INT 10h video interrupt wrapper"};
            }
            return new String[]{"bp_bios_int10", "BIOS INT 10h video interrupt wrapper"};
        }

        // WriteLn wrapper
        if (body.contains("_Write_") && lineCount < 8) {
            return new String[]{"bp_writeln_wrapper", "WriteLn wrapper"};
        }

        // INT 21h wrappers
        if (body.contains("swi(0x21)") && lineCount < 15 && !body.contains("for")) {
            int bracePos = body.indexOf('{');
            String codeBody = bracePos >= 0 ? body.substring(bracePos) : body;
            if (!codeBody.contains("FUN_")) {
                return new String[]{"bp_dos_int21", "DOS INT 21h wrapper"};
            }
        }

        // Write char via __InOutProc + conditional WriteLn flush
        if (body.contains("__InOutProc") && body.contains("0x1a") && lineCount < 25) {
            return new String[]{"bp_write_inoutproc", "Write char via __InOutProc + conditional flush"};
        }

        // Write(Text, Integer)
        if (body.contains("__Str2Int") && body.contains("in_CX") && lineCount < 25) {
            return new String[]{"bp_write_int", "Write(Text, Integer) — write integer"};
        }

        // WriteLn / write char + flush
        if (body.contains("in_ZF") && body.contains("0x1a") &&
            body.contains("FUN_") && lineCount < 25) {
            return new String[]{"bp_write_char_flush", "Write char + conditional WriteLn flush"};
        }

        // Conditional flush only
        int bracePos = body.indexOf('{');
        String codeBody = bracePos >= 0 ? body.substring(bracePos) : body;
        if (body.contains("0x1a") &&
            countOccurrences(codeBody, "FUN_") == 1 &&
            lineCount < 22 && !body.contains("in_ZF")) {
            return new String[]{"bp_flush_text_cond", "Conditional text buffer flush"};
        }

        // Bounded string copy
        if (body.contains("param_1 < *param_3") &&
            body.contains("*param_2 = bVar1") && lineCount < 40) {
            return new String[]{"bp_str_copy_bounded", "Bounded string copy: min(param_1, *param_3) bytes"};
        }

        // Intr(IntNo, Regs)
        if (body.contains("swi(0)") && body.contains("uRam")) {
            return new String[]{"dos_intr", "Intr(IntNo, Regs) — call software interrupt"};
        }

        return null;
    }

    // ═══════════════════════════════════════════════════════════════════════
    // String Annotation (replaces annotate_strings.py)
    // ═══════════════════════════════════════════════════════════════════════

    // ═══════════════════════════════════════════════════════════════════════
    // Library Function Detection
    // ═══════════════════════════════════════════════════════════════════════

    private static final Pattern FLIRT_AT_PATTERN = Pattern.compile("^@\\w+\\$");
    private static final Pattern FLIRT_DUNDER_PATTERN = Pattern.compile("^__[A-Z]");

    /**
     * Check if a function name identifies a library function.
     * Library functions have their bodies eliminated from the output.
     */
    private static final String[] LIBRARY_PREFIXES = {
        "bp_", "ddp_", "crt_", "dos_", "comio_", "ovr_"
    };

    private boolean isLibraryFunction(String name) {
        for (String prefix : LIBRARY_PREFIXES) {
            if (name.startsWith(prefix)) return true;
        }
        if (FLIRT_AT_PATTERN.matcher(name).find()) return true;
        if (FLIRT_DUNDER_PATTERN.matcher(name).find()) return true;
        return false;
    }

    // ═══════════════════════════════════════════════════════════════════════
    // CONCAT11 Cleanup
    // ═══════════════════════════════════════════════════════════════════════

    private static final Pattern CONCAT11_EXTRAOUT = Pattern.compile(
        "CONCAT11\\(extraout_AH\\w*,");

    /**
     * Replace CONCAT11(extraout_AH..., value) → value.
     * In BP7, the AH portion of CONCAT11 is irrelevant — only the lower
     * byte (AL) matters for character/byte operations.
     * Complex CONCAT11 patterns (arithmetic) are left untouched.
     */
    private String cleanupConcat11(String text) {
        StringBuilder result = new StringBuilder();
        int i = 0;
        java.util.regex.Matcher m = CONCAT11_EXTRAOUT.matcher(text);

        while (m.find(i)) {
            result.append(text, i, m.start());

            // Find matching closing paren with balanced tracking
            int parenStart = m.start() + "CONCAT11".length();
            int depth = 0;
            int j = parenStart;
            while (j < text.length()) {
                char c = text.charAt(j);
                if (c == '(') depth++;
                else if (c == ')') {
                    depth--;
                    if (depth == 0) break;
                }
                j++;
            }

            if (depth != 0) {
                // Unbalanced — leave unchanged
                result.append(text, m.start(), m.end());
                i = m.end();
                continue;
            }

            // Extract inner content: everything between CONCAT11( and )
            String inner = text.substring(parenStart + 1, j);

            // Find first top-level comma to separate first arg from value
            int commaPos = -1;
            int parens = 0;
            for (int k = 0; k < inner.length(); k++) {
                char c = inner.charAt(k);
                if (c == '(') parens++;
                else if (c == ')') parens--;
                else if (c == ',' && parens == 0) {
                    commaPos = k;
                    break;
                }
            }

            if (commaPos >= 0) {
                String value = inner.substring(commaPos + 1).trim();
                result.append(value);
            } else {
                // No comma found — leave unchanged
                result.append(text, m.start(), j + 1);
            }

            i = j + 1;
        }

        result.append(text, i, text.length());
        return result.toString();
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Unused Variable Declaration Cleanup
    // ═══════════════════════════════════════════════════════════════════════

    private static final Pattern FUNC_BLOCK_PATTERN = Pattern.compile(
        "\n// ={10,}\n// Function: \\S+ @ [0-9a-f]+:[0-9a-f]+\n// ={10,}\n");
    private static final Pattern UNAFF_DS_DECL = Pattern.compile(
        "^\\s+\\w+\\s+(unaff_DS)\\s*;$", Pattern.MULTILINE);
    private static final Pattern EXTRAOUT_AH_DECL = Pattern.compile(
        "^\\s+\\w+\\s+(extraout_AH\\w*)\\s*;$", Pattern.MULTILINE);

    /**
     * Remove unused variable declarations for unaff_DS and extraout_AH.
     * After CONCAT11 cleanup, some extraout_AH variables become unused.
     * Also removes unaff_DS declarations when the variable isn't referenced.
     */
    private String cleanupUnusedDeclarations(String output) {
        // Split into function blocks
        String[] parts = FUNC_BLOCK_PATTERN.split(output);
        String[] headers = findAllMatches(FUNC_BLOCK_PATTERN, output);

        StringBuilder result = new StringBuilder();
        result.append(parts[0]);

        for (int idx = 0; idx < headers.length; idx++) {
            result.append(headers[idx]);
            if (idx + 1 < parts.length) {
                String block = parts[idx + 1];
                block = removeUnusedDecl(block, UNAFF_DS_DECL);
                block = removeUnusedDecl(block, EXTRAOUT_AH_DECL);
                result.append(block);
            }
        }

        return result.toString();
    }

    /** Remove declarations matching pattern if the variable is unused in the block. */
    private String removeUnusedDecl(String block, Pattern declPattern) {
        java.util.regex.Matcher m = declPattern.matcher(block);
        List<int[]> toRemove = new ArrayList<>();

        while (m.find()) {
            String varName = m.group(1);
            // Check if varName appears elsewhere in the block
            String before = block.substring(0, m.start());
            String after = block.substring(m.end());
            Pattern varRef = Pattern.compile("\\b" + Pattern.quote(varName) + "\\b");
            if (!varRef.matcher(before).find() && !varRef.matcher(after).find()) {
                toRemove.add(new int[]{m.start(), m.end()});
            }
        }

        if (toRemove.isEmpty()) return block;

        // Remove matched declarations in reverse order
        StringBuilder sb = new StringBuilder(block);
        for (int i = toRemove.size() - 1; i >= 0; i--) {
            int start = toRemove.get(i)[0];
            int end = toRemove.get(i)[1];
            // Also remove the trailing newline if present
            if (end < sb.length() && sb.charAt(end) == '\n') end++;
            sb.delete(start, end);
        }
        return sb.toString();
    }

    /** Find all matches of a pattern in text, returning the matched strings. */
    private String[] findAllMatches(Pattern pattern, String text) {
        List<String> matches = new ArrayList<>();
        java.util.regex.Matcher m = pattern.matcher(text);
        while (m.find()) {
            matches.add(m.group());
        }
        return matches.toArray(new String[0]);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // String Annotation
    // ═══════════════════════════════════════════════════════════════════════

    private static final Pattern HEX_PATTERN = Pattern.compile("0[xX][0-9a-fA-F]+");
    private static final Pattern PAIR_PATTERN = Pattern.compile(
        "((?:0[xX][0-9a-fA-F]+|-?\\d+))\\s*,\\s*((?:0[xX][0-9a-fA-F]+|-?\\d+))");
    private static final Pattern PTR_ARITH_PATTERN = Pattern.compile("[+\\-]\\s*-?\\s*$");

    private String annotateLine(String line, Map<String, String> descriptions) {
        List<String> found = new ArrayList<>();
        Set<Long> seenAddrs = new HashSet<>();

        // Pass 1: paired constants (segment, offset)
        Matcher pairMatcher = PAIR_PATTERN.matcher(line);
        while (pairMatcher.find()) {
            Long a = parseConstant(pairMatcher.group(1));
            Long b = parseConstant(pairMatcher.group(2));
            if (a == null || b == null) continue;

            List<Long> candidates = new ArrayList<>();
            boolean bIsSeg = isSegmentLike(b) && a >= 0 && a <= 0xFFFF;
            boolean aIsSeg = isSegmentLike(a) && b >= 0 && b <= 0xFFFF;

            if (bIsSeg && aIsSeg) {
                if (b >= a) {
                    long base = b >= 0x8000 ? OVR_IMAGE_BASE : EXE_IMAGE_BASE;
                    candidates.add(a + base);
                    if (b < 0x8000) candidates.add(((b - GHIDRA_SEG_REBASE) * 16 + a) + EXE_IMAGE_BASE);
                    base = a >= 0x8000 ? OVR_IMAGE_BASE : EXE_IMAGE_BASE;
                    candidates.add(b + base);
                    if (a < 0x8000) candidates.add(((a - GHIDRA_SEG_REBASE) * 16 + b) + EXE_IMAGE_BASE);
                } else {
                    long base = a >= 0x8000 ? OVR_IMAGE_BASE : EXE_IMAGE_BASE;
                    candidates.add(b + base);
                    if (a < 0x8000) candidates.add(((a - GHIDRA_SEG_REBASE) * 16 + b) + EXE_IMAGE_BASE);
                    base = b >= 0x8000 ? OVR_IMAGE_BASE : EXE_IMAGE_BASE;
                    candidates.add(a + base);
                    if (b < 0x8000) candidates.add(((b - GHIDRA_SEG_REBASE) * 16 + a) + EXE_IMAGE_BASE);
                }
            } else if (bIsSeg) {
                long base = b >= 0x8000 ? OVR_IMAGE_BASE : EXE_IMAGE_BASE;
                candidates.add(a + base);
                if (b < 0x8000) candidates.add(((b - GHIDRA_SEG_REBASE) * 16 + a) + EXE_IMAGE_BASE);
            } else if (aIsSeg) {
                long base = a >= 0x8000 ? OVR_IMAGE_BASE : EXE_IMAGE_BASE;
                candidates.add(b + base);
                if (a < 0x8000) candidates.add(((a - GHIDRA_SEG_REBASE) * 16 + b) + EXE_IMAGE_BASE);
            }

            for (Long addr : candidates) {
                if (seenAddrs.contains(addr)) continue;
                String s = stringDb.get(addr);
                if (s != null) {
                    seenAddrs.add(addr);
                    String display = s.length() > 120 ? s.substring(0, 120) + "…" : s;
                    display = display.replace("*/", "*\\/");
                    found.add("/* \"" + display + "\" */");
                    break;
                }
            }
        }

        // Pass 2: single-constant fallback
        if (found.isEmpty() && !line.contains("/* WARNING")) {
            Matcher hexMatcher = HEX_PATTERN.matcher(line);
            while (hexMatcher.find()) {
                Long v = parseConstant(hexMatcher.group());
                if (v == null || v > 0xFFFF || v < 0x11) continue;

                // Skip pointer arithmetic contexts
                String prefix = line.substring(Math.max(0, hexMatcher.start() - 4), hexMatcher.start());
                if (PTR_ARITH_PATTERN.matcher(prefix).find()) continue;

                for (long base : new long[]{EXE_IMAGE_BASE, OVR_IMAGE_BASE}) {
                    long addr = v + base;
                    if (seenAddrs.contains(addr)) continue;
                    String s = stringDb.get(addr);
                    if (s != null) {
                        seenAddrs.add(addr);
                        String display = s.length() > 120 ? s.substring(0, 120) + "…" : s;
                        display = display.replace("*/", "*\\/");
                        found.add("/* \"" + display + "\" */");
                        break;
                    }
                }
            }
        }

        // Add function label annotations (inline comments for known function calls)
        // Pattern: funcName(  — find function calls by name
        for (Map.Entry<String, String> e : descriptions.entrySet()) {
            String funcName = e.getKey();
            if (line.contains(funcName + "(") || line.contains(funcName + " (")) {
                found.add("/* " + e.getValue() + " */");
            }
        }

        if (found.isEmpty()) return line;
        return line.replaceAll("\\s+$", "") + "  " + String.join("  ", found);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Utility methods
    // ═══════════════════════════════════════════════════════════════════════

    private boolean isSegmentLike(long v) {
        return (v >= 0x1000 && v <= 0x7FFF) || (v >= 0x8000 && v <= 0xA000);
    }

    private Long parseConstant(String s) {
        try {
            if (s.startsWith("0x") || s.startsWith("0X")) {
                return Long.parseLong(s.substring(2), 16);
            }
            return Long.parseLong(s);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private int countOccurrences(String text, String pattern) {
        int count = 0;
        int idx = 0;
        while ((idx = text.indexOf(pattern, idx)) >= 0) {
            count++;
            idx += pattern.length();
        }
        return count;
    }

    private String renderString(String text) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c >= 0x20 && c <= 0x7e) {
                sb.append(c);
            } else if (c == '\n') {
                sb.append("\\n");
            } else if (c == '\r') {
                sb.append("\\r");
            } else if (c == '\t') {
                sb.append("\\t");
            } else if (c < 0x20) {
                sb.append(String.format("\\x%02x", (int) c));
            } else {
                sb.append(c);  // high byte
            }
        }
        return sb.toString();
    }

    private boolean isQualityString(String text) {
        return isQualityString(text, 4);
    }

    private boolean isQualityString(String text, int minLen) {
        int len = text.length();
        if (len < minLen) return false;
        if (text.charAt(0) < 0x20 || text.charAt(0) > 0x7e) return false;
        for (int i = 1; i < Math.min(6, len); i++) {
            char c = text.charAt(i);
            if (c < 0x20 || c > 0x7e) return false;
        }
        for (int i = Math.max(0, len - 5); i < len; i++) {
            if (text.charAt(i) >= 0x80) return false;
        }
        int letterCount = 0;
        for (int i = 0; i < len; i++) {
            char c = text.charAt(i);
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
                || (c >= '0' && c <= '9')
                || " !\"'(),.:?".indexOf(c) >= 0) {
                letterCount++;
            }
        }
        return letterCount * 2 >= len;
    }

    private String escapeJson(String s) {
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    /**
     * Scan memory blocks for Pascal length-prefixed strings that Ghidra's
     * findPascalStrings() misses. Borland Pascal packs const strings
     * sequentially at the start of code segments: [len][chars][len][chars]...
     *
     * The scanner reads raw bytes, validates each candidate as printable
     * ASCII, and adds it to stringDb if it passes quality checks.
     *
     * Returns the number of new strings added.
     */
    private int scanCodeSegmentStrings() {
        ghidra.program.model.mem.Memory mem = currentProgram.getMemory();
        int found = 0;

        for (ghidra.program.model.mem.MemoryBlock block : mem.getBlocks()) {
            if (!block.isInitialized()) continue;

            Address start = block.getStart();
            long blockSize = block.getSize();

            // Scan from the start of each block for Pascal strings
            long offset = 0;
            int consecutiveMisses = 0;

            while (offset < blockSize && offset < 0x2000) {
                // Stop scanning if we hit too many non-string bytes
                // (we've left the const string area and entered code)
                if (consecutiveMisses > 16) break;

                try {
                    Address addr = start.add(offset);
                    int len = mem.getByte(addr) & 0xFF;

                    // Length byte must be 1-255
                    if (len == 0) {
                        offset++;
                        consecutiveMisses++;
                        continue;
                    }

                    // Don't read past the block or our scan window
                    if (offset + 1 + len > blockSize || offset + 1 + len > 0x2000) {
                        break;
                    }

                    // Read the string bytes
                    byte[] strBytes = new byte[len];
                    mem.getBytes(addr.add(1), strBytes);

                    // Validate: all bytes must be printable ASCII (0x20-0x7E)
                    boolean valid = true;
                    for (int i = 0; i < len; i++) {
                        int b = strBytes[i] & 0xFF;
                        if (b < 0x20 || b > 0x7E) {
                            valid = false;
                            break;
                        }
                    }

                    if (!valid || len < 2) {
                        offset++;
                        consecutiveMisses++;
                        continue;
                    }

                    String text = new String(strBytes, "US-ASCII");
                    long linearAddr = addr.getOffset();

                    // Only add if not already in the database (lower minLen for code-segment strings)
                    if (!stringDb.containsKey(linearAddr) && isQualityString(text, 2)) {
                        stringDb.put(linearAddr, renderString(text));
                        stringAddrDb.put(linearAddr, addr.toString());
                        found++;
                    }

                    // Skip past this string to the next potential string
                    offset += 1 + len;
                    consecutiveMisses = 0;

                } catch (MemoryAccessException e) {
                    offset++;
                    consecutiveMisses++;
                } catch (AddressOutOfBoundsException e) {
                    break;
                }
            }
        }

        return found;
    }
}
