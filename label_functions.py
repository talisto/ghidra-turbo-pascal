#!/usr/bin/env python3
"""
label_functions.py — Add human-readable labels to Borland Pascal functions
in decompiled output from Ghidra.

Applies known function identifications from:
  1. FLIRT signature matches (already applied by Ghidra)
  2. Empirically identified functions (from manual analysis of LORD IGMs)
  3. Common Borland Pascal 7 RTL patterns

Usage:
  python3 label_functions.py <decompiled.c> [-o outfile]

If -o is omitted, writes <decompiled.labeled.c> alongside the input file.
The script adds // comments after function calls with the identified purpose.
It also generates a summary of identified vs unidentified functions.
"""

import sys
import os
import re
from collections import defaultdict

# ── Known Function Labels ────────────────────────────────────────────────────
#
# These are identified by their segment:offset in Ghidra's address space.
# The segment value depends on the Ghidra load base (typically +0x1000).
# The offset within the segment is stable across loads of the same binary.
#
# Format: 'seg_off' -> (short_name, description)
#
# NOTE: These labels are specific to Borland Pascal 7 + RHP-based LORD IGMs.
# Different IGMs may use different segment values but the same offsets within
# each library unit.

# Borland Pascal 7 System RTL (typically the highest-addressed unit)
BP_SYSTEM_LABELS = {
    '0530': ('bp_unit_init',        'Unit initialization / stack check'),
    '04f4': ('bp_str_temp_free',    'Free temporary string (@LStrClr)'),
    '3275': ('bp_str_pos',          'Pos() — find substring position'),
    '3646': ('bp_str_compare',      'String comparison'),
    '36c9': ('bp_str_dispose',      'Dispose string memory'),
    '371e': ('bp_str_assign_var',   'Assign string from variable'),
    '38fd': ('bp_file_assign',      'Assign() — bind filename to file var'),
    '393d': ('bp_file_rewrite',     'Rewrite() — open file for writing'),
    '395e': ('bp_file_reset',       'Reset() — open file for reading'),
    '3a61': ('bp_file_close',       'Close() — close file'),
    '39db': ('bp_file_read',        'Read from file'),
    '3ae9': ('bp_file_write',       'Write to file'),
    '3c24': ('bp_blockread',        'BlockRead() — read binary block'),
    '3e22': ('bp_blockwrite',       'BlockWrite() — write binary block'),
    '3f4b': ('bp_str_assign',       'Assign string from constant'),
    '3f65': ('bp_str_copy',         'Copy string (bounded, like Copy())'),
    '3f89': ('bp_str_equal',        'String equality check'),
    '3fca': ('bp_str_concat',       'String concatenation (+)'),
    '3ff6': ('bp_str_concat_assign','Concat and assign'),
    '403c': ('bp_str_copy_far',     'Far string copy'),
    '4067': ('bp_char_to_str',      'Char-to-string conversion'),
    '40f3': ('bp_int_to_str',       'Integer-to-string (Str())'),
    '46d0': ('bp_random_seed',      'Random seed / RandSeed access'),
    '46e4': ('bp_random',           'Random(N) — generate random number'),
    '48da': ('bp_halt',             'Halt / RunError handler'),
    # Additional large-binary System unit functions (seen in DDTEST / full TP7 RTL).
    # These appear at higher offsets when more RTL features are linked in.
    '0549': ('bp_textrec_init',     'TextRec buffer init (Assign / open association)'),
    '05c7': ('bp_output_init',      'Unit output initializer (thin wrapper)'),
    '0621': ('bp_text_open_check',  'Text file mode check / open for I/O'),
    '0840': ('bp_writeln_impl',     'WriteLn implementation (large RTL variant)'),
    '0861': ('bp_flush_text_cond',  'Conditional text buffer flush (large RTL)'),
    '08de': ('bp_write_char_buf',   'Write character to TextRec buffer'),
    '0964': ('bp_write_str_body',   'Write(Text, String, Word) inner body (large RTL)'),
    '0e45': ('bp_str_append',       'String append / concatenation'),
    '0e71': ('bp_str_val_scan',     'String scanning for Val()'),
    '0eb7': ('bp_str_assign_cap',   'String assignment with length cap'),
    '0ee2': ('bp_mkstr1',           'Build 1-char Pascal string from Char'),
    '0f6e': ('bp_str_delete',       'Delete() — remove substring from string'),
    '1e6d': ('bp_val_parse',        'Val() — parse string to integer value'),
}

# Core System RTL functions present in ALL TP7 binaries (even small ones).
# These have stable offsets within the System unit regardless of program size.
BP_SYSTEM_CORE_LABELS = {
    '00b1': ('bp_module_init',      'Module initialization (sets unit flag)'),
    '010f': ('bp_exit_handler',     'Heap manager / exit handler'),
    '0116': ('bp_halt_handler',     'Halt handler with interrupt restore'),
    '01f0': ('bp_print_loop',      'Print character loop (null-terminated)'),
    '01fe': ('bp_print_decimal',   'Decimal digit printer'),
    '020a': ('bp_div_digit',       'Digit divider for decimal output'),
    '0218': ('bp_char_out_setup',  'Console character output setup'),
    '0232': ('bp_char_out',        'Single character output via INT 21h'),
    '0291': ('bp_iocheck',         'Check I/O result code (IOCheck)'),
    '02cd': ('bp_stack_check',     'Stack overflow check'),
    '02e6': ('bp_runtime_init',    'Runtime initialization'),
    '0364': ('bp_input_init',      'Input TextRec initialization'),
    '0369': ('bp_output_init',     'Output TextRec initialization'),
    '0371': ('bp_textrec_init',    'TextRec initialization helper'),
    '03be': ('bp_write_setup',     'Write buffer setup'),
    '03fa': ('bp_writeln_impl',    'WriteLn implementation'),
    '0627': ('bp_read_setup',      'Read buffer setup'),
    '0701': ('bp_write_str',       'Write(Text, String, Word) — write string'),
    '07bd': ('bp_longint_mul',     'Longint multiply (32-bit on 16-bit)'),
    '07d7': ('bp_str_assign_const','Assign string from constant'),
    '08ec': ('bp_str_copy_const',  'Copy string from constant source'),
}

# RHP Display Library (LORD's output system)
RHP_DISPLAY_LABELS = {
    '0002': ('rhp_lw',              'lw() — write inline text (no newline)'),
    '02a8': ('rhp_lln',             'lln() — write line with newline'),
    '054e': ('rhp_sln',             'sln() — write blank line'),
}

# RHP Input Library
RHP_INPUT_LABELS = {
    '0d37': ('rhp_display_char',    'Display character with typewriter delay'),
    '0de1': ('rhp_display_slow',    'Slow display variant'),
    '1168': ('rhp_getkey',          'getkey() — read single keypress'),
    '14e7': ('rhp_readline',        'Read line of text input'),
    '1cdb': ('rhp_check_carrier',   'Check carrier detect / online status'),
    '2516': ('rhp_clear_screen',    'Clear screen / reset display'),
    '0c54': ('rhp_cls',             'Clear screen (alternate)'),
}

# Conversion / Math Library
CONV_LABELS = {
    '0002': ('bp_int_to_str_2',     'IntToStr — integer to string'),
    '011d': ('bp_longint_to_str',   'LongintToStr — longint to string'),
    '04c7': ('bp_str_to_int',       'Val() — string to integer'),
    '0c6f': ('bp_val_longint',      'Val() — string to longint'),
    '0d7a': ('bp_str_pad',          'String pad/format (right-justify)'),
    '0df7': ('bp_str_pad_left',     'String pad left'),
}

# Timer / System Library
TIMER_LABELS = {
    '02fa': ('rhp_delay',           'delay() / mswait — millisecond pause'),
    '068c': ('rhp_timer_check',     'Timer check / timeout detection'),
}

# Record / File Library
RECORD_LABELS = {
    '00f5': ('bp_file_open',        'Open file'),
    '01ce': ('bp_record_read',      'Read record from file'),
    '02b6': ('bp_record_write',     'Write record to file'),
}

# DDPlus 7.1 Door Driver Toolkit (offset-based, segment varies per binary)
# Verified against DDTEST.EXE compiled from DDTEST.PAS with TP7.
# These offsets are stable within the DDPlus unit across compilations.
DDPLUS_LABELS = {
    '00bb': ('ddp_str_input',       'DDPlus string input/copy helper'),
    '0143': ('ddp_str_parse',       'DDPlus string parse/scan helper'),
    '0080': ('ddp_clear_region',    'DDPlus Clear_Region(x,r1,r2) — blank rows'),
    '06ad': ('ddp_time_left',       'DDPlus time_left — BBS minutes remaining'),
    '10bb': ('ddp_sendtext',        'DDPlus sendtext(s) — raw string to modem'),
    '1129': ('ddp_morecheck',       'DDPlus morecheck — pause-per-screenful'),
    '11b7': ('ddp_sclrscr',         'DDPlus sclrscr — clear screen (ANSI+local)'),
    '1209': ('ddp_sclreol',         'DDPlus sclreol — clear to end of line'),
    '12a4': ('ddp_swritec',         'DDPlus swritec(ch) — send single character'),
    '130c': ('ddp_swrite',          'DDPlus swrite(s) — send string, no newline'),
    '13b6': ('ddp_swriteln',        'DDPlus swriteln(s) — send string + CR/LF'),
    '14e0': ('ddp_swritexy',        'DDPlus swritexy(x,y,s) — position then write'),
    '1590': ('ddp_propeller',       'DDPlus Propeller(v) — spinning progress indicator'),
    '1d30': ('ddp_ansi_dispatch',   'DDPlus ANSI color dispatch (internal)'),
    '1d95': ('ddp_set_foreground',  'DDPlus set_foreground(color) — ANSI fg color'),
    '211f': ('ddp_set_background',  'DDPlus set_background(color) — ANSI bg color'),
    '21da': ('ddp_set_color',       'DDPlus set_color(fg,bg) — set ANSI colors'),
    '281e': ('ddp_sgoto_xy',        'DDPlus sgoto_xy(x,y) — ANSI cursor move'),
}

# DDPlus IO utility unit — helper segment paired with the DDPlus driver.
# Detected by the characteristic low-offset function cluster {0000, 004a, 00bb, 0143}.
DDPLUS_IO_LABELS = {
    '00bb': ('ddp_str_input',    'DDPlus string input/copy helper'),
    '0143': ('ddp_str_parse',    'DDPlus string parse/scan helper'),
}

# Borland Pascal CRT unit (cursor, color, keyboard)
# Detected by presence of WhereX (024b) and WhereY (0257) at stable offsets.
CRT_UNIT_LABELS = {
    '021f': ('crt_gotoxy_impl',   'GotoXY(X,Y) — cursor positioning with bounds check'),
    '024b': ('crt_wherex_impl',   'WhereX — current cursor column (window-relative)'),
    '0257': ('crt_wherey_impl',   'WhereY — current cursor row (window-relative)'),
    '0263': ('crt_textattr_set',  'TextColor/TextBackground — set color attribute byte'),
}

# ── FLIRT Name Decoder ─────────────────────────────────────────────────────
# Borland Pascal FLIRT signatures use mangled names like:
#   @Write$qm4Textm6String4Word
#   @Randomize$qv
#   __ClearDSeg
#   __InOutProc
#
# This table maps known FLIRT-mangled names to human-readable descriptions.

FLIRT_DESCRIPTIONS = {
    # Standard I/O
    '_Write_qm4Textm6String4Word':   ('bp_write_str',      'Write(Text, String, Word) — write string to text file'),
    '_Write_qm4Text4Word':           ('bp_write_word',      'Write(Text, Word) — write word to text file'),
    '_Write_qm4Text7Longint':        ('bp_write_longint',   'Write(Text, Longint) — write longint to text file'),
    '_Write_qm4Text7Integer':        ('bp_write_int',       'Write(Text, Integer) — write integer to text file'),
    '_Write_qm4Text4Char':           ('bp_write_char',      'Write(Text, Char) — write char to text file'),
    '_Write_qm4Text7Boolean':        ('bp_write_bool',      'Write(Text, Boolean) — write boolean to text file'),
    '_Write_qm4Text4Real4Word4Word': ('bp_write_real',      'Write(Text, Real, Word, Word) — write real to text file'),
    '_WriteLn_qm4Text':              ('bp_writeln',         'WriteLn(Text) — write newline'),
    '_ReadLn_qm4Text':               ('bp_readln',          'ReadLn(Text) — read line from text file'),
    '_Read_qm4Text':                 ('bp_read',            'Read(Text) — read from text file'),
    '_Read_qm4Textm6String':         ('bp_read_str',        'Read(Text, String) — read string from text file'),
    '_Read_qm4Textm7Longint':        ('bp_read_longint',    'Read(Text, Longint) — read longint'),
    '_Read_qm4Textm7Integer':        ('bp_read_int',        'Read(Text, Integer) — read integer'),
    # t1-style mangled variants (repeated parameter types use t1 shorthand)
    '_Write_qm4Text4Char4Word':      ('bp_write_char',      'Write(Text, Char, Word) — write char with field width'),
    '_Write_qm4Text7Longint4Word':   ('bp_write_longint',   'Write(Text, Longint, Word) — write longint with width'),
    '_Write_qm4Text7Boolean4Word':   ('bp_write_bool',      'Write(Text, Boolean, Word) — write boolean with width'),
    '_Write_qm4Text4Real4Wordt3':    ('bp_write_real',      'Write(Text, Real, Word, Word) — write real number'),
    '_Read_qm4Text4Char':            ('bp_read_char',       'Read(Text, Char) — read character'),
    '_Read_qm4Text7Longint':         ('bp_read_longint',    'Read(Text, Longint) — read longint'),
    '_Read_qm4Textm6String4Word':    ('bp_read_str',        'Read(Text, String, Word) — read string with max length'),
    '_Concat_qm6Stringt1':           ('bp_concat',          'Concat(String, String) — string concatenation'),
    '_Copy_qm6Stringt17Integert3':   ('bp_copy',            'Copy(String, String, Integer, Integer) — substring'),
    '_Pos_qm6Stringt1':             ('bp_pos',              'Pos(String, String) — find substring position'),
    '_Delete_qm6String7Integert2':   ('bp_delete',          'Delete(String, Integer, Integer) — delete substring'),
    '_Insert_qm6Stringt14Word7Integer': ('bp_insert',       'Insert(String, String, Word, Integer) — insert substring'),
    '_Str_q7Longint4Wordm6String4Byte': ('bp_str_long',     'Str(Longint, Word, String, Byte) — longint to string'),
    '_Random_q4Word':                ('bp_random',          'Random(Word) — random integer 0..N-1'),
    '_GetMem_q4Word':                ('bp_getmem',          'GetMem(Word) — allocate raw memory'),
    '_AssignCrt_qm4Text':            ('crt_assigncrt',      'AssignCrt(Text) — assign text to CRT'),
    '_GotoXY_q4Bytet1':             ('crt_gotoxy',          'GotoXY(Byte, Byte) — position cursor'),
    '_Window_q4Bytet1t2t3':          ('crt_window',         'Window(X1,Y1,X2,Y2) — set text window'),
    '_GetDate_qm4Wordt1t1t1':        ('dos_getdate',        'GetDate(Word,Word,Word,Word)'),
    '_GetTime_qm4Wordt1t1t1':        ('dos_gettime',        'GetTime(Word,Word,Word,Word)'),
    '_FindFirst_q7PathStr4Wordm9SearchRec': ('dos_findfirst', 'FindFirst(PathStr,Word,SearchRec)'),
    '_GetEnv_q6String':              ('dos_getenv',         'GetEnv(String) — get environment variable'),
    '_basg_qm6Stringt1':             ('bp_str_assign',      'String assignment'),
    '_basg_qm6Stringt14Byte':        ('bp_str_assign_n',    'String assignment with max length'),
    # Double-underscore variants emitted by some Ghidra/FLIRT sig versions
    '__basg_qm6Stringt1':            ('bp_str_assign',      'String assignment'),
    '__basg_qm6Stringt14Byte':       ('bp_str_assign_n',    'String assignment with max length'),
    # BP7 stack overflow check — called at function entry with stack frame size.
    # Semantically identical to the offset-0530 label bp_unit_init; using the
    # same short name ensures FLIRT-identified and offset-identified files both
    # render consistently without triggering the name-collision dedup guard.
    '_bp_stackcheck_q4Word':         ('bp_unit_init',       'Unit initialization / stack check'),
    '_IOResult_qv':                  ('bp_ioresult',        'IOResult — last I/O result code'),
    '_UpCase_q4Char':                ('bp_upcase',          'UpCase(Char) — convert to uppercase'),
    '_RunError_q4Byte':              ('bp_runerror',        'RunError(Byte) — trigger runtime error'),

    # String operations (full mangled names)
    '_Concat_qm6Stringm6String':     ('bp_concat',          'Concat(String, String) — string concatenation'),
    '_Copy_qm6String7Integer7Integer': ('bp_copy',          'Copy(String, Index, Count) — substring'),
    '_Length_qm6String':             ('bp_length',          'Length(String) — string length'),
    '_Pos_qm6Stringm6String':       ('bp_pos',             'Pos(Substr, S) — find substring'),
    '_Delete_qm6String7Integer7Integer': ('bp_delete',     'Delete(S, Index, Count) — delete substring'),
    '_Insert_qm6Stringm6String7Integer': ('bp_insert',     'Insert(Source, S, Index) — insert substring'),
    '_Val_qm6Stringm7Integerm7Integer':  ('bp_val_int',    'Val(S, V, Code) — string to integer'),
    '_Val_qm6Stringm7Longintm7Integer':  ('bp_val_long',   'Val(S, V, Code) — string to longint'),
    '_Str_q7Integerm6String':        ('bp_str_int',         'Str(I, S) — integer to string'),
    '_Str_q7Longintm6String':        ('bp_str_long',        'Str(L, S) — longint to string'),

    # Math
    '_Random_q7Integer':             ('bp_random',          'Random(N) — random integer 0..N-1'),
    '_Randomize_qv':                 ('bp_randomize',       'Randomize — seed from system clock'),

    # System
    '_Halt_q4Word':                  ('bp_halt',            'Halt(ExitCode) — terminate program'),
    '_Rename_qm4Filem6String':       ('bp_rename',          'Rename(File, NewName)'),
    '_Erase_qm4File':                ('bp_erase',           'Erase(File) — delete file'),
    '_Assign_qm4Filem6String':       ('bp_assign',          'Assign(File, Name) — bind filename to file var'),
    '_Reset_qm4File':                ('bp_reset',           'Reset(File) — open for reading'),
    '_Rewrite_qm4File':              ('bp_rewrite',         'Rewrite(File) — open for writing'),
    '_Close_qm4File':                ('bp_close',           'Close(File)'),
    '_Seek_qm4File7Longint':         ('bp_seek',            'Seek(File, Position)'),
    '_FileSize_qm4File':             ('bp_filesize',        'FileSize(File) — number of records'),
    '_FilePos_qm4File':              ('bp_filepos',         'FilePos(File) — current position'),
    '_Eof_qm4File':                  ('bp_eof',             'Eof(File) — end of file check'),
    '_Eof_qm4Text':                  ('bp_eof_text',        'Eof(Text) — end of text file'),
    '_ParamCount_qv':                ('bp_paramcount',      'ParamCount — number of command line args'),
    '_ParamStr_q4Word':              ('bp_paramstr',        'ParamStr(Index) — command line argument'),
    '_GetEnv_qm6String':             ('bp_getenv',          'GetEnv(Name) — get environment variable'),

    # Heap
    '_New_qm7Pointer':               ('bp_new',             'New(Ptr) — allocate on heap'),
    '_Dispose_qm7Pointer':           ('bp_dispose',         'Dispose(Ptr) — free heap memory'),
    '_GetMem_qm7Pointer4Word':       ('bp_getmem',          'GetMem(Ptr, Size) — allocate raw memory'),
    '_FreeMem_qm7Pointer4Word':      ('bp_freemem',         'FreeMem(Ptr, Size) — free raw memory'),
    '_MemAvail_qv':                  ('bp_memavail',        'MemAvail — available heap memory'),
    '_MaxAvail_qv':                  ('bp_maxavail',        'MaxAvail — largest free block'),

    # CRT unit
    '_ClrScr_qv':                    ('crt_clrscr',         'ClrScr — clear screen'),
    '_GotoXY_q4Byte4Byte':           ('crt_gotoxy',         'GotoXY(X, Y) — position cursor'),
    '_WhereX_qv':                    ('crt_wherex',         'WhereX — current cursor column'),
    '_WhereY_qv':                    ('crt_wherey',         'WhereY — current cursor row'),
    '_TextColor_q4Byte':             ('crt_textcolor',      'TextColor(Color) — set foreground'),
    '_TextBackground_q4Byte':        ('crt_textbg',         'TextBackground(Color) — set background'),
    '_Delay_q4Word':                 ('crt_delay',           'Delay(MS) — millisecond pause'),
    '_Sound_q4Word':                 ('crt_sound',           'Sound(Hz) — start speaker tone'),
    '_NoSound_qv':                   ('crt_nosound',         'NoSound — stop speaker'),
    '_ReadKey_qv':                   ('crt_readkey',         'ReadKey — read character from keyboard'),
    '_KeyPressed_qv':                ('crt_keypressed',      'KeyPressed — check if key available'),
    '_TextMode_q7Integer':           ('crt_textmode',        'TextMode(Mode) — set text video mode'),
    '_Window_q4Byte4Byte4Byte4Byte': ('crt_window',         'Window(X1,Y1,X2,Y2) — set text window'),
    '_InsLine_qv':                   ('crt_insline',         'InsLine — insert line at cursor'),
    '_DelLine_qv':                   ('crt_delline',         'DelLine — delete line at cursor'),

    # DOS unit
    '_GetDate_qm4Wordm4Wordm4Wordm4Word': ('dos_getdate',  'GetDate(Year,Month,Day,DOW)'),
    '_GetTime_qm4Wordm4Wordm4Wordm4Word': ('dos_gettime',  'GetTime(Hour,Min,Sec,Sec100)'),
    '_FindFirst_qm6String4Wordm9SearchRec': ('dos_findfirst', 'FindFirst(Path,Attr,SR)'),
    '_FindNext_qm9SearchRec':        ('dos_findnext',       'FindNext(SR) — find next matching file'),
    '_DiskFree_q4Byte':              ('dos_diskfree',       'DiskFree(Drive) — free disk space'),
    '_DiskSize_q4Byte':              ('dos_disksize',       'DiskSize(Drive) — total disk size'),
    '_DosVersion_qv':                ('dos_dosversion',     'DosVersion — DOS version number'),
    '_EnvCount_qv':                  ('dos_envcount',       'EnvCount — number of environment strings'),
    '_EnvStr_q7Integer':             ('dos_envstr',         'EnvStr(Index) — environment string by index'),
    '_SwapVectors_qv':               ('dos_swapvectors',    'SwapVectors — swap interrupt vectors'),
    '_Exec_qm6Stringm6String':       ('dos_exec',           'Exec(Path, CmdLine) — run external program'),

    # Overlay unit
    '_OvrInit_qm6String':            ('ovr_init',           'OvrInit(FileName) — initialize overlay system'),
    '_OvrInitEMS_qv':                ('ovr_initems',        'OvrInitEMS — use EMS for overlays'),

    # ── DDPlus 7.1 door driver toolkit ────────────────────────────────────
    # Freeware BBS door development kit for Turbo Pascal 7 (Steven Lorenz /
    # Bob Dalton / Scott Baker).  FLIRT names predicted from TP7 name-mangling
    # conventions; extract ddplus.sig from DDTEST.EXE to confirm exact names.
    #
    # Screen / output
    '_sclrscr_qv':                       ('ddp_sclrscr',          'DDPlus sclrscr — clear screen (ANSI + local CRT)'),
    '_sclreol_qv':                       ('ddp_sclreol',          'DDPlus sclreol — clear to end of line'),
    '_swrite_q6String':                  ('ddp_swrite',           'DDPlus swrite(s) — send string to modem and screen'),
    '_swriteln_q6String':                ('ddp_swriteln',         'DDPlus swriteln(s) — send string + CR/LF'),
    '_swritec_q4Char':                   ('ddp_swritec',          'DDPlus swritec(ch) — send single character'),
    '_swritexy_q7Integert16String':      ('ddp_swritexy',         'DDPlus swritexy(x,y,s) — cursor position then write'),
    '_sgoto_xy_q7Integert1':             ('ddp_sgoto_xy',         'DDPlus sgoto_xy(x,y) — ANSI cursor move'),
    '_sendtext_q6String':                ('ddp_sendtext',         'DDPlus sendtext(s) — raw string to modem port only'),
    '_set_foreground_q4Byte':            ('ddp_set_foreground',   'DDPlus set_foreground(color) — ANSI foreground color'),
    '_set_background_q4Byte':            ('ddp_set_background',   'DDPlus set_background(color) — ANSI background color'),
    '_set_color_q4Bytet1':               ('ddp_set_color',        'DDPlus set_color(fg,bg) — set ANSI fore+background'),
    '_Clear_Region_q4Bytet1t2':          ('ddp_clear_region',     'DDPlus Clear_Region(x,r1,r2) — blank a band of rows'),
    '_Propeller_q4Byte':                 ('ddp_propeller',        'DDPlus Propeller(v) — spinning |/-\\ progress indicator'),
    '_display_status_qv':                ('ddp_display_status',   'DDPlus display_status — render status bar'),
    '_Displayfile_q6String':             ('ddp_displayfile',      'DDPlus Displayfile(name) — display text file to user'),
    '_SelectAnsi_q4Char6String':         ('ddp_selectansi',       'DDPlus SelectAnsi(flag,name) — auto-select .ANS/.ASC file'),
    # Input
    '_sread_char_qm4Char':               ('ddp_sread_char',       'DDPlus sread_char(var ch) — blocking single-char read'),
    '_sread_char_filtered_qm4Char':      ('ddp_sread_char_filt',  'DDPlus sread_char_filtered — read char, strip control codes'),
    '_speedread_qm4Char':                ('ddp_speedread',        'DDPlus speedread(var ch) — instant read, no echo'),
    '_sread_qm6String':                  ('ddp_sread',            'DDPlus sread(var s) — read string with backspace editing'),
    '_sread_num_qm7Integer':             ('ddp_sread_num',        'DDPlus sread_num(var n) — read integer from user'),
    '_sread_num_byte_qm4Byte':           ('ddp_sread_num_byte',   'DDPlus sread_num_byte(var b) — read byte from user'),
    '_sread_num_word_qm4Word':           ('ddp_sread_num_word',   'DDPlus sread_num_word(var w) — read word from user'),
    '_sread_num_longint_qm7Longint':     ('ddp_sread_num_long',   'DDPlus sread_num_longint(var l) — read longint from user'),
    '_prompt_qm6String7Integer7Boolean': ('ddp_prompt',           'DDPlus prompt(var s, maxlen, passmode) — length-limited input'),
    '_get_stacked_qm6String':            ('ddp_get_stacked',      'DDPlus get_stacked — dequeue stacked command input'),
    '_skeypressed_qv':                   ('ddp_skeypressed',      'DDPlus skeypressed: boolean — non-blocking key check'),
    # Status / timing
    '_time_left_qv':                     ('ddp_time_left',        'DDPlus time_left: integer — BBS minutes remaining'),
    '_Time_used_qv':                     ('ddp_time_used',        'DDPlus Time_used: integer — minutes used in this door'),
    '_elapsed_q7Longintt1t2t3t4t5m4Wordt1t2': ('ddp_elapsed',    'DDPlus elapsed(h,m,s,h,m,s → var h,m,s) — time difference'),
    # Initialisation / framework
    '_InitDoorDriver_q6String':          ('ddp_init',             'DDPlus InitDoorDriver(cfg) — read .CTL + BBS drop file'),
    '_DDAssignSoutput_qm4Text':          ('ddp_assign_soutput',   'DDPlus DDAssignSoutput(f) — enable simultaneous file log'),
    # Communications
    '_open_async_port_qv':               ('ddp_open_async',       'DDPlus open_async_port — open configured serial port'),
    '_close_async_port_qv':              ('ddp_close_async',      'DDPlus close_async_port — close serial port'),
    '_ReleaseTimeSlice_qv':              ('ddp_timeslice',        'DDPlus ReleaseTimeSlice — yield to DV/Win/OS2 multitasker'),
    '_DV_Aware_On_qv':                   ('ddp_dv_aware',         'DDPlus DV_Aware_On — register with DESQview'),

    # ── COMIO unit (DDPlus serial I/O layer) ──────────────────────────────
    # Direct serial port / FOSSIL / DigiBoard abstraction used by DDPlus.
    '_AsyncSendChar_q4Char':             ('comio_send_char',      'COMIO AsyncSendChar(ch) — write char to serial port'),
    '_AsyncReceiveChar_qm4Char':         ('comio_recv_char',      'COMIO AsyncReceiveChar(var ch) — read char from serial port'),
    '_AsyncCarrierPresent_qv':           ('comio_carrier',        'COMIO AsyncCarrierPresent: boolean — check DCD carrier'),
    '_AsyncCharPresent_qv':              ('comio_char_ready',     'COMIO AsyncCharPresent: boolean — char waiting in RX buffer'),
    '_AsyncSetBaud_q7Longint':           ('comio_set_baud',       'COMIO AsyncSetBaud(n) — set serial baud rate'),
    '_AsyncSetDTR_q7Boolean':            ('comio_set_dtr',        'COMIO AsyncSetDTR(state) — assert/drop DTR line'),
    '_AsyncFlushOutput_qv':              ('comio_flush',          'COMIO AsyncFlushOutput — wait for TX buffer to drain'),
    '_AsyncPurgeOutput_qv':              ('comio_purge',          'COMIO AsyncPurgeOutput — discard TX buffer contents'),
    '_AsyncSelectPort_q4Byte':           ('comio_select_port',    'COMIO AsyncSelectPort(n) — select COM port 1-4'),
    '_AsyncSetFlow_q7Booleant1t2':       ('comio_set_flow',       'COMIO AsyncSetFlow(soft_tx,hard,soft_rx) — flow control'),
}

# Non-mangled FLIRT names (double underscore prefix)
FLIRT_PLAIN_DESCRIPTIONS = {
    '__ClearDSeg':     ('bp_clear_dseg',    'Clear data segment (BSS init)'),
    '__InOutProc':     ('bp_inoutproc',     'I/O procedure dispatcher'),
    '__PrintString':   ('bp_printstring',   'Print string to stdout'),
    '__IOCheck':       ('bp_iocheck',       'Check I/O result code'),
}

# ── Pattern-Based Code Analysis ────────────────────────────────────────────
# Identify functions by analyzing their decompiled code body, not by offset.
# This works for ANY TP7 binary, not just specific IGMs.

def identify_by_pattern(func_name: str, func_body: str) -> tuple[str, str] | None:
    """Try to identify a function by its code patterns.
    Returns (short_name, description) or None.
    """
    body = func_body.strip()

    # Stack check: checks stack pointer against a limit
    if ('stack0x0000' in body and '0x200' in body and
        'FUN_' in body and body.count('\n') < 15):
        return ('bp_stack_check', 'Stack overflow check')

    # Write(Text, String, Word): calls __WriteBlanks and __WriteBuffer
    if '__WriteBlanks' in body and '__WriteBuffer' in body and body.count('\n') < 25:
        return ('bp_write_str', 'Write(Text, String, Word) — write string')

    # Write(Text, String, Word) structural pattern — sub-functions not FLIRT-named:
    # reads length byte from param_2, checks vs field width (param_1), writes if non-empty
    if ('bVar1 = *param_2' in body and
            'bVar1 < param_1' in body and
            'bVar1 != 0' in body and
            body.count('\n') < 25):
        return ('bp_write_str', 'Write(Text, String, Word) — write string')

    # BIOS INT 10h wrapper: small function that just calls INT 10h
    if 'swi(0x10)' in body and body.count('\n') < 20:
        # Check no FUN_ calls in the code body (after opening brace)
        brace_pos = body.find('{')
        code_body = body[brace_pos:] if brace_pos >= 0 else body
        if 'FUN_' not in code_body:
            return ('bp_bios_int10', 'BIOS INT 10h video interrupt wrapper')
        return ('bp_bios_int10', 'BIOS INT 10h video interrupt wrapper')

    # WriteLn wrapper: calls Write then outputs newline
    if ('_Write_' in body and body.count('\n') < 8):
        return ('bp_writeln_wrapper', 'WriteLn wrapper')

    # INT 21h wrappers: very small functions that just do a DOS interrupt
    if body.count('swi(0x21)') >= 1 and body.count('\n') < 15 and 'for' not in body:
        brace_pos = body.find('{')
        code_body = body[brace_pos:] if brace_pos >= 0 else body
        if 'FUN_' not in code_body:
            return ('bp_dos_int21', 'DOS INT 21h wrapper')

    # Write char via __InOutProc + conditional WriteLn flush
    if '__InOutProc' in body and '0x1a' in body and body.count('\n') < 25:
        return ('bp_write_inoutproc', 'Write char via __InOutProc + conditional flush')

    # Write(Text, Integer) — has FLIRT-named __Str2Int but sub-calls not FLIRT-named
    if '__Str2Int' in body and 'in_CX' in body and body.count('\n') < 25:
        return ('bp_write_int', 'Write(Text, Integer) — write integer')

    # WriteLn / write char + flush: calls write sub-fn, then conditionally flushes
    # Detected by use of in_ZF flag and TextRec flush function pointer at +0x1a
    if ('in_ZF' in body and '0x1a' in body and
            'FUN_' in body and body.count('\n') < 25):
        return ('bp_write_char_flush', 'Write char + conditional WriteLn flush')

    # Conditional flush only (no write): checks TextRec flush pointer, calls if set
    brace_pos = body.find('{')
    code_body = body[brace_pos:] if brace_pos >= 0 else body
    if ('0x1a' in body and
            code_body.count('FUN_') == 1 and
            body.count('\n') < 22 and
            'in_ZF' not in body):
        return ('bp_flush_text_cond', 'Conditional text buffer flush')

    # Bounded string copy: copies min(param_1, *param_3) bytes from param_3 to param_2
    if ('param_1 < *param_3' in body and
            '*param_2 = bVar1' in body and
            body.count('\n') < 40):
        return ('bp_str_copy_bounded', 'Bounded string copy: min(param_1, *param_3) bytes')

    # Intr(IntNo, Regs): self-modifying code that patches swi(0) with actual intno
    if 'swi(0)' in body and 'uRam' in body:
        return ('dos_intr', 'Intr(IntNo, Regs) — call software interrupt')

    return None


def extract_function_bodies(text: str) -> dict[str, str]:
    """Extract function name → body text for all functions.
    Returns a dict mapping the function name to its full body text.
    """
    func_bodies = {}
    func_pattern = re.compile(r'^// Function: (\S+) @ ', re.MULTILINE)
    matches = list(func_pattern.finditer(text))

    for i, m in enumerate(matches):
        name = m.group(1)
        start = m.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        func_bodies[name] = text[start:end]

    return func_bodies


def build_label_table(decompiled_text: str) -> dict[str, tuple[str, str]]:
    """Build a mapping of full function names → (short_label, description).

    Discovers which Ghidra segments correspond to which libraries by looking
    at the function names actually present in the decompiled code, uses
    pattern-based analysis of function bodies, and decodes FLIRT-mangled names.
    """
    # Find all unique FUN_xxxx_yyyy names
    func_names = set(re.findall(r'FUN_([0-9a-f]+)_([0-9a-f]+)', decompiled_text))

    # Group by segment to identify which segment is which library
    seg_funcs: dict[str, set[str]] = defaultdict(set)
    for seg, off in func_names:
        seg_funcs[seg].add(off)

    # Heuristic identification:
    # - System RTL: has the most functions, contains str_concat (3fca), str_copy (3f65)
    #   OR has the most matches against known core RTL offsets
    # - Display: contains 0002, 02a8, 054e
    # - Input: contains 1168 (getkey)
    # - Conversion: contains 0002, 011d (int conversions)
    # - Timer: contains 02fa (delay)
    # - Records: contains 01ce, 02b6

    labels: dict[str, tuple[str, str]] = {}

    # Known core RTL offsets used for System segment identification
    _CORE_RTL_OFFSETS = set(BP_SYSTEM_CORE_LABELS.keys())

    # First pass: identify the System RTL segment (the one with the most
    # core RTL offset matches).  Large binaries are identified by having
    # 3fca/3f65; small binaries are identified by counting core offsets.
    system_seg = None
    best_core_count = 0
    for seg, offsets in seg_funcs.items():
        # Strong markers: str_concat or str_copy are definitive System RTL
        if '3fca' in offsets or '3f65' in offsets or '04f4' in offsets:
            system_seg = seg
            break
        # Count core RTL offset matches
        core_count = len(offsets & _CORE_RTL_OFFSETS)
        if core_count > best_core_count:
            best_core_count = core_count
            system_seg = seg

    # Apply System RTL labels
    if system_seg:
        seg_offsets = seg_funcs[system_seg]
        # Apply both high-offset and core labels
        for off, (name, desc) in BP_SYSTEM_LABELS.items():
            if off in seg_offsets:
                labels[f'FUN_{system_seg}_{off}'] = (name, desc)
        for off, (name, desc) in BP_SYSTEM_CORE_LABELS.items():
            if off in seg_offsets:
                labels[f'FUN_{system_seg}_{off}'] = (name, desc)

    # Second pass: identify library segments (excluding the System segment)
    for seg, offsets in seg_funcs.items():
        if seg == system_seg:
            continue

        # Display library: identified by having 02a8 (lln) and 054e (sln)
        if '02a8' in offsets and '054e' in offsets:
            for off, (name, desc) in RHP_DISPLAY_LABELS.items():
                if off in offsets:
                    labels[f'FUN_{seg}_{off}'] = (name, desc)

        # Input library: identified by 1168 (getkey)
        elif '1168' in offsets:
            for off, (name, desc) in RHP_INPUT_LABELS.items():
                if off in offsets:
                    labels[f'FUN_{seg}_{off}'] = (name, desc)

        # Conversion library: identified by having both 0002 and 011d
        elif '0002' in offsets and '011d' in offsets:
            for off, (name, desc) in CONV_LABELS.items():
                if off in offsets:
                    labels[f'FUN_{seg}_{off}'] = (name, desc)

        # Timer library: identified by 02fa (delay) but NOT display funcs
        elif '02fa' in offsets and '02a8' not in offsets and '054e' not in offsets:
            for off, (name, desc) in TIMER_LABELS.items():
                if off in offsets:
                    labels[f'FUN_{seg}_{off}'] = (name, desc)

        # Record/file library: identified by 01ce and 02b6
        elif '01ce' in offsets and '02b6' in offsets:
            for off, (name, desc) in RECORD_LABELS.items():
                if off in offsets:
                    labels[f'FUN_{seg}_{off}'] = (name, desc)

        # DDPlus 7.1 door driver: identified by swriteln (13b6), swrite (130c),
        # sclrscr (11b7), and sgoto_xy (281e) at characteristic offsets
        elif '13b6' in offsets and '130c' in offsets and '11b7' in offsets and '281e' in offsets:
            for off, (name, desc) in DDPLUS_LABELS.items():
                if off in offsets:
                    labels[f'FUN_{seg}_{off}'] = (name, desc)

        # DDPlus IO utility unit: identified by low-offset function cluster
        elif '0000' in offsets and '004a' in offsets and '00bb' in offsets and '0143' in offsets:
            for off, (name, desc) in DDPLUS_IO_LABELS.items():
                if off in offsets:
                    labels[f'FUN_{seg}_{off}'] = (name, desc)

        # CRT unit: identified by WhereX (024b) and WhereY (0257)
        elif '024b' in offsets and '0257' in offsets:
            for off, (name, desc) in CRT_UNIT_LABELS.items():
                if off in offsets:
                    labels[f'FUN_{seg}_{off}'] = (name, desc)

    # --- Pattern-based identification ---
    # Analyze function bodies for code patterns
    func_bodies = extract_function_bodies(decompiled_text)
    for name, body in func_bodies.items():
        if name.startswith('FUN_') and name not in labels:
            result = identify_by_pattern(name, body)
            if result is not None:
                labels[name] = result

    return labels


def decode_flirt_name(mangled: str) -> tuple[str, str] | None:
    """Decode a Borland Pascal FLIRT-mangled function name.
    Returns (short_name, description) or None if not recognized.
    """
    # Check exact match in known FLIRT descriptions
    if mangled in FLIRT_DESCRIPTIONS:
        return FLIRT_DESCRIPTIONS[mangled]
    if mangled in FLIRT_PLAIN_DESCRIPTIONS:
        return FLIRT_PLAIN_DESCRIPTIONS[mangled]

    # Try to decode from the mangling pattern:
    # @FuncName$qParamTypes  →  _FuncName_qParamTypes (Ghidra's C rendering)
    # Common type codes: m=var, 4=ref, q=params, v=void
    if mangled.startswith('_') and '_q' in mangled:
        # Extract function name between leading _ and _q
        parts = mangled.split('_q', 1)
        func_name = parts[0].lstrip('_')
        params = parts[1] if len(parts) > 1 else ''
        desc = f"{func_name}({params}) — FLIRT-identified"
        short = f"bp_{func_name.lower()}"
        return (short, desc)

    # Double-underscore system functions
    if mangled.startswith('__'):
        name = mangled.lstrip('_')
        return (f'bp_{name.lower()}', f'{name} — system runtime function')

    return None


def label_line(line: str, labels: dict[str, tuple[str, str]],
               flirt_labels: dict[str, tuple[str, str]] | None = None) -> str:
    """Add a label comment to lines containing known function calls."""
    stripped = line.rstrip('\n')

    # Find FUN_* function calls in this line
    matches = list(re.finditer(r'(FUN_[0-9a-f]+_[0-9a-f]+)\s*\(', line))
    annotations = []
    for m in matches:
        func_name = m.group(1)
        if func_name in labels:
            _, desc = labels[func_name]
            annotations.append(f'/* {desc} */')

    # Find FLIRT-named function calls
    if flirt_labels:
        flirt_matches = list(re.finditer(r'(\b(?:_[A-Za-z]\w*_q[A-Za-z0-9]+|__[A-Za-z]\w+)\b)\s*\(', line))
        for m in flirt_matches:
            func_name = m.group(1)
            if func_name in flirt_labels:
                _, desc = flirt_labels[func_name]
                annotations.append(f'/* {desc} */')

    if not annotations:
        return line

    return stripped + '  ' + '  '.join(annotations) + '\n'


def apply_renames(text: str, labels: dict[str, tuple[str, str]],
                  flirt_labels: dict[str, tuple[str, str]] | None = None) -> str:
    """Replace known function identifiers with their short labels throughout text.

    Handles both FUN_xxxx_yyyy offset-based names and FLIRT-mangled names.
    Skips any short name shared by more than one function to avoid creating
    duplicate identifiers in the output.
    """
    name_count: dict[str, int] = {}
    for _, (short, _) in labels.items():
        name_count[short] = name_count.get(short, 0) + 1
    if flirt_labels:
        for _, (short, _) in flirt_labels.items():
            name_count[short] = name_count.get(short, 0) + 1
    for func_name, (short, _) in labels.items():
        if name_count[short] == 1:
            text = text.replace(func_name, short)
    if flirt_labels:
        for func_name, (short, _) in flirt_labels.items():
            if name_count[short] == 1:
                text = text.replace(func_name, short)
    return text


def main():
    args = sys.argv[1:]
    if not args or args[0] in ('-h', '--help'):
        print(__doc__)
        sys.exit(0)

    src_file = args[0]
    out_file = None

    i = 1
    while i < len(args):
        if args[i] == '-o' and i + 1 < len(args):
            out_file = args[i + 1]; i += 2
        else:
            i += 1

    if out_file is None:
        base, ext = os.path.splitext(src_file)
        out_file = base + '.labeled' + ext

    with open(src_file, 'r', encoding='utf-8', errors='replace') as f:
        text = f.read()

    # Build label table (offset-based + pattern-based)
    labels = build_label_table(text)

    # Count all function references
    all_funcs = re.findall(r'(FUN_[0-9a-f]+_[0-9a-f]+)', text)
    func_counts = defaultdict(int)
    for f_name in all_funcs:
        func_counts[f_name] += 1

    # Find and decode FLIRT-identified functions
    # Broader pattern: catches @Name$q... (rendered as _Name_q...) and __Name
    # Note: __[A-Za-z]\w+ now covers lowercase-starting names like __basg_qm6Stringt1
    flirt_pattern = re.compile(
        r'\b(_[A-Za-z]\w*_q[A-Za-z0-9]+|__[A-Za-z]\w+)\b'
    )
    flirt_funcs = flirt_pattern.findall(text)
    flirt_counts = defaultdict(int)
    for f_name in flirt_funcs:
        flirt_counts[f_name] += 1

    # Build FLIRT label table
    flirt_labels: dict[str, tuple[str, str]] = {}
    for fname in flirt_counts:
        decoded = decode_flirt_name(fname)
        if decoded:
            flirt_labels[fname] = decoded

    # Apply labels
    lines = text.split('\n')
    labeled_count = 0
    out_lines = []
    for line in lines:
        new_line = label_line(line + '\n', labels, flirt_labels)
        if new_line != line + '\n':
            labeled_count += 1
        out_lines.append(new_line.rstrip('\n'))

    output_text = apply_renames('\n'.join(out_lines), labels, flirt_labels)

    with open(out_file, 'w', encoding='utf-8') as f:
        f.write(output_text)

    # Print summary
    print(f"Function Label Summary")
    print(f"=" * 60)
    print(f"  Total unique FUN_* functions: {len(func_counts)}")
    print(f"  FLIRT-identified functions:   {len(flirt_counts)}")
    print(f"  FLIRT decoded labels:         {len(flirt_labels)}")
    print(f"  Pattern-labeled functions:    {len(labels)}")
    print(f"  Lines labeled:               {labeled_count}")
    print()

    # Show identified functions
    if labels:
        print("Offset/pattern-identified functions:")
        for func_name in sorted(labels.keys()):
            short, desc = labels[func_name]
            count = func_counts.get(func_name, 0)
            print(f"  {func_name:30s} = {short:25s} ({count:4d} refs) — {desc}")
        print()

    if flirt_labels:
        print("FLIRT-identified functions (decoded):")
        for func_name in sorted(flirt_labels.keys()):
            short, desc = flirt_labels[func_name]
            count = flirt_counts.get(func_name, 0)
            print(f"  {func_name:40s} = {short:20s} ({count:4d} refs) — {desc}")
        print()

    # Show unidentified FLIRT names (recognized but not decoded)
    undecoded = set(flirt_counts.keys()) - set(flirt_labels.keys())
    if undecoded:
        print("FLIRT functions (not decoded):")
        for func_name in sorted(undecoded):
            print(f"  {func_name:40s} ({flirt_counts[func_name]:4d} refs)")
        print()

    # Show unidentified high-frequency functions
    unidentified_high = [(n, c) for n, c in func_counts.items()
                         if n not in labels and c > 10]
    if unidentified_high:
        print("Unidentified functions (>10 refs):")
        for func_name, count in sorted(unidentified_high, key=lambda x: -x[1]):
            print(f"  {func_name:30s} ({count:4d} refs)")
        print()

    print(f"  Written to: {out_file}")


if __name__ == '__main__':
    main()
