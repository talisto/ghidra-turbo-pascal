program DDTest;
{
  DDPlus 7.1 -- Comprehensive function coverage test.

  PURPOSE: Links every exported DDPlus procedure and function into the
  compiled binary so that FLIRT signatures can be extracted from it with
  IDA's sigmake tool.  The resulting ddplus.sig can then be applied by
  ApplySigHeadless.py to auto-rename DDPlus stubs in any door game binary.

  COMPILE ORDER (all .PAS files must be in C:\TP\SOURCE):
    DDFOSSIL.PAS
    ASYNC2.PAS
    DDIGI.PAS
    COMIO.PAS
    DDSCOTT.PAS
    DDANSI2.PAS
    DDOVR.PAS
    DDOVR2.PAS
    DDPLUS.PAS
    DDTEST.PAS        <- this file

  DVAWARE.OBJ and SLASYNC.OBJ must also be in C:\TP\SOURCE.

  USAGE:
    DDTEST /L           (local mode -- no BBS drop file needed)

  GAME.CTL must be present in the same directory at runtime.

  NOTE: Some calls (Displayfile, SelectAnsi) reference files that may not
  exist; they will fail gracefully.  The goal is linkage, not a passing run.
}

{$I-}

uses ddplus;

{ -- Global variables (TP7 requires all vars in var sections) -- }
var
  ch         : char;
  s, sv      : string;
  n          : integer;
  b          : byte;
  w          : word;
  l          : longint;
  tl, tu     : integer;
  sk         : boolean;
  eh, em, es : word;
  logf       : text;

{ =========================================================================== }
{  1. Display / screen output functions                                       }
{ =========================================================================== }
procedure TestDisplay;
var
  i : byte;
begin
  { sclrscr: sends ANSI clear-screen escape to modem + clears local screen }
  sclrscr;

  { swriteln: write string + CR/LF to modem and local screen }
  swriteln('=== DDTest 7.1 Function Coverage Test ===');
  swriteln('');
  swriteln('User: ' + user_first_name + ' ' + user_last_name);
  swriteln('Board: ' + board_name);
  swriteln('');

  { swrite: write string without newline }
  swrite('swrite (no newline): ');

  { swritec: write a single character }
  swritec('*');
  swritec(#13);
  swritec(#10);

  { swritexy: position cursor then write string }
  swritexy(1, 5, 'swritexy at row 5');

  { sgoto_xy: position cursor without writing }
  sgoto_xy(1, 7);
  swriteln('After sgoto_xy(1,7)');

  { sclreol: clear from cursor to end of line }
  sclreol;

  { set_foreground / set_background / set_color: ANSI color control }
  set_foreground(12);   { LightRed }
  swriteln('Foreground: LightRed');
  set_background(1);    { Blue }
  swrite('Background: Blue, then ');
  set_color(15, 0);     { White on Black }
  swriteln('set_color reset');

  { Clear_Region: clear a rectangular band of rows }
  Clear_Region(1, 11, 13);
  sgoto_xy(1, 14);
  swriteln('Clear_Region rows 11-13 done');

  { Propeller: spinning progress indicator (1..4 cycles through |/-\) }
  swrite('Propeller: ');
  for i := 1 to 8 do
    Propeller(i mod 4 + 1);
  swriteln('');
end;

{ =========================================================================== }
{  2. Status / timing functions                                               }
{ =========================================================================== }
procedure TestStatus;
begin
  { time_left: BBS minutes remaining for this user session }
  tl := time_left;
  str(tl, sv);
  swriteln('time_left  : ' + sv + ' min');

  { Time_used: minutes spent in this door so far }
  tu := Time_used;
  str(tu, sv);
  swriteln('Time_used  : ' + sv + ' min');

  { skeypressed: non-blocking check for pending keypress }
  sk := skeypressed;
  if sk then
    swriteln('skeypressed: key waiting')
  else
    swriteln('skeypressed: no key');

  { display_status: renders the DDPlus status bar at the bottom of screen }
  display_status;

  { elapsed: compute difference between two HH:MM:SS times }
  elapsed(0, 0, 0, 0, 2, 30, eh, em, es);
  str(em, sv);
  swrite('elapsed 0:00:00 to 0:02:30 = ' + sv + 'm ');
  str(es, sv);
  swriteln(sv + 's');
end;

{ =========================================================================== }
{  3. Communications / port functions                                         }
{ =========================================================================== }
procedure TestComms;
begin
  { sendtext: write raw string directly to the modem UART (no local echo) }
  sendtext('sendtext raw output');

  { open_async_port / close_async_port: (re)open and close the serial port }
  open_async_port;
  close_async_port;

  { ReleaseTimeSlice: yield CPU to DESQview / Windows / OS/2 multitasker }
  ReleaseTimeSlice;

  { DV_Aware_On: register this program with DESQview (safe outside DV) }
  DV_Aware_On;
end;

{ =========================================================================== }
{  4. Input functions                                                         }
{ =========================================================================== }
procedure TestInput;
begin
  swriteln('');
  swriteln('--- Input tests (press keys as prompted) ---');

  { sread_char: blocking single-char read, echoes character }
  swrite('sread_char (any key): ');
  sread_char(ch);
  swriteln('');

  { speedread: single-char read with NO echo and no line buffering }
  swrite('speedread (any key, no echo): ');
  speedread(ch);
  swriteln('');

  { sread_char_filtered: like sread_char but strips control chars }
  swrite('sread_char_filtered (alpha/num key): ');
  sread_char_filtered(ch);
  swriteln('');

  { sread_num: read a signed integer (stops on Enter) }
  swrite('sread_num (integer): ');
  sread_num(n);

  { sread_num_byte: read a byte value 0..255 }
  swrite('sread_num_byte (0-255): ');
  sread_num_byte(b);

  { sread_num_word: read a word value 0..65535 }
  swrite('sread_num_word (0-65535): ');
  sread_num_word(w);

  { sread_num_longint: read a longint }
  swrite('sread_num_longint (longint): ');
  sread_num_longint(l);

  { sread: full string input with backspace editing }
  swrite('sread (string): ');
  sread(s);

  { prompt: length-limited string input, optional password masking }
  swrite('prompt (max 15 chars): ');
  s := '';
  prompt(s, 15, false);
  swriteln('');

  { get_stacked: retrieves pre-queued input from the stacked command buffer }
  get_stacked(s);
end;

{ =========================================================================== }
{  5. File display functions                                                  }
{ =========================================================================== }
procedure TestFileOps;
begin
  { Displayfile: show a plain ASCII file to the user (fails gracefully) }
  Displayfile('DDTEST.TXT');

  { SelectAnsi: show .ANS or .ASC depending on user graphics setting }
  { chflag='2' selects .ANS; '1' selects .ASC; '0' skips entirely    }
  SelectAnsi('1', 'DDTEST');

  { DDAssignSoutput: redirect all subsequent swrite output to also go }
  { to a text file (simultaneous log).                                 }
  assign(logf, 'DDTEST.LOG');
  rewrite(logf);
  DDAssignSoutput(logf);
  swriteln('This line is logged to DDTEST.LOG via DDAssignSoutput');
  close(logf);
end;

{ =========================================================================== }
{  Main program                                                               }
{ =========================================================================== }
begin
  { InitDoorDriver: reads GAME.CTL, then reads the BBS drop file.          }
  { In local mode (/L flag) the drop file is skipped; the user gets a      }
  { default name and full time.                                             }
  initdoordriver('GAME.CTL');

  TestDisplay;
  TestStatus;
  TestComms;
  TestInput;
  TestFileOps;

  swriteln('');
  swriteln('All function tests complete.');

  { Final globals access -- ensures these symbols are linked }
  str(bbs_time_left, sv);
  swriteln('bbs_time_left: ' + sv);
  str(com_port, sv);
  swriteln('com_port: ' + sv);
  str(node_num, sv);
  swriteln('node_num: ' + sv);
  str(graphics, sv);
  swriteln('graphics: ' + sv);
  if local then swriteln('local: true') else swriteln('local: false');

  swriteln('Press any key to exit.');
  sread_char(ch);
end.
