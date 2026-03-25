program FileIO;
{ Test file I/O: text files, typed files, record I/O }
{ Exercises: bp_file_assign, bp_file_rewrite, bp_file_reset, etc. }

{$I-}

type
  DataRec = record
    id: integer;
    name: string[20];
    score: longint;
  end;

var
  tf: text;
  df: file of DataRec;
  rec: DataRec;
  line: string;
  i, code: integer;

procedure WriteTextFile;
begin
  Assign(tf, 'TEST.TXT');
  Rewrite(tf);
  if IOResult <> 0 then
  begin
    writeln('Error creating TEST.TXT');
    exit;
  end;
  writeln(tf, 'Line 1: Hello from FileIO test');
  writeln(tf, 'Line 2: Testing text file output');
  writeln(tf, 'Line 3: Numbers: ', 42, ' ', 3.14:6:2);
  for i := 4 to 10 do
    writeln(tf, 'Line ', i, ': Generated line');
  Close(tf);
  writeln('Wrote TEST.TXT');
end;

procedure ReadTextFile;
var
  lineCount: integer;
begin
  Assign(tf, 'TEST.TXT');
  Reset(tf);
  code := IOResult;
  if code <> 0 then
  begin
    writeln('Error opening TEST.TXT: ', code);
    exit;
  end;
  lineCount := 0;
  while not Eof(tf) do
  begin
    Readln(tf, line);
    inc(lineCount);
    writeln('  Read: ', line);
  end;
  Close(tf);
  writeln('Read ', lineCount, ' lines from TEST.TXT');
end;

procedure WriteRecordFile;
begin
  Assign(df, 'TEST.DAT');
  Rewrite(df);
  if IOResult <> 0 then
  begin
    writeln('Error creating TEST.DAT');
    exit;
  end;

  for i := 1 to 5 do
  begin
    rec.id := i;
    Str(i, rec.name);
    rec.name := 'Player' + rec.name;
    rec.score := longint(i) * 1000;
    Write(df, rec);
  end;
  Close(df);
  writeln('Wrote 5 records to TEST.DAT');
end;

procedure ReadRecordFile;
var
  count: integer;
begin
  Assign(df, 'TEST.DAT');
  Reset(df);
  code := IOResult;
  if code <> 0 then
  begin
    writeln('Error opening TEST.DAT: ', code);
    exit;
  end;

  count := 0;
  while not Eof(df) do
  begin
    Read(df, rec);
    inc(count);
    writeln('  Record ', rec.id, ': ', rec.name, ' Score=', rec.score);
  end;
  Close(df);
  writeln('Read ', count, ' records from TEST.DAT');
end;

procedure SeekTest;
begin
  Assign(df, 'TEST.DAT');
  Reset(df);
  code := IOResult;
  if code <> 0 then
  begin
    writeln('Error opening TEST.DAT for seek test');
    exit;
  end;

  writeln('FileSize: ', FileSize(df));
  writeln('FilePos: ', FilePos(df));

  { Seek to record 3 (0-based) }
  Seek(df, 2);
  Read(df, rec);
  writeln('Record at pos 2: ', rec.name, ' Score=', rec.score);

  { Seek to last record }
  Seek(df, FileSize(df) - 1);
  Read(df, rec);
  writeln('Last record: ', rec.name, ' Score=', rec.score);

  Close(df);
end;

procedure CleanupFiles;
begin
  Assign(tf, 'TEST.TXT');
  Erase(tf);
  if IOResult = 0 then
    writeln('Deleted TEST.TXT');

  Assign(df, 'TEST.DAT');
  Erase(df);
  if IOResult = 0 then
    writeln('Deleted TEST.DAT');
end;

begin
  writeln('=== Text File I/O ===');
  WriteTextFile;
  ReadTextFile;
  writeln;

  writeln('=== Record File I/O ===');
  WriteRecordFile;
  ReadRecordFile;
  writeln;

  writeln('=== Seek Test ===');
  SeekTest;
  writeln;

  writeln('=== Cleanup ===');
  CleanupFiles;
end.
