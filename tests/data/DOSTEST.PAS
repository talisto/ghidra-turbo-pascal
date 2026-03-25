program DosTest;
{ Test DOS unit features: environment, date/time, exec }
{ Exercises: DOS interrupt patterns, register passing }
uses Dos;

var
  year, month, day, dow: word;
  hour, minute, second, sec100: word;
  sr: SearchRec;
  envVal: string;
  i: integer;
  regs: Registers;

begin
  writeln('=== Date and Time ===');
  GetDate(year, month, day, dow);
  writeln('Date: ', year, '-', month, '-', day);
  write('Day of week: ');
  case dow of
    0: writeln('Sunday');
    1: writeln('Monday');
    2: writeln('Tuesday');
    3: writeln('Wednesday');
    4: writeln('Thursday');
    5: writeln('Friday');
    6: writeln('Saturday');
  end;

  GetTime(hour, minute, second, sec100);
  writeln('Time: ', hour, ':', minute, ':', second, '.', sec100);
  writeln;

  writeln('=== DOS Version ===');
  writeln('Version: ', Lo(DosVersion), '.', Hi(DosVersion));
  writeln;

  writeln('=== Environment ===');
  writeln('EnvCount: ', EnvCount);
  for i := 1 to EnvCount do
  begin
    if i <= 5 then
      writeln('  Env[', i, ']: ', EnvStr(i));
  end;
  envVal := GetEnv('PATH');
  if envVal <> '' then
    writeln('PATH: ', Copy(envVal, 1, 60), '...')
  else
    writeln('PATH not found');
  writeln;

  writeln('=== File Search ===');
  FindFirst('*.PAS', Archive, sr);
  while DosError = 0 do
  begin
    writeln('  Found: ', sr.Name, ' (', sr.Size, ' bytes)');
    FindNext(sr);
  end;
  writeln;

  writeln('=== Disk Info ===');
  writeln('DiskFree(0): ', DiskFree(0), ' bytes');
  writeln('DiskSize(0): ', DiskSize(0), ' bytes');
  writeln;

  writeln('=== ParamCount/ParamStr ===');
  writeln('ParamCount: ', ParamCount);
  writeln('ParamStr(0): ', ParamStr(0));
  for i := 1 to ParamCount do
    writeln('ParamStr(', i, '): ', ParamStr(i));
  writeln;

  writeln('Done.');
end.
