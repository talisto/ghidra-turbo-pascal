program ExitTest;
{ Test exit procedures and halt: ExitProc chain, Halt, RunError }
{ Exercises: ExitProc chain pattern common in TP7 programs }

var
  SaveExitProc: pointer;
  ExitCount: integer;

{$F+}
procedure MyExit;
begin
  ExitProc := SaveExitProc;
  writeln('MyExit called! ExitCode=', ExitCode);
  if ErrorAddr <> nil then
  begin
    writeln('Runtime error detected, clearing...');
    ErrorAddr := nil;
  end;
end;
{$F-}

procedure DoWork;
var
  i, sum: integer;
begin
  sum := 0;
  for i := 1 to 100 do
    sum := sum + i;
  writeln('Sum 1..100 = ', sum);
end;

begin
  writeln('=== ExitProc Test ===');
  SaveExitProc := ExitProc;
  ExitProc := @MyExit;

  DoWork;

  writeln('About to exit normally...');
  { Normal exit will trigger MyExit }
end.
