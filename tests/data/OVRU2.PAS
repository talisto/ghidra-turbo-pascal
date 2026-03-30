{$O+}
unit OvrU2;

interface

function Factorial(n: Integer): LongInt;
procedure PrintStats(hp, mp, level: Integer);
function IsPrime(n: Integer): Boolean;

implementation

function Factorial(n: Integer): LongInt;
var
  result: LongInt;
  i: Integer;
begin
  result := 1;
  for i := 2 to n do
    result := result * i;
  Factorial := result;
end;

procedure PrintStats(hp, mp, level: Integer);
begin
  WriteLn('--- Character Stats ---');
  WriteLn('  HP:    ', hp);
  WriteLn('  MP:    ', mp);
  WriteLn('  Level: ', level);
  WriteLn('  Power: ', hp + mp * level);
  WriteLn('-----------------------');
end;

function IsPrime(n: Integer): Boolean;
var
  i: Integer;
begin
  if n < 2 then
  begin
    IsPrime := False;
    Exit;
  end;
  IsPrime := True;
  for i := 2 to n - 1 do
    if n mod i = 0 then
    begin
      IsPrime := False;
      Exit;
    end;
end;

end.
