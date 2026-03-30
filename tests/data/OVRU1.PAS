{$O+}
unit OvrU1;

interface

procedure Greet(name: String);
function Multiply(a, b: Integer): Integer;
procedure ShowMenu;

implementation

procedure Greet(name: String);
begin
  WriteLn('Hello, ', name, '!');
  WriteLn('Welcome to the overlay test.');
end;

function Multiply(a, b: Integer): Integer;
begin
  Multiply := a * b;
end;

procedure ShowMenu;
begin
  WriteLn('=== Overlay Menu ===');
  WriteLn('1. Option Alpha');
  WriteLn('2. Option Beta');
  WriteLn('3. Option Gamma');
  WriteLn('4. Quit');
  WriteLn('====================');
end;

end.
