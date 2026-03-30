program OvrTest;
{
  OVRTEST.PAS — Overlay test program for BPdecompiler test suite.

  Demonstrates Borland Pascal VROOMM overlay system with two
  overlay units. Compile with TPC to produce OVRTEST.EXE + OVRTEST.OVR.

  Compilation (in DOSBox with Turbo Pascal 7):
    TPC OVRTEST.PAS

  Both OVRU1.PAS and OVRU2.PAS must be in the same directory.
  The compiler will produce:
    OVRTEST.EXE  — main executable with INT 3F stubs
    OVRTEST.OVR  — FBOV overlay file containing OvrU1 + OvrU2 code
}

uses
  Overlay, OvrU1, OvrU2;

{$O OvrU1}
{$O OvrU2}

var
  i: Integer;
  choice: Char;
  fact: LongInt;

begin
  { Initialize the overlay manager }
  OvrInit('OVRTEST.OVR');
  if OvrResult <> ovrOk then
  begin
    WriteLn('Overlay initialization failed! Error: ', OvrResult);
    Halt(1);
  end;
  WriteLn('Overlay system initialized successfully.');

  { Call functions from OvrU1 (first overlay segment) }
  Greet('Player');
  WriteLn;

  WriteLn('Multiply(6, 7) = ', Multiply(6, 7));
  WriteLn;

  ShowMenu;
  WriteLn;

  { Call functions from OvrU2 (second overlay segment) }
  for i := 1 to 10 do
  begin
    fact := Factorial(i);
    WriteLn(i, '! = ', fact);
  end;
  WriteLn;

  PrintStats(100, 50, 5);
  WriteLn;

  WriteLn('Primes up to 20:');
  for i := 2 to 20 do
    if IsPrime(i) then
      Write(i, ' ');
  WriteLn;

  WriteLn;
  WriteLn('Overlay test complete.');
end.
