program CrtTest;
{ Test CRT unit features: GotoXY, colors, ClrScr, window }
{ Exercises: CRT function patterns common in door games }
uses Crt;

var
  i: integer;
  ch: char;

procedure TestColors;
var
  fg, bg: integer;
begin
  writeln('=== Color Test ===');
  for fg := 0 to 15 do
  begin
    TextColor(fg);
    write('Color ', fg:2, ' ');
  end;
  TextColor(LightGray);
  writeln;
  writeln;
end;

procedure TestGotoXY;
begin
  writeln('=== GotoXY Test ===');
  GotoXY(1, WhereY);
  write('At (1,Y)');
  GotoXY(20, WhereY);
  write('At (20,Y)');
  GotoXY(40, WhereY);
  writeln('At (40,Y)');
end;

procedure TestWindow;
begin
  writeln('=== Window Test ===');
  writeln('WhereX=', WhereX, ' WhereY=', WhereY);
  writeln('Testing basic output positioning');
end;

procedure TestDelay;
begin
  writeln('=== Delay Test ===');
  write('Waiting 100ms...');
  Delay(100);
  writeln(' done.');
  write('Waiting 200ms...');
  Delay(200);
  writeln(' done.');
end;

procedure TestKeyboard;
begin
  writeln('=== Keyboard Constants ===');
  writeln('Enter key test skipped (non-interactive)');
end;

procedure TestTextMode;
begin
  writeln('=== Text Mode Info ===');
  writeln('LastMode = ', LastMode);
end;

procedure TestSound;
begin
  writeln('=== Sound Test ===');
  Sound(440);
  Delay(50);
  NoSound;
  writeln('Beeped at 440Hz for 50ms');
end;

begin
  { Don't clear screen - we want to capture output }
  TestColors;
  TestGotoXY;
  TestWindow;
  TestDelay;
  TestKeyboard;
  TestTextMode;
  TestSound;
  TextColor(LightGray);
  TextBackground(Black);
  writeln;
  writeln('All CRT tests complete.');
end.
