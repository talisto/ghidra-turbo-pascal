program Control;
{ Test control flow: if/else, case, for, while, repeat/until, nested }
{ Exercises: branch structures, loop patterns, nested control flow }

var
  i, j, sum: integer;
  ch: char;
  found: boolean;

begin
  { If/else chain }
  i := 42;
  if i > 100 then
    writeln('greater than 100')
  else if i > 50 then
    writeln('greater than 50')
  else if i > 25 then
    writeln('greater than 25')
  else
    writeln('25 or less');

  { Case statement with ranges }
  i := 7;
  case i of
    1: writeln('one');
    2: writeln('two');
    3..5: writeln('three to five');
    6..10: writeln('six to ten');
  else
    writeln('other');
  end;

  { For loop - counting up }
  sum := 0;
  for i := 1 to 10 do
    sum := sum + i;
  writeln('Sum 1..10 = ', sum);

  { For loop - counting down }
  write('Countdown: ');
  for i := 5 downto 1 do
    write(i, ' ');
  writeln;

  { While loop }
  i := 1;
  sum := 0;
  while i <= 100 do
  begin
    sum := sum + i;
    i := i + 1;
  end;
  writeln('Sum 1..100 = ', sum);

  { Repeat/until }
  i := 1;
  sum := 0;
  repeat
    sum := sum + i * i;
    i := i + 1;
  until i > 10;
  writeln('Sum of squares 1..10 = ', sum);

  { Nested loops }
  writeln('Multiplication table:');
  for i := 1 to 5 do
  begin
    for j := 1 to 5 do
      write(i * j:4);
    writeln;
  end;

  { Boolean logic }
  found := false;
  for i := 1 to 20 do
    if (i mod 3 = 0) and (i mod 5 = 0) then
    begin
      writeln('FizzBuzz: ', i);
      found := true;
    end;
  if not found then
    writeln('No FizzBuzz found');

  { Break simulation (goto) }
  { TP7 doesn't have break, use boolean flag }
  found := false;
  i := 2;
  while (i <= 100) and (not found) do
  begin
    j := 2;
    found := true;
    while j * j <= i do
    begin
      if i mod j = 0 then
      begin
        found := false;
        j := i; { exit inner loop }
      end;
      j := j + 1;
    end;
    if found then
      writeln('First prime >= 2: ', i);
    i := i + 1;
    found := false;
  end;
end.
