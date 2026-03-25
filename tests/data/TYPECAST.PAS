program TypeCast;
{ Test type casting, type coercion, and size boundaries }
{ Exercises: type conversion patterns, boundary checks }

var
  b: byte;
  w: word;
  si: shortint;
  i: integer;
  li: longint;
  c: char;
  bool: boolean;
  r: real;

begin
  writeln('=== Type Sizes ===');
  writeln('SizeOf(byte)     = ', SizeOf(byte));
  writeln('SizeOf(word)     = ', SizeOf(word));
  writeln('SizeOf(shortint) = ', SizeOf(shortint));
  writeln('SizeOf(integer)  = ', SizeOf(integer));
  writeln('SizeOf(longint)  = ', SizeOf(longint));
  writeln('SizeOf(real)     = ', SizeOf(real));
  writeln('SizeOf(boolean)  = ', SizeOf(boolean));
  writeln('SizeOf(char)     = ', SizeOf(char));
  writeln;

  writeln('=== Boundary Values ===');
  b := 0;
  writeln('Byte min:     ', b);
  b := 255;
  writeln('Byte max:     ', b);

  w := 0;
  writeln('Word min:     ', w);
  w := 65535;
  writeln('Word max:     ', w);

  si := -128;
  writeln('ShortInt min: ', si);
  si := 127;
  writeln('ShortInt max: ', si);

  i := -32768;
  writeln('Integer min:  ', i);
  i := 32767;
  writeln('Integer max:  ', i);

  li := -2147483647 - 1;
  writeln('LongInt min:  ', li);
  li := 2147483647;
  writeln('LongInt max:  ', li);
  writeln;

  writeln('=== Type Conversions ===');
  { Integer to longint }
  i := 30000;
  li := longint(i) * 2;
  writeln('30000 * 2 as longint = ', li);

  { Byte to integer }
  b := 200;
  i := b;
  writeln('Byte 200 as integer = ', i);

  { Char to integer (Ord) }
  c := 'A';
  i := Ord(c);
  writeln('Ord(A) = ', i);

  { Integer to char (Chr) }
  c := Chr(66);
  writeln('Chr(66) = ', c);

  { Boolean }
  bool := true;
  writeln('Ord(true) = ', Ord(bool));
  bool := false;
  writeln('Ord(false) = ', Ord(bool));

  { Word/integer boundary interaction }
  w := 40000;
  i := integer(w);
  writeln('Word 40000 as integer = ', i);
  writeln;

  writeln('=== Hi/Lo ===');
  w := $ABCD;
  writeln('Hi($ABCD) = ', Hi(w));
  writeln('Lo($ABCD) = ', Lo(w));
  writeln;

  writeln('=== Swap ===');
  w := $1234;
  writeln('Swap($1234) = $', Swap(w));
  writeln;

  writeln('=== Inc/Dec ===');
  i := 10;
  Inc(i);
  writeln('Inc(10) = ', i);
  Inc(i, 5);
  writeln('Inc(11,5) = ', i);
  Dec(i);
  writeln('Dec(16) = ', i);
  Dec(i, 3);
  writeln('Dec(15,3) = ', i);
end.
