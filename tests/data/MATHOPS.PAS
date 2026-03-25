program MathOps;
{ Test arithmetic: integer, longint, 32-bit operations, div, mod }
{ Exercises: 16-bit and 32-bit arithmetic, carry propagation }

var
  a, b, c: integer;
  la, lb, lc: longint;
  r: real;

begin
  { Basic integer arithmetic }
  a := 100;
  b := 37;
  c := a + b;
  writeln('100 + 37 = ', c);
  c := a - b;
  writeln('100 - 37 = ', c);
  c := a * b;
  writeln('100 * 37 = ', c);
  c := a div b;
  writeln('100 div 37 = ', c);
  c := a mod b;
  writeln('100 mod 37 = ', c);

  { Negative numbers }
  a := -50;
  b := 25;
  writeln('-50 + 25 = ', a + b);
  writeln('-50 * 25 = ', a * b);

  { Longint (32-bit) arithmetic }
  la := 100000;
  lb := 200000;
  lc := la + lb;
  writeln('100000 + 200000 = ', lc);
  lc := la * 3;
  writeln('100000 * 3 = ', lc);
  lc := lb div 7;
  writeln('200000 div 7 = ', lc);

  { Large values near int16 limits }
  a := 32000;
  b := 700;
  writeln('32000 + 700 = ', longint(a) + longint(b));

  { Overflow on purpose with longint }
  la := 2000000000;
  lb := 100000000;
  lc := la + lb;
  writeln('2000000000 + 100000000 = ', lc);

  { Real arithmetic }
  r := 355.0 / 113.0;
  writeln('355/113 = ', r:10:6);

  { Bit operations }
  a := $FF;
  b := $0F;
  writeln('$FF and $0F = ', a and b);
  writeln('$FF or  $0F = ', a or b);
  writeln('$FF xor $0F = ', a xor b);
  writeln('not $0F = ', not b);
  writeln('$0F shl 4 = ', b shl 4);
  writeln('$FF shr 4 = ', a shr 4);

  { Absolute value }
  a := -42;
  writeln('Abs(-42) = ', Abs(a));

  { Sqr }
  a := 7;
  writeln('Sqr(7) = ', Sqr(a));
end.
