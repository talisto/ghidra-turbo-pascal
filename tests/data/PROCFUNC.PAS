program ProcFunc;
{ Test procedures/functions: value/var params, recursion, nested }
{ Exercises: stack frames, parameter passing, far calls }

{$F+}

type
  IntArray = array[1..10] of integer;

var
  arr: IntArray;
  i, result: integer;

{ Simple procedure with value parameter }
procedure PrintValue(x: integer);
begin
  writeln('Value: ', x);
end;

{ Procedure with var parameter (pass by reference) }
procedure DoubleIt(var x: integer);
begin
  x := x * 2;
end;

{ Function returning integer }
function Square(x: integer): integer;
begin
  Square := x * x;
end;

{ Function returning longint }
function Factorial(n: integer): longint;
begin
  if n <= 1 then
    Factorial := 1
  else
    Factorial := longint(n) * Factorial(n - 1);
end;

{ Nested procedure }
procedure Outer(a: integer);
  procedure Inner(b: integer);
  begin
    writeln('  Inner: a=', a, ' b=', b, ' a+b=', a + b);
  end;
begin
  writeln('Outer: a=', a);
  Inner(a * 2);
  Inner(a * 3);
end;

{ Procedure with array parameter }
procedure FillArray(var arr: IntArray; start, count: integer);
var
  i: integer;
begin
  for i := 1 to count do
    arr[i] := start + i - 1;
end;

procedure PrintArray(var arr: IntArray; count: integer);
var
  i: integer;
begin
  write('Array: ');
  for i := 1 to count do
    write(arr[i]:4);
  writeln;
end;

{ Function with string parameter }
function CountChars(s: string; ch: char): integer;
var
  i, count: integer;
begin
  count := 0;
  for i := 1 to Length(s) do
    if s[i] = ch then
      inc(count);
  CountChars := count;
end;

{ Procedure with multiple out parameters }
procedure MinMax(var arr: IntArray; count: integer;
                 var minVal, maxVal: integer);
var
  i: integer;
begin
  minVal := arr[1];
  maxVal := arr[1];
  for i := 2 to count do
  begin
    if arr[i] < minVal then minVal := arr[i];
    if arr[i] > maxVal then maxVal := arr[i];
  end;
end;

var
  x, mn, mx: integer;

begin
  { Value parameter }
  PrintValue(42);

  { Var parameter }
  x := 10;
  DoubleIt(x);
  writeln('After DoubleIt(10): ', x);

  { Function calls }
  writeln('Square(7) = ', Square(7));
  writeln('Factorial(10) = ', Factorial(10));

  { Nested procedures }
  Outer(5);

  { Array operations }
  FillArray(arr, 10, 10);
  PrintArray(arr, 10);

  { String function }
  writeln('Count of l in Hello: ', CountChars('Hello World', 'l'));

  { Multiple return values via var params }
  MinMax(arr, 10, mn, mx);
  writeln('Min=', mn, ' Max=', mx);
end.
