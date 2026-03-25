program Strings;
{ Test string operations: concat, copy, length, pos, upcase }
{ Exercises: bp_str_concat, bp_str_copy, bp_str_pos, bp_int_to_str }

var
  s1, s2, s3: string;
  i: integer;
  p: integer;

begin
  s1 := 'Hello';
  s2 := ', World!';
  s3 := s1 + s2;
  writeln('Concatenated: ', s3);
  writeln('Length: ', Length(s3));

  s3 := Copy(s1, 1, 3);
  writeln('Copy(1,3): ', s3);

  p := Pos('World', s1 + s2);
  writeln('Pos of World: ', p);

  Str(42, s1);
  writeln('Str(42): ', s1);

  Val('123', i, p);
  writeln('Val(123): ', i);

  s1 := 'abcdef';
  for i := 1 to Length(s1) do
    s1[i] := UpCase(s1[i]);
  writeln('Uppercase: ', s1);

  { String comparison }
  if 'abc' < 'def' then
    writeln('abc < def: TRUE')
  else
    writeln('abc < def: FALSE');

  { Empty string }
  s1 := '';
  writeln('Empty length: ', Length(s1));

  { Max length string }
  s1 := 'This is a somewhat long string for testing purposes in TP7';
  writeln('Long string: ', s1);

  { Delete and Insert }
  s1 := 'Hello World';
  Delete(s1, 6, 1);
  writeln('After Delete: ', s1);
  Insert('-', s1, 6);
  writeln('After Insert: ', s1);
end.
