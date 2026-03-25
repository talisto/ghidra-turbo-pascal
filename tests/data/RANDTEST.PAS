program RandTest;
{ Test random number generation: Random, Randomize, RandSeed }
{ Exercises: bp_random, bp_random_seed, switch/case on random }

var
  i, r: integer;
  counts: array[0..9] of integer;
  oldSeed: longint;

procedure TestFixedSeed;
begin
  writeln('=== Fixed Seed Test ===');
  RandSeed := 12345;
  write('Seed 12345: ');
  for i := 1 to 10 do
    write(Random(100), ' ');
  writeln;

  { Same seed should give same sequence }
  RandSeed := 12345;
  write('Same seed:  ');
  for i := 1 to 10 do
    write(Random(100), ' ');
  writeln;
  writeln;
end;

procedure TestDistribution;
begin
  writeln('=== Distribution Test (10000 rolls of Random(10)) ===');
  for i := 0 to 9 do
    counts[i] := 0;

  RandSeed := 42;
  for i := 1 to 10000 do
  begin
    r := Random(10);
    inc(counts[r]);
  end;

  for i := 0 to 9 do
    writeln('  ', i, ': ', counts[i]:5, ' (', counts[i] div 100, '%)');
  writeln;
end;

procedure TestRandomDecision;
{ Simulates the kind of random branching found in door games }
var
  outcome: integer;
begin
  writeln('=== Random Decision (like a game event) ===');
  RandSeed := 99;

  for i := 1 to 5 do
  begin
    outcome := Random(6);
    write('  Round ', i, ': ');
    case outcome of
      0: writeln('You found gold!');
      1: writeln('A monster attacks!');
      2: writeln('You discover a potion.');
      3: writeln('Nothing happens.');
      4: writeln('You gain experience!');
      5: writeln('A trap springs!');
    end;
  end;
  writeln;
end;

procedure TestRandomRange;
{ Test Random with various ranges }
begin
  writeln('=== Random Range Test ===');
  RandSeed := 7;
  write('Random(2):   ');
  for i := 1 to 20 do
    write(Random(2));
  writeln;

  write('Random(6)+1: ');
  for i := 1 to 20 do
    write(Random(6) + 1);
  writeln;

  write('Random(100): ');
  for i := 1 to 10 do
    write(Random(100):4);
  writeln;
  writeln;
end;

procedure TestBoolRandom;
{ 50/50 chance pattern common in door games }
var
  heads, tails: integer;
begin
  writeln('=== Coin Flip (50/50) Test ===');
  heads := 0;
  tails := 0;
  RandSeed := 123;
  for i := 1 to 1000 do
    if Random(2) = 0 then
      inc(heads)
    else
      inc(tails);
  writeln('  Heads: ', heads, '  Tails: ', tails);
  writeln;
end;

begin
  TestFixedSeed;
  TestDistribution;
  TestRandomDecision;
  TestRandomRange;
  TestBoolRandom;
  writeln('Done.');
end.
