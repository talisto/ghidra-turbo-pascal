program GameSim;
{ Simulates patterns common in BBS door games and LORD IGMs }
{ This is the most important test: exercises string display, }
{ random events, record I/O, stat modification, boundary checks }
{ - all the patterns the decompiler is designed to handle. }

{$I-}

type
  PlayerRec = record
    name: string[30];
    hp, maxhp: integer;
    str, def, cha: integer;
    gold: longint;
    exp: longint;
    level: byte;
    gems: integer;
    alive: boolean;
    forestFight: boolean;
    visited: boolean;
  end;

var
  player: PlayerRec;
  choice: char;
  done: boolean;

procedure InitPlayer;
begin
  player.name := 'TestPlayer';
  player.hp := 100;
  player.maxhp := 100;
  player.str := 10;
  player.def := 10;
  player.cha := 10;
  player.gold := 500;
  player.exp := 0;
  player.level := 1;
  player.gems := 3;
  player.alive := true;
  player.forestFight := false;
  player.visited := false;
end;

procedure StatCheck(var stat: integer; amount: integer; cap: integer);
begin
  stat := stat + amount;
  if stat > cap then
    stat := cap;
  if stat < 0 then
    stat := 0;
end;

procedure ShowStats;
begin
  writeln;
  writeln('  === ', player.name, ' ===');
  writeln('  Level: ', player.level);
  writeln('  HP:    ', player.hp, '/', player.maxhp);
  writeln('  STR:   ', player.str);
  writeln('  DEF:   ', player.def);
  writeln('  CHA:   ', player.cha);
  writeln('  Gold:  ', player.gold);
  writeln('  Exp:   ', player.exp);
  writeln('  Gems:  ', player.gems);
  if player.alive then
    writeln('  Status: Alive')
  else
    writeln('  Status: Dead');
  writeln;
end;

procedure ForestEvent;
var
  outcome: integer;
  amount: integer;
begin
  if player.forestFight then
  begin
    writeln('  You already had a forest fight today.');
    exit;
  end;

  writeln('  You venture into the dark forest...');
  outcome := Random(8);
  case outcome of
    0: begin
         writeln('  You find a bag of gold!');
         amount := Random(100) + 50;
         player.gold := player.gold + amount;
         writeln('  +', amount, ' gold');
       end;
    1: begin
         writeln('  A fairy grants you strength!');
         StatCheck(player.str, 3, 32000);
         writeln('  +3 STR');
       end;
    2: begin
         writeln('  You discover a defensive charm.');
         StatCheck(player.def, 2, 32000);
         writeln('  +2 DEF');
       end;
    3: begin
         writeln('  A monster attacks!');
         amount := Random(20) + 10;
         player.hp := player.hp - amount;
         writeln('  -', amount, ' HP');
         if player.hp <= 0 then
         begin
           player.hp := 0;
           player.alive := false;
           writeln('  You have been slain!');
         end;
       end;
    4: begin
         writeln('  You gain experience from exploring.');
         player.exp := player.exp + longint(player.level) * 100;
         writeln('  +', longint(player.level) * 100, ' EXP');
       end;
    5: begin
         writeln('  A healer restores your health!');
         { Double heal pattern - common in LORD }
         if player.maxhp < 15000 then
           player.hp := player.maxhp * 2
         else
           player.hp := 30000;
         writeln('  HP restored to ', player.hp);
       end;
    6: begin
         writeln('  You find a sparkling gem!');
         if player.gems < 32000 then
         begin
           inc(player.gems);
           writeln('  +1 Gem');
         end
         else
           writeln('  Your gem pouch is full!');
       end;
    7: begin
         writeln('  Nothing happens. The forest is quiet.');
       end;
  end;

  player.forestFight := true;
end;

procedure TavernEvent;
var
  outcome: integer;
  amount: integer;
begin
  writeln('  You enter the tavern...');

  if player.gold < 10 then
  begin
    writeln('  You cannot afford anything here.');
    exit;
  end;

  player.gold := player.gold - 10;
  writeln('  You buy a drink for 10 gold.');

  outcome := Random(5);
  case outcome of
    0: begin
         writeln('  The bartender tells you a secret.');
         StatCheck(player.cha, 1, 32000);
         writeln('  +1 CHA');
       end;
    1: begin
         writeln('  A bard sings of your deeds.');
         player.exp := player.exp + 50;
         writeln('  +50 EXP');
       end;
    2: begin
         writeln('  You arm-wrestle a stranger and win!');
         amount := Random(50) + 10;
         player.gold := player.gold + amount;
         writeln('  +', amount, ' gold');
       end;
    3: begin
         writeln('  A thief picks your pocket!');
         amount := Random(30) + 5;
         if player.gold >= amount then
           player.gold := player.gold - amount
         else
         begin
           amount := player.gold;
           player.gold := 0;
         end;
         writeln('  -', amount, ' gold');
       end;
    4: begin
         writeln('  You rest peacefully. HP restored.');
         player.hp := player.maxhp;
       end;
  end;
end;

procedure LevelUp;
begin
  if player.exp >= longint(player.level) * 1000 then
  begin
    inc(player.level);
    player.maxhp := player.maxhp + 20;
    player.hp := player.maxhp;
    StatCheck(player.str, 2, 32000);
    StatCheck(player.def, 2, 32000);
    writeln('  *** LEVEL UP! You are now level ', player.level, '! ***');
    writeln('  +20 Max HP, +2 STR, +2 DEF');
    player.exp := 0;
  end;
end;

procedure MainMenu;
begin
  writeln;
  writeln('  ============================');
  writeln('  = The Test Adventure Game  =');
  writeln('  ============================');
  writeln;
  writeln('  (F)orest');
  writeln('  (T)avern');
  writeln('  (S)tats');
  writeln('  (Q)uit');
  writeln;
  write('  Your choice: ');
end;

var
  amount: integer;

begin
  { Run with fixed seed for reproducible test output }
  RandSeed := 42;
  InitPlayer;

  writeln('Welcome to The Test Adventure Game!');
  writeln;

  { Simulate a few turns non-interactively }
  writeln('--- Simulating game turns ---');

  { Turn 1: Forest }
  writeln('Turn 1: Forest');
  ForestEvent;
  LevelUp;

  { Reset for next day }
  player.forestFight := false;

  { Turn 2: Tavern }
  writeln('Turn 2: Tavern');
  TavernEvent;
  LevelUp;

  { Turn 3: Forest again }
  writeln('Turn 3: Forest');
  ForestEvent;
  LevelUp;

  player.forestFight := false;

  { Turn 4: Multiple events }
  writeln('Turn 4: Forest');
  ForestEvent;
  LevelUp;

  writeln('Turn 4b: Tavern');
  TavernEvent;
  LevelUp;

  { Show final stats }
  writeln;
  writeln('=== Final Stats ===');
  ShowStats;

  writeln('Game simulation complete.');
end.
