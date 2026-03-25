program Records;
{ Test records and typed constants: record types, with statement }
{ Exercises: memory layout, field access patterns, typed constants }

type
  PlayerRec = record
    name: string[20];
    hp, maxhp: integer;
    gold: longint;
    level: byte;
    alive: boolean;
  end;

  ItemRec = record
    name: string[15];
    value: integer;
    weight: byte;
  end;

const
  MaxItems = 5;

var
  player: PlayerRec;
  items: array[1..MaxItems] of ItemRec;
  i: integer;

procedure InitPlayer(var p: PlayerRec; n: string);
begin
  p.name := n;
  p.hp := 100;
  p.maxhp := 100;
  p.gold := 0;
  p.level := 1;
  p.alive := true;
end;

procedure ShowPlayer(var p: PlayerRec);
begin
  writeln('=== Player Info ===');
  writeln('Name:  ', p.name);
  writeln('HP:    ', p.hp, '/', p.maxhp);
  writeln('Gold:  ', p.gold);
  writeln('Level: ', p.level);
  if p.alive then
    writeln('Status: Alive')
  else
    writeln('Status: Dead');
  writeln;
end;

procedure DamagePlayer(var p: PlayerRec; amount: integer);
begin
  p.hp := p.hp - amount;
  if p.hp <= 0 then
  begin
    p.hp := 0;
    p.alive := false;
    writeln(p.name, ' has been slain!');
  end
  else
    writeln(p.name, ' takes ', amount, ' damage. HP: ', p.hp);
end;

procedure HealPlayer(var p: PlayerRec; amount: integer);
begin
  p.hp := p.hp + amount;
  if p.hp > p.maxhp then
    p.hp := p.maxhp;
  writeln(p.name, ' healed for ', amount, '. HP: ', p.hp);
end;

procedure AddGold(var p: PlayerRec; amount: longint);
begin
  p.gold := p.gold + amount;
  writeln(p.name, ' gained ', amount, ' gold. Total: ', p.gold);
end;

procedure InitItems;
begin
  items[1].name := 'Sword';
  items[1].value := 100;
  items[1].weight := 5;

  items[2].name := 'Shield';
  items[2].value := 75;
  items[2].weight := 8;

  items[3].name := 'Potion';
  items[3].value := 25;
  items[3].weight := 1;

  items[4].name := 'Ring';
  items[4].value := 200;
  items[4].weight := 0;

  items[5].name := 'Armor';
  items[5].value := 150;
  items[5].weight := 15;
end;

procedure ShowItems;
var
  i: integer;
begin
  writeln('=== Items ===');
  writeln('Name':16, 'Value':8, 'Weight':8);
  writeln('----':16, '-----':8, '------':8);
  for i := 1 to MaxItems do
    with items[i] do
      writeln(name:16, value:8, weight:8);
  writeln;
end;

begin
  InitPlayer(player, 'TestHero');
  ShowPlayer(player);

  DamagePlayer(player, 30);
  HealPlayer(player, 15);
  AddGold(player, 1000);
  AddGold(player, 50000);
  ShowPlayer(player);

  DamagePlayer(player, 200);
  ShowPlayer(player);

  InitItems;
  ShowItems;

  { Test with statement }
  with player do
  begin
    name := 'Revived';
    hp := 50;
    maxhp := 200;
    alive := true;
    level := 5;
  end;
  ShowPlayer(player);
end.
