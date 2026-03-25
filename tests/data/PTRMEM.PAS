program PtrMem;
{ Test pointers, dynamic memory, and heap operations }
{ Exercises: New, Dispose, GetMem, FreeMem, pointer arithmetic }

type
  PNode = ^TNode;
  TNode = record
    value: integer;
    next: PNode;
  end;

  PString = ^string;

var
  head, current, temp: PNode;
  ps: PString;
  p: pointer;
  i: integer;
  size: longint;

procedure AddNode(var head: PNode; val: integer);
var
  newNode: PNode;
begin
  New(newNode);
  newNode^.value := val;
  newNode^.next := head;
  head := newNode;
end;

procedure PrintList(head: PNode);
var
  current: PNode;
begin
  current := head;
  write('List: ');
  while current <> nil do
  begin
    write(current^.value, ' ');
    current := current^.next;
  end;
  writeln;
end;

procedure FreeList(var head: PNode);
var
  temp: PNode;
begin
  while head <> nil do
  begin
    temp := head;
    head := head^.next;
    Dispose(temp);
  end;
end;

function ListLength(head: PNode): integer;
var
  count: integer;
begin
  count := 0;
  while head <> nil do
  begin
    inc(count);
    head := head^.next;
  end;
  ListLength := count;
end;

begin
  writeln('=== Linked List Test ===');
  head := nil;

  for i := 1 to 10 do
    AddNode(head, i * 10);

  PrintList(head);
  writeln('Length: ', ListLength(head));
  FreeList(head);
  writeln('Freed list, head=nil: ', head = nil);
  writeln;

  writeln('=== Heap Info ===');
  writeln('MemAvail: ', MemAvail);
  writeln('MaxAvail: ', MaxAvail);
  writeln;

  writeln('=== GetMem/FreeMem Test ===');
  GetMem(p, 1000);
  writeln('Allocated 1000 bytes');
  writeln('MemAvail after alloc: ', MemAvail);
  FreeMem(p, 1000);
  writeln('Freed 1000 bytes');
  writeln('MemAvail after free:  ', MemAvail);
  writeln;

  writeln('=== String on Heap ===');
  New(ps);
  ps^ := 'Hello from the heap!';
  writeln('Heap string: ', ps^);
  Dispose(ps);
  writeln('Disposed heap string');
  writeln;

  writeln('=== Pointer Nil Check ===');
  p := nil;
  if p = nil then
    writeln('Pointer is nil')
  else
    writeln('Pointer is not nil');

  writeln;
  writeln('Done.');
end.
