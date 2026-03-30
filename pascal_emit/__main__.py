"""CLI entry point: python -m pascal_emit <decompiled.c> [-o output.pas]"""
import sys
from .pipeline import process


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 -m pascal_emit <decompiled.c> [-o output.pas]")
        sys.exit(1)

    output_path = None
    paths = []
    i = 1
    while i < len(sys.argv):
        if sys.argv[i] == '-o' and i + 1 < len(sys.argv):
            output_path = sys.argv[i + 1]
            i += 2
        else:
            paths.append(sys.argv[i])
            i += 1

    for path in paths:
        process(path, output_path=output_path)


if __name__ == '__main__':
    main()
