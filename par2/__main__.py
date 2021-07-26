from argparse import ArgumentParser

from par2 import Par2


def ls():
    parser = ArgumentParser(description='List files that can be recovered from a Par2 file')
    parser.add_argument('files', type=str, nargs='+',
                        help='The par 2 File(s) to examine')
    args = parser.parse_args()
    for file in args.files:
        print(f"{file}:")
        try:
            par2_parser = Par2(file)
        except Exception as e:
            print(f"  Unable to parse file: {e}")
            continue
        for recovery_set in par2_parser.recovery_sets.values():
            for recoverable_file in recovery_set.files:
                print(f"  {recoverable_file}")


if __name__ == '__main__':
    ls()
