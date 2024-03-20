import sys
import yara_updater
import yara_scanner
import report_generator
import argparse
import time


def run_scanner(args):
    global match_result
    start_time = time.time()
    try:
        is_recursive = args.recursive
        if args.scan_dir:
            match_result = yara_scanner.scan_directory(args.scan_dir.strip(), is_recursive)
        elif args.quick:
            match_result = yara_scanner.quick_scan(args.quick.strip())
        elif args.scan_file:
            match_result = yara_scanner.scan_file(args.scan_file.strip())
        elif args.scan_memory:
            match_result = yara_scanner.scan_memory(args.scan_memory.strip())

    except KeyboardInterrupt:
        print("Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print("Error occurred:", e)
    end_time = time.time()
    # Generate report
    print("[+] Time elapsed: {:.2f} second".format(end_time - start_time))
    report = report_generator.generate_report(match_result)
    print(report)


def main():
    arg_parser = argparse.ArgumentParser(description="Yara Scanner")

    # Add command-line arguments
    arg_parser.add_argument("--scan-dir", help="Path to the directory to be scanned")
    arg_parser.add_argument("--quick", help="Path to the directory to be scanned")
    arg_parser.add_argument("--scan-file", help="Path to the file to be scanned")
    arg_parser.add_argument("--scan-memory", help="PID of the process to be scanned")
    arg_parser.add_argument("--recursive", action="store_true", help="Scan subdirectories (only applicable with --scan-dir)")
    arg_parser.add_argument("--update", action="store_true", help="Update Yara rules")

    args = arg_parser.parse_args()

    try:
        if args.update:
            yara_updater.update()
        elif args.scan_dir or args.quick or args.scan_file or args.scan_memory:
            run_scanner(args)
        else:
            print("No action specified. Please provide a scan directory, quick scan directory, or scan file.")
            arg_parser.print_help()

    except KeyboardInterrupt:
        print("Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print("Error occurred:", e)


if __name__ == "__main__":
    main()
