import pathlib

import common_functions
import os
import settings
import yara

module_name = os.path.basename(__file__)


def get_file_path_list(root_dir, recursive, filters):
    if recursive:
        return common_functions.recursive_file_scan(root_dir, files_only=True, filters=filters)
    else:
        return common_functions.get_file_set_in_dir(root_dir, files_only=True, filters=filters)


def match_memory(pid, yara_rule_path_list):
    """
    Attempt to match memory content of process with yara rules
    :param pid: process id to read its memory and match it with yara rules
    :param yara_rule_path_list: yara rule(s) path list
    :return: list of dictionaries containing math details for each file
    """
    match_list = []
    mem_path = f"/proc/{pid}/mem"
    for rule_path in yara_rule_path_list:
        try:
            # Convert PosixPath to string for consistency
            if type(rule_path) is pathlib.PosixPath:
                rule_path = rule_path.absolute().as_posix()

            # Load YARA rules from the specified path
            rules = yara.load(rule_path)

            matches = rules.match(mem_path, timeout=settings.yara_matching_timeout)
            if len(matches) > 0:
                        record = {"pid": pid, "yara_rules_file": rule_path, "match_list": matches}
                        match_list.append(record)

        except yara.Error as e:
            # Handle YARA errors, particularly when the file cannot be opened
            if 'could not open file' in str(e):
                break
    return match_list


def match(path_list, yara_rules_path_list):
    """
    Attempt to match file content with yara rules
    :param path_list: list contains path(s) of files to match with yara rules
    :param yara_rules_path_list: yara rule(s) path list
    :return: list of dictionaries containing match details for each file. example: {"file": file_path, "yara_rules_file": rule_path, "match_list": matches}
    """
    # Store matches found
    match_list = []
    count = len(path_list)
    # Loop through each file path in the provided list
    for file_path in path_list:
        print(count, " is left to scan")
        # Convert PosixPath to string for consistency
        if type(file_path) is pathlib.PosixPath:
            file_path = file_path.absolute().as_posix()

        # Skip non-existent files or those flagged for exclusion
        if not os.path.isfile(file_path) or common_functions.should_exclude(file_path):
            continue

        # Loop through each YARA rule path in the provided list
        for rule_path in yara_rules_path_list:
            try:
                # Convert PosixPath to string for consistency
                if type(rule_path) is pathlib.PosixPath:
                    rule_path = rule_path.absolute().as_posix()

                # Load YARA rules from the specified path
                rules = yara.load(rule_path)

                # Get the file size to check against the maximum allowed file size
                file_size = os.path.getsize(file_path)

                # Skip files that exceed the maximum allowed file size
                if file_size > settings.max_file_size:
                    continue

                # Attempt to match
                # Check if the file path contains non-ascii chars, as it may cause errors in Windows environments
                is_ascii_path = common_functions.is_ascii(file_path)
                if not is_ascii_path and os.name == 'nt':
                    with open(file_path, 'rb') as f:
                        # Use YARA's match method with file content as data
                        matches = rules.match(data=f.read(), timeout=settings.yara_matching_timeout)
                else:
                    # Use YARA's match method with the file path directly
                    matches = rules.match(file_path, timeout=settings.yara_matching_timeout)

                # If matches are found, record details and add to the match list
                if len(matches) > 0:
                    record = {"file": file_path, "yara_rules_file": rule_path, "match_list": matches}
                    match_list.append(record)

            except yara.Error as e:
                # Handle YARA errors, particularly when the file cannot be opened
                if 'could not open file' in str(e):
                    break
        count = count - 1

    return match_list


def scan_file(file_path):
    file_path = u"{}".format(file_path)

    if file_path is None or not os.path.isfile(file_path):
        msg = "The provided path '{}' is invalid.".format(file_path)
        print('[-] ERROR: {}'.format(msg))
        raise Exception(msg)

    # Check if there are any rules in yara-rules-src dir and compile them
    common_functions.compile_yara_rules_src_dir()
    try:
        print('[+] Single file scan started')
        yara_rule_path_list = get_file_path_list(settings.yara_rules_directory, True, '*.yar')

        match_list = match([file_path], yara_rule_path_list)
        print('[+] File scan complete.')
        return file_path, match_list

    except Exception as e:
        raise


def scan_directory(directory_path, recursive=False):
    directory_path = u"{}".format(directory_path)

    if directory_path is None or not os.path.isdir(directory_path):
        msg = "The provided path '{}' is invalid.".format(directory_path)
        print('[-] ERROR: {}'.format(msg))
        raise Exception(msg)

    # Check if there are any rules in yara-rules-src dir and compile them
    common_functions.compile_yara_rules_src_dir()

    try:
        print('[+] Directory scan started')
        file_path_list = get_file_path_list(directory_path, recursive, '*')
        print('[+] {} File to process.'.format(len(file_path_list)))
        yara_rule_path_list = get_file_path_list(settings.yara_rules_directory, True, '*.yar')
        match_list = match(file_path_list, yara_rule_path_list)
        print('[+] Directory scan complete.')

        return file_path_list, match_list

    except Exception as e:
        raise


def quick_scan(directory_path):
    directory_path = u"{}".format(directory_path)

    if directory_path is None or not os.path.isdir(directory_path):
        msg = "The provided path '{}' is invalid.".format(directory_path)
        print('[-] ERROR: {}'.format(msg))
        raise Exception(msg)

    # Check if there are any rules in yara-rules-src dir and compile them
    common_functions.compile_quick_yara_rules_src_dir()

    try:
        print('[+] Quick scan started')
        file_path_list = get_file_path_list(directory_path, True, '*')
        print('[+] {} File to process.'.format(len(file_path_list)))
        yara_rule_path_list = get_file_path_list(settings.quick_yara_rules_directory, True, '*.yar')
        match_list = match(file_path_list, yara_rule_path_list)
        print('[+] Quick scan complete.')

        return file_path_list, match_list

    except Exception as e:
        raise


def scan_memory(pid):
    if (int)(pid) < 0 or not os.path.exists(f"/proc/{pid}"):
        msg = "The provided PID '{}' is invalid.".format(pid)
        print('[-] ERROR: {}'.format(msg))
        raise Exception(msg)
    # Check if there are any rules in yara-rules-src dir and compile them
    common_functions.compile_yara_rules_src_dir()

    try:
        print('[+] Memory scan started')
        yara_rule_path_list = get_file_path_list(settings.yara_rules_directory, True, "*.yar")
        match_list = match_memory(pid, yara_rule_path_list)
        print('[+] Memory scan complete.')

        return pid, match_list

    except Exception as e:
        raise


def combine_file_path_list_with_dir(file_list, dir_path):
    file_path_set = set()
    for file_path in file_list:
        if file_path is None:
            continue
        full_path = dir_path + file_path
        if os.path.isfile(full_path):
            file_path_set.add(full_path)

    return file_path_set
