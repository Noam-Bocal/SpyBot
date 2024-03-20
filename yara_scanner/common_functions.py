import os
import glob
import zipfile
import urllib.request
import shutil
import yara
from datetime import datetime
import fnmatch
import exclude
import settings

# Get the module name (current file's base name)
module_name = os.path.basename(__file__)


# Function to find a file with a specific name in a given path
def find_files(name, path):
    for root, dirs, files in os.walk(path):
        if name in files:
            full_path = u"{}".format(os.path.join(root, name))
            return full_path


# Function to check if one path is a parent of another path
def path_is_parent(parent_path, child_path):
    parent_path = os.path.abspath(parent_path)
    child_path = os.path.abspath(child_path)
    return os.path.commonpath([parent_path]) == os.path.commonpath([parent_path, child_path])


# Function to check if a string contains only ASCII characters
def is_ascii(s):
    return all(ord(c) < 128 for c in s)


# Function to check if a file or path should be excluded based on predefined criteria
def should_exclude(path):
    for p in exclude.excluded_path_list:
        if path_is_parent(p, path):
            return True

    # Check file extension
    for ext in exclude.excluded_file_extensions:
        if path.lower().endswith(ext):
            return True

    return False


# Function to get a set of files in a directory based on filters
def get_file_set_in_dir(dir_path, files_only, filters=None):
    root_dir_path = u"{}".format(dir_path)
    file_path_set = set()
    if filters is None:
        filters = '*'

    for path in glob.glob(os.path.join(root_dir_path, filters)):
        path = u"{}".format(path)
        if files_only:
            if os.path.isfile(path):
                file_path_set.add(path)
        else:
            file_path_set.add(path)

    return file_path_set


# Function to recursively scan for files based on filters
def recursive_file_scan(root_dir_path, files_only, filters):
    root_dir_path = u"{}".format(root_dir_path)
    file_path_set = set()

    if filters is None or filters == "":
        filters = '*'

    for root, dirnames, filenames in os.walk(root_dir_path):
        for filename in fnmatch.filter(filenames, filters):
            file_path = os.path.join(root, filename)
            file_path = u"{}".format(file_path)
            if files_only:
                if not os.path.isfile(file_path):
                    continue
            file_path_set.add(file_path)

    return file_path_set


# Function to delete the content of a directory
def delete_directory_content(dir_path):
    for file in os.listdir(dir_path):
        file_path = os.path.join(dir_path, file)
        file_path = u"{}".format(file_path)

        try:
            if os.path.isfile(file_path):
                os.unlink(file_path)
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)
        except Exception as e:
            print('[-] ERROR {}'.format(e))
            continue


# Function to download a file from a given URL to a specified path
def download(url, path):
    with urllib.request.urlopen(url) as response, open(path, 'wb') as out_file:
        shutil.copyfileobj(response, out_file)


# Function to extract files from a zip archive
def extract_zip(zip_file_path, directory_to_extract_to):
    if not os.path.isfile(zip_file_path):
        return

    with zipfile.ZipFile(zip_file_path) as zf:
        zf.extractall(directory_to_extract_to)


# Function to compile YARA rules from source files to destination directory
def compile_yara_rules(yara_rule_path_list, save_directory):
    for path in yara_rule_path_list:
        try:
            # Form the save path by joining the save directory with the base name of the YARA rule file
            save_path = os.path.join(save_directory, os.path.basename(path))

            # Compile the YARA rule and save it to the specified destination
            compiled = yara.compile(filepath=path, includes=True)
            compiled.save(save_path)
        except Exception as e:
            continue


# Function to compile YARA rules from the source directory to the destination directory
def compile_yara_rules_src_dir():
    dir = os.path.abspath(settings.yara_rules_src_directory)
    # Get a set of YARA rule files in the source directory with a '.yar' extension
    path_list = get_file_set_in_dir(dir, True, "*.yar")

    if get_file_set_in_dir is None or len(path_list) < 1:
        return

    # Compile the YARA rules obtained from the source directory and save them to the destination directory
    compile_yara_rules(path_list, settings.yara_rules_directory)


def compile_quick_yara_rules_src_dir():
    dir = os.path.abspath(settings.quick_yara_rules_src_directory)

    # Get a set of YARA rule files in the source directory with a '.yar' extension
    path_list = get_file_set_in_dir(dir, True, "*.yar")

    if get_file_set_in_dir is None or len(path_list) < 1:
        return

    # Compile the YARA rules obtained from the source directory and save them to the destination directory
    compile_yara_rules(path_list, settings.quick_yara_rules_directory)


# Function to write content to a file
def write_to_file(file_path, content):
    with open(file_path, mode='w', encoding='utf8') as file:
        file.write(content)


# Function to open a file for reading
def open_file(file_path):
    try:
        return open(file_path, "r")
    except IOError as e:
        print('[-] ERROR {}'.format(e))
        return None


# Function to close a file
def close_file(file_stream):
    try:
        file_stream.close()
        return True
    except IOError as e:
        print('[-] ERROR {}'.format(e))
        return False


# Function to read all lines from a file
def read_file_lines(file_path):
    with open(file_path) as fp:
        return fp.readlines()


# Function to get the current date and time in the specified format
def get_datetime():
    return datetime.now().strftime(settings.date_time_format)


# Function to get the last X lines from a file (tail)
def tail(file_path, lines=1, _buffer=4098):
    lines_found = []
    block_counter = -1

    f = open_file(file_path)

    while len(lines_found) < lines:
        try:
            f.seek(block_counter * _buffer, os.SEEK_END)
        except IOError:
            f.seek(0)
            lines_found = f.readlines()
            break

        lines_found = f.readlines()
        block_counter -= 1

    close_file(f)
    return lines_found[-lines:]
