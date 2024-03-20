import os
import common_functions
import settings

module_name = os.path.basename(__file__)

# Excluded rules that causes errors stating an undefined identifier, as stated in
# https://github.com/Neo23x0/signature-base#external-variables-in-yara-rules
excluded_rules_file_list = [
    'generic_anomalies.yar',
    'general_cloaking.yar',
    'thor_inverse_matches.yar',
    'yara_mixed_ext_vars.yar'
]


def init_directories():
    """
    Create temp & Yara rules directories if not exists
    :return:
    """
    if not os.path.isdir(settings.tmp_directory):
        os.makedirs(settings.tmp_directory)

    if not os.path.isdir(settings.yara_rules_directory):
        os.makedirs(settings.yara_rules_directory)


def find_yara_files(path):
    """
    Search for Yara-Rules files path(s) in a given directory path
    :return: List contains yara rules path(s)
    """
    rule_path_list = []

    for root, _, files in os.walk(path):
        for file_name in files:
            if file_name.endswith(('.yar', '.yara')) and file_name not in excluded_rules_file_list:
                rule_path_list.append(os.path.join(root, file_name))

    return rule_path_list


def clean_up():
    common_functions.delete_directory_content(settings.tmp_directory)


def update():
    """
    Update yara-rules in yara_rules_directory by downloading latest files from yara rules github repo yara_rules_repo_url
    :return: True on success, False on fail
    """

    print('[+] Started Yara rules update')
    print('[+] Initializing directories..')
    init_directories()

    try:
        for entry in settings.yara_rules_repo_download_urls:
            try:
                if not entry['enabled']:
                    continue

                print('[+] Fetching signatures from {}'.format(entry['download_url']))

                if entry['file_type'] == 'zip':
                    file_name = entry['name'] + '.zip'
                    save_path = os.path.join(settings.tmp_directory, file_name)
                    common_functions.download(entry['download_url'], save_path)
                    common_functions.extract_zip(save_path, settings.tmp_directory)
                    rules_dir_absolute_path = os.path.abspath(
                        os.path.join(settings.tmp_directory, entry['yara_rules_directory_name_in_zip']))
                    yara_rule_path_list = find_yara_files(rules_dir_absolute_path)

                    if yara_rule_path_list is None or len(yara_rule_path_list) <= 0:
                        print('[-] ERROR: Could not find any yara files that matches the specified in $yara_rules_file_list')
                        continue

                    print('[+] Compiling rules..')
                    common_functions.compile_yara_rules(yara_rule_path_list, settings.yara_rules_directory)

                    half_len = len(yara_rule_path_list) // 2
                    print('[+] Compiling rules for quick directory..')
                    common_functions.compile_yara_rules(yara_rule_path_list[:half_len], settings.quick_yara_rules_directory)

                elif entry['file_type'] == 'yara':
                    file_name = entry['name'] + '.yar'
                    save_path = os.path.join(settings.tmp_directory, file_name)
                    common_functions.download(entry['download_url'], save_path)

                    print('[+] Compiling rules..')
                    common_functions.compile_yara_rules([save_path], settings.yara_rules_directory)

                    print('[+] Compiling rules for quick directory..')
                    common_functions.compile_yara_rules([save_path], settings.quick_yara_rules_directory)
            except Exception as e:
                print('[-] ERROR fetching rules from {} : {}'.format(entry['name'], e))
                continue
    finally:
        print('[+] Cleaning up..')
        clean_up()
        print('[+] Update complete.')
        return True
