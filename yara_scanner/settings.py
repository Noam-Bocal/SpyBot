################ Internal settings, usually remains the same! ################
tmp_directory = 'tmp'

# Compiled rules directory
yara_rules_directory = 'yara-rules'
quick_yara_rules_directory = 'quick-yara-rules'
memory_yara_rules_directory = 'memory-yara-rules'

# Uncompiled rules directory (Src). Yara rules in this diectory will be compiled automatically when start
yara_rules_src_directory = 'yara-rules-src'
quick_yara_rules_src_directory = 'quick-yara-rules-src'
memory_yara_rules_src_directory = 'memory-yara-rules-src'

yara_rules_repo_download_urls = [
    {'name': 'red_team_tool_countermeasures',
     'enabled': True,
     'file_type': 'yara',
     'download_url': 'https://raw.githubusercontent.com/fireeye/red_team_tool_countermeasures/master/all-yara.yar',
     'yara_rules_directory_name_in_zip': True
     },
    {'name': 'Neo23x0',
     'enabled': True,
     'file_type': 'zip',
     'download_url': 'https://github.com/Neo23x0/signature-base/archive/master.zip',
     'yara_rules_directory_name_in_zip': 'signature-base-master/yara'
     }
]

# yara_rules_repo_url = 'https://github.com/Neo23x0/signature-base'
# yara_rules_repo_download_url = yara_rules_repo_url + '/archive/master.zip'
# yara_rules_zipped_name = 'signature-base.zip'
# yara_rules_directory_name_in_zip = 'signature-base-master/yara'

yara_matching_timeout = 30  # timeout in seconds
max_file_size = 16777216  # Max file size 16 MB

# time format used across modules [logging, alerts]
date_time_format = '%Y-%m-%d %H:%M:%S'
