def generate_report(matches_list):
    virus_files = [match_info['file'] for match_info in matches_list[1] if match_info and match_info['match_list']]

    match_dict = {}

    # Handling the case when there's only one file to scan
    if isinstance(matches_list[0], str):
        if len(virus_files) >= 1:
            match_dict[matches_list[0]] = 1
        else:
            match_dict[matches_list[0]] = 0
    else:
        for match_key in matches_list[0]:
            match_dict[match_key] = 1 if any(match_key in virus_file for virus_file in virus_files) else 0

    return match_dict







