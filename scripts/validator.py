import os
import sys
import yaml
import json
from itertools import chain
from colorama import Fore

path = os.environ["INPUT_MYINPUT"]
valid_translate = yaml.safe_load(open(os.path.join(path, "scripts/stream_translate_guide.yaml")))
valid_annotate = ['Action', 'Reason', 'Status', 'Stream', 'Vector', 'AuthProto', 'User', 'Threat', 'Query', 'QueryType', 'Event', 'Category', 'EventName', 'Config', 'Role']
extractor_path = os.path.join(path, "extractors")

def main():
    valid_flag = True
    for root, subdirs, files in os.walk(extractor_path):
        for file in files:
            if (file.endswith(".yml") or file.endswith(".yaml")):
                yaml_path = f'{root}/{file}'
                try:
                    with open(yaml_path, 'r') as f:
                        parser = yaml.safe_load(f)
                        validate_dct = {'schema-version': None,
                                        'extractor-id': None,
                                        'source-name': None,
                                        'source-type': None,
                                        'source-description': None,
                                        'provides-streams': None,
                                        'master-filters': None,
                                        'event-details': None}
                        ext_id = int(parser['extractor-id'])
                        validate_dct.update(parser)
                        missing_keys = [k for k, v in validate_dct.items() if not v]
                        # Validating top level keys in parser
                        if missing_keys:
                            print(Fore.RED + f"{file} - ExtractorID - {ext_id}: Missing keys : {missing_keys}")
                            valid_flag = False
                        elif validate_dct['master-filters'] and isinstance(validate_dct['master-filters'], list):
                            ed = validate_dct['event-details']
                            for i in ed:
                                ed_validate = {'first-match': None,
                                               'decoder': None,
                                               'decoder-regex': None,
                                               'event-key-format': None,
                                               'event-key-mapping': None,
                                               'fallback': None
                                               }
                                ed_validate.update(i)
                                if ed_validate['decoder'] == 'json':
                                    ed_validate['decoder-regex'] = 'json'

                                # Validating decoder type
                                if ed_validate['decoder'] not in ['custom', 'json', 'regex']:
                                    print(Fore.RED + f"{file} - ExtractorID - {ext_id}: Invalid decoder found: '{ed_validate['decoder']}' Expected: 'custom' or 'json' or'regex'")
                                    valid_flag = False
                                # Validating keys at event-details level
                                ed_missing_keys = [k for k, v in validate_dct.items() if not v]
                                if ed_missing_keys:
                                    print(Fore.RED + f"{file} - ExtractorID - {ext_id}: Missing keys in 'event-details' section for first match - {i['first-match']}: {ed_missing_keys}")
                                    valid_flag = False
                                else:
                                    fallback_keys = ed_validate['fallback'].keys()
                                    globals_keys = ed_validate.get('globals', {})

                                    tmp_dct = dict()
                                    tmp_dct['fallback'] = fallback_keys
                                    if globals_keys:
                                        tmp_dct['globals'] = globals_keys.keys()
                                    for k, v in ed_validate['event-key-mapping'].items():
                                        tmp_dct[k] = v.keys()

                                    # Validating keys annotate and translate in event-key-mapping
                                    for k, v in tmp_dct.items():
                                        if 'annotate' in v or 'translate' in v:
                                            continue
                                        else:
                                            print(Fore.RED + f"{file} - ExtractorID - {ext_id}: Keys 'annotate/translate' missing for key '{k}' in first-match {i['first-match']}")
                                            valid_flag = False
                                # Validating mappings Stream wise
                                fm = i['event-key-mapping']
                                for k, v in fm.items():
                                    annotate_list = [x for x in chain(fm[k]["annotate"].keys()) if x]
                                    for m in annotate_list:
                                        if m not in valid_annotate:
                                            print(Fore.RED + f"{file} - ExtractorID - {ext_id}: Unexpected field '{m}' for stream '{fm[k]['annotate']['Stream']}' located at 'annotate' key '{k}' in first-match '{i['first-match']}'")
                                            valid_flag = False
                                    translate_list = [x for x in chain(fm[k]["translate"].values()) if x]
                                    if fm[k]["annotate"]["Stream"] in valid_translate:
                                        for n in translate_list:
                                            if n not in valid_translate[fm[k]["annotate"]["Stream"]]:
                                                print(Fore.RED + f"{file} - ExtractorID - {ext_id}: Unexpected field '{n}' for stream '{fm[k]['annotate']['Stream']}' located at 'translate' key '{k}' at first-match '{i['first-match']}'")
                                                valid_flag = False
                                    else:
                                        print(Fore.RED + f"{file} - ExtractorID - {ext_id}: Guide for the stream: '{fm[k]['annotate']['Stream']}' is not defined located at first-match '{i['first-match']}")
                                        valid_flag = False
                except Exception as e:
                    print(Fore.RED + f"[-] The yaml is invalid for file {file}: {e}")
                    valid_flag = False

    if valid_flag:
        print(Fore.GREEN + "[+] All files are validated successfully")
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
