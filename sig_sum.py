import argparse
import requests
from pathlib import Path
import yaml
import re


def accept_dir():
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", help="Enter the directory path")
    args = parser.parse_args()
    return (args.directory)

def find_files(directory):
    p = Path(directory)
    files = p.rglob("*.yml")
    file_list = []
    for item in files:
        file_list.append(str(item))
    return file_list

def parse_yaml(file):
    with open(file, 'r') as f:
        data = yaml.full_load(f)
    return data

def summarize(yaml_data, mitre_tags, technique):
    rule_title = yaml_data.get('title')
    alert_severity = yaml_data.get('level')
    rule_source_category = yaml_data.get('logsource').get('category')
    rule_source_product = yaml_data.get('logsource').get('product')
    detection_logic = yaml_data.get('detection')
    return f"title: {rule_title}\nseverity: {alert_severity}\nsource: {rule_source_category} from {rule_source_product}\nMitre Tags: {mitre_tags} Mitre Technique Name(s): {technique}\nDetection: {detection_logic}\n"
    
def collect_tags(yaml_data):
    mitre_tags = yaml_data.get('tags')
    tags_len = len(mitre_tags)
    tags_list = []
    for i in range(tags_len):
        tags_list.append(mitre_tags[i].removeprefix('attack.'))
    return tags_list

def map_mitre(mitre_list):
    tech_list = []
    for i in mitre_list:
        if re.search("t\\d+", i):
            tech_list.append(i)
    return tech_list

def get_mitre():
    try:
        response = requests.get("https://raw.githubusercontent.com/mitre/cti/refs/heads/master/enterprise-attack/enterprise-attack.json")
        response.raise_for_status()
    except requests.exceptions.HTTPError as err:
        return None
    return response.json()

def tech_name():
    data = get_mitre().get('objects')
    dic = {}
    for i in data:
        if i['type'] == "attack-pattern":
            for ref in i.get('external_references', []):
                if ref.get('source_name') == 'mitre-attack':
                    dic[ref.get('external_id')] = i.get('name')
    return dic

def main():
    directory = accept_dir()
    files = find_files(directory)
    mitre_dic = tech_name()
    for i in files:
        yaml_data = (parse_yaml(i))
        mitre_tags = collect_tags(yaml_data)
        tech_list = map_mitre(mitre_tags)
        technique = []
        for i in tech_list:
            tname = mitre_dic.get(i.upper())
            if tname:
                technique.append(tname)
        print(summarize(yaml_data, mitre_tags, technique))
main()


