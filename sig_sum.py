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
    list = []
    for item in files:
        list.append(str(item))
    return list

def parse_yaml(file):
    with open(file, 'r') as f:
        data = yaml.full_load(f)
    return data

def summarize(yaml, mitre_tags, technique):
    rule_title = yaml.get('title')
    alert_severity = yaml.get('level')
    rule_source_category = yaml.get('logsource').get('category')
    rule_source_product = yaml.get('logsource').get('product')
    detection_logic = yaml.get('detection')
    return f"title: {rule_title}\nseverity: {alert_severity}\nsource: {rule_source_category} from {rule_source_product}\nMitre Tags: {mitre_tags} Mitre Technique Name(s): {technique}\nDetection: {detection_logic}\n"
    
def collect_tags(yaml):
    mitre_tags = yaml.get('tags')
    tags_len = len(mitre_tags)
    tags_list = []
    for i in range(tags_len):
        tags_list.append(mitre_tags[i].removeprefix('attack.'))
    return tags_list

def map_mitre(mitre_list):
    tech_list = []
    for i in mitre_list:
        m = i.removeprefix('attack.')
        if re.search("t\\d+", m):
            tech_list.append(m)
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
            ext_ref = i.get('external_references')[0]
            key = ext_ref.get('external_id')
            value = i.get('name')
            dic[key] = value
    return dic

def main():
    directory = accept_dir()
    files = find_files(directory)
    mitre_dic = tech_name()
    for i in files:
        yaml = (parse_yaml(i))
        mitre_tags = collect_tags(yaml)
        tech_list = map_mitre(mitre_tags)
        technique = []
        for i in tech_list:
            for key, value in mitre_dic.items():
                if i.upper() == key:
                    technique.append(value)
        print(summarize(yaml, mitre_tags, technique))
main()


