import re
import os
from collections import defaultdict
from jinja2 import Environment, FileSystemLoader
from github import Github
from decouple import config
from collections import defaultdict


# # Load environment variables
# GITHUB_TOKEN = config('GITHUB_TOKEN')
# REPO_NAME = 'your-repo-name'
# BRANCH_NAME = 'new-template-branch'

# Initialize Jinja2 environment
env = Environment(
    loader=FileSystemLoader('.'),
    trim_blocks=True,
    lstrip_blocks=True
)

IGNORED_ACLS = [
    'localhost'
]

IGNORED_RULES = [
    'http_access allow localhost manager',
    'http_access deny manager',
    'http_access deny to_localhost',
    'http_access deny all'
]


# def group_rules(rules):
#     grouped = defaultdict(
#         lambda: {
#             "rule_type": None,
#             "action": None,
#             "SRC": {"type": "src", "vals": []},
#             "DST": {"type": "dst", "vals": []},
#             "DST_port": {"type": "port", "vals": []},
#             "HTTP_method": {"type": "method", "vals": []},
#             "command": {"type": "command", "vals": []},
#         }
#     )

#     for rule in rules:
#         # Key for grouping
#         key = (
#             rule.get("rule_type"),
#             rule.get("action"),
#             tuple(sorted(rule.get("SRC", {}).get("vals", []))),
#             tuple(sorted(rule.get("DST", {}).get("vals", []))),
#             tuple(rule.get("DST_port", {}).get("vals", [])),
#             tuple(rule.get("command", {}).get("vals", [])),
#         )

#         # Add values to the grouped dictionary
#         grouped[key]["rule_type"] = rule.get("rule_type")
#         grouped[key]["action"] = rule.get("action")

#         # Merge SRC and DST 'vals' lists
#         grouped[key]["SRC"]["vals"] = sorted(set(grouped[key]["SRC"]["vals"] + rule.get("SRC", {}).get("vals", [])))
#         grouped[key]["DST"]["vals"] = sorted(set(grouped[key]["DST"]["vals"] + rule.get("DST", {}).get("vals", [])))

#         # Merge DST_port, HTTP_method, and command values
#         grouped[key]["DST_port"]["vals"] = sorted(set(grouped[key]["DST_port"]["vals"] + rule.get("DST_port", {}).get("vals", [])))
#         grouped[key]["HTTP_method"]["vals"] = sorted(set(grouped[key]["HTTP_method"]["vals"] + rule.get("HTTP_method", {}).get("vals", [])))
#         grouped[key]["command"]["vals"] = sorted(set(grouped[key]["command"]["vals"] + rule.get("command", {}).get("vals", [])))


#     # Remove duplicates by converting lists to sets and back to sorted lists
#     for group in grouped.values():
#         group["SRC"]["vals"] = sorted(set(group["SRC"]["vals"]))
#         group["DST"]["vals"] = sorted(set(group["DST"]["vals"]))
#         group["DST_port"]["vals"] = sorted(set(group["DST_port"]["vals"]))
#         group["HTTP_method"]["vals"] = sorted(set(group["HTTP_method"]["vals"]))
#         group["command"]["vals"] = sorted(set(group["command"]["vals"]))

#     # Convert the defaultdict back to a normal list of dictionaries
#     return list(grouped.values())


def load_and_parse_squid_stage(file_path):
    """
    Load and parse a Squid configuration file to extract ACLs and
    HTTP access rules.

    Args:
        file_path (str): The path to the Squid configuration file.

    Returns:
            - acls (defaultdict): A dictionary where the keys are ACL names
              and the values are lists of dictionaries with 'type' and 'value'
            - rules (list): A list of dictionaries where each dictionary
              represents an HTTP access rule with 'action' and 'acl' keys.
            - rules (list): A list of dictionaries where each dictionary
              represents an HTTP access rule with 'action' and 'acl' keys.

    Raises:
        IOError: If the file cannot be opened or read.
    """
    with open(file_path, 'r') as f:
        content = f.read()

    # Extract ACLs
    acl_pattern = re.compile(r'^acl\s+(\S+)\s+(\S+)\s+(.+)$', re.MULTILINE)
    acls = defaultdict(list)
    for match in acl_pattern.finditer(content):
        acl_name = match.group(1)
        acl_type = match.group(2)
        acl_value = match.group(3)
        if acl_name not in IGNORED_ACLS:
            acls[acl_name].append({'type': acl_type, 'value': acl_value})

    # Extract rules
    rule_pattern = re.compile(r'^http_access\s+(\S+)\s+(.+)$', re.MULTILINE)
    rules = []
    for match in rule_pattern.finditer(content):
        rule = f'http_access {match.group(1)} {match.group(2)}'
        if rule not in IGNORED_RULES:
            rules.append({'action': match.group(1), 'acl': match.group(2)})

    return acls, rules


def generate_squid_template(acls, rules, output_file):
    """
    Generates a Squid configuration file from a Jinja2 template.

    Args:
        acls (list): A list of access control lists (ACLs) to be included in
            the template.
        rules (list): A list of rules to be included in the template.
        output_file (str): The path to the output file where the rendered
            template will be saved.

    Returns:
        None
    """
    template = env.get_template('base_squid_template.j2')
    rendered_template = template.render(acls=acls, rules=rules)
    with open(output_file, 'w') as f:
        f.write(rendered_template)


# def update_contents(template_name):
#     # Fetch and render the template (implementation depends on your setup)
#     pass


# def parse_dante_config(file_path):
#     # Parse the Dante configuration file (implementation depends on your setup)
#     pass


# def separate_rules(parsed_rules):
#     socks_rules = [rule for rule in parsed_rules if rule["rule_type"] == "dante-socks"]
#     client_rules = [rule for rule in parsed_rules if rule["rule_type"] == "dante-client"]
#     return socks_rules, client_rules


# def generate_dante_template(client_rules, socks_rules, output_file):
#     template = env.get_template('base_dante_template.j2')
#     rendered_template = template.render(client_rules=client_rules, socks_rules=socks_rules)
#     with open(output_file, 'w') as f:
#         f.write(rendered_template)


if __name__ == '__main__':
    # Load and parse the content from squid-stage.conf.j2
    acls, rules = load_and_parse_squid_stage('squid-stage.conf.j2')

    # Generate the squid-stage.conf file
    generate_squid_template(acls, rules, 'squid-stage.conf')

    # # Fetch and render the template
    # update_contents('short_sockd-stage.conf.j2')

    # # Parse the configuration file
    # parsed_rules = parse_dante_config('short_sockd-stage.conf.j2')

    # # Separate SOCKS and client rules
    # socks_rules, client_rules = separate_rules(parsed_rules)

    # # Generate the standardized Dante configuration
    # generate_dante_template(client_rules, socks_rules, 'standardized_dante.conf')


