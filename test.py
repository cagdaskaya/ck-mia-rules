import re
from collections import defaultdict
from jinja2 import Environment, FileSystemLoader

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


def load_and_parse_squid_stage(file_path):
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
    template = env.get_template('base_squid_template.j2')
    rendered_template = template.render(acls=acls, rules=rules)
    with open(output_file, 'w') as f:
        f.write(rendered_template)


if __name__ == '__main__':
    # Load and parse the content from squid-stage.conf.j2
    acls, rules = load_and_parse_squid_stage('squid-stage.conf.j2')

    # Generate the squid-stage.conf file
    generate_squid_template(acls, rules, 'squid-stage.conf')
