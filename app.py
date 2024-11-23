from flask import Flask, render_template  # request, url_for, redirect
from ipaddress import ip_network
import requests
from decouple import config
import re


app = Flask(__name__)
# app.jinja_env.lstrip_blocks = False
# app.jinja_env.trim_blocks = False

VDC_NETS = {
    '10.234.14.0/24': 'cdpvdc-bri',
    '10.234.78.0/24': 'cdpvdc-slo',
    '10.234.33.176/29': 'mia-prd-bri',
    '10.234.99.176/29': 'mia-prd-slo',
    '10.234.33.184/29': 'mia-stg-bri',
    '10.234.99.184/29': 'mia-stg-slo',
    '10.234.32.128/25': 'skynet-prd-bri',
    '10.234.97.128/25': 'skynet-prd-slo',
    '10.234.32.0/25': 'skynet-stg-bri',
    '10.234.97.0/25': 'skynet-stg-slo',
    '10.234.31.32/27': 'tsf-prd-bri',
    '10.234.104.32/27': 'tsf-prd-slo',
    '10.234.31.64/27': 'tsf-stg-bri',
    '10.234.104.64/27': 'tsf-stg-slo',
    '10.234.31.128/29': 'utils-prd-bri',
    '10.234.104.128/29': 'utils-prd-slo',
    '10.234.31.136/29': 'utils-stg-bri',
    '10.234.104.136/29': 'utils-stg-slo',
    '10.245.225.224/28': 'utils-prd-bri',
    '10.245.229.224/28': 'utils-prd-slo',
    '10.245.225.240/28': 'utils-stg-bri',
    '10.245.229.240/28': 'utils-stg-slo',
    '10.234.31.96/28': 'vodcm-prd-bri',
    '10.234.104.96/28': 'vodcm-prd-slo',
    '10.234.31.112/28': 'vodcm-stg-bri',
    '10.234.104.112/28': 'vodcm-stg-slo',
    '10.234.79.0/28': 'vso-prd-slo',
    '10.234.99.0/25': 'vso-stg-slo'
}


def update_contents(template: str):
    if template.startswith('squid'):
        shim = 'squid'
    elif template.startswith('sockd'):
        shim = 'dante'
    url = (
        'https://api.github.com/repos/sky-uk/gcd-mia/'
        f'contents/roles/{shim}/templates/{template}'
    )
    token = config('GIT_TOKEN')
    headers = {
        'Accept': 'application/vnd.github.v3.raw',
        'Authorization': f'Bearer {token}'
    }
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching template: {e}")
        return []

    content = response.text
    with open(template, 'w') as f:
        f.write(content)
    return [i.strip() for i in content.split('\n')]


def squid_acl_check(acl, conf):
    acl_facts = {}
    if acl != 'all':
        if acl.startswith('!'):
            acl_find = [i for i in conf if i.startswith(f'acl {acl[1:]} ')]
            acl_facts['tags'] = 'not'
        else:
            acl_find = [i for i in conf if i.startswith(f'acl {acl} ')]
        if acl_find:
            acl_facts['name'] = acl_find[0].split()[1]
            acl_facts['type'] = acl_find[0].split()[2]
            acl_facts['vals'] = [' '.join(i.split()[3:]) for i in acl_find]
        else:
            acl_facts['name'] = acl
            acl_facts['type'] = 'unknonwn'
            acl_facts['vals'] = []
    else:
        acl_facts = {
            'name': 'all', 'type': 'both', 'vals': 'any', 'tags': 'all'
        }
    return acl_facts


def squid_rule_check(conf):
    squid_rules = []
    for line in conf:
        if (line.startswith('http_access') and 
                not line.count(' manager') and 
                not line.count('localhost'.lower())):
            parts = line.split()
            action = parts[1].upper()
            acls = parts[2:]
            rule = {
                "rule_type": "squid",
                "action": action,
            }
            for acl in acls:
                acl_facts = squid_acl_check(acl, conf)
                acl_type = acl_facts['type']
                if acl_type.startswith('src'):
                    rule['SRC'] = acl_facts
                elif acl_type.startswith('dst'):
                    rule['DST'] = acl_facts
                elif acl_type.startswith('port'):
                    rule['DST_port'] = acl_facts
                elif acl_type.startswith('method'):
                    rule['HTTP_method'] = acl_facts
            squid_rules.append(rule)
    return squid_rules


def parse_dante_config(file_path):
    with open(file_path, 'r') as f:
        lines = f.readlines()

    serialized_rules = []
    current_rule = []

    # Step 1: Serialize multiline rules into one-liners
    for line in lines:
        line = line.strip()
        if (not line or line.startswith("#")):
            continue  # Skip empty lines, comments etc..
        if line.endswith("{"):
            current_rule = [line]
        elif line.endswith("}"):
            current_rule.append(line)
            serialized_rules.append(" ".join(current_rule))
            current_rule = []
        elif current_rule:
            current_rule.append(line)
    parsed_rules = []

    # Step 2: Parse serialized rules
    for rule in serialized_rules:
        rule_type = "client" if rule.startswith("client") else (
            "socks" if rule.startswith("socks") else None
        )
        if rule_type:
            if " pass " in rule:
                action = "ALLOW"
            elif " block " in rule:
                action = "DENY"
            else:
                action = None
            from_matches = re.search(
                r'from:\s+([^}]+?)\s+(to:|port:|command:|log:|})', rule
            )
            to_matches = re.search(
                r'to:\s+([^}]+?)\s+(from:|port:|command:|log:|})', rule
            )
            port_matches = re.search(
                r'port:\s+([^}]+?)\s+(from:|to:|command:|log:|})', rule
            )
            command_matches = re.search(
                r'command:\s+([^}]+?)\s+(from:|to:|port:|log:|})', rule
            )
            from_list = from_matches.group(1).split() if from_matches else []
            to_list = to_matches.group(1).split() if to_matches else []
            port = port_matches.group(1).split() if port_matches else ["ANY"]
            command = (command_matches.group(1).split()
                       if command_matches else ["n/a"])

            enriched_from_list = []
            for src in from_list:
                try:
                    src_network = ip_network(src, strict=False)
                    bg = next(
                        (bg_name for net, bg_name in VDC_NETS.items()
                         if src_network.subnet_of(ip_network(net))),
                        None
                    )
                    if bg:
                        enriched_from_list.append(f"{src} - {bg}")
                    else:
                        enriched_from_list.append(src)
                except ValueError:
                    enriched_from_list.append(src)

            # Create a dictionary for each rule
            parsed_rules.append({
                "rule_type": rule_type,
                "action": action,
                "SRC": {"type": "src", "vals": enriched_from_list},
                "DST": {"type": "dst", "vals": to_list},
                "DST_port": {"type": "port", "vals": port},
                "command": {"type": "command", "vals": command},
            })
            print(f'rule_type: {rule_type}')

    return parsed_rules


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/squid/prd')
def squid_prd_func():
    squid_prd_conf = update_contents('squid-prod.conf.j2')
    squid_prd_rules = squid_rule_check(squid_prd_conf)
    return render_template(
        'squid_prd.html', squid_prd_rules=squid_prd_rules, enumerate=enumerate
    )


@app.route('/squid/stg')
def squid_stg_func():
    squid_stg_conf = update_contents('squid-stage.conf.j2')
    squid_stg_rules = squid_rule_check(squid_stg_conf)
    return render_template(
        'squid_stg.html', squid_stg_rules=squid_stg_rules, enumerate=enumerate
    )


@app.route('/dante-prd')
def dante_prd_func():
    # Parse the configuration file
    update_contents('sockd-prod.conf.j2')
    parsed_rules = parse_dante_config('sockd-prod.conf.j2')

    # Separate SOCKS and client rules
    socks_rules = [
        rule for rule in parsed_rules if rule["rule_type"] == "socks"
    ]
    client_rules = [
        rule for rule in parsed_rules if rule["rule_type"] == "client"
    ]

    return render_template(
        'dante_prd.html',
        socks_prd_rules=socks_rules,
        client_prd_rules=client_rules,
        enumerate=enumerate
    )


@app.route('/dante-stg')
def dante_stg_func():
    # Parse the configuration file
    parsed_rules = parse_dante_config('short_sockd-stage.conf.j2')

    # Separate SOCKS and client rules
    socks_rules = [
        rule for rule in parsed_rules if rule["rule_type"] == "socks"
    ]
    client_rules = [
        rule for rule in parsed_rules if rule["rule_type"] == "client"
    ]

    return render_template(
        'dante_stg.html',
        socks_stg_rules=socks_rules,
        client_stg_rules=client_rules,
        enumerate=enumerate
    )


if __name__ == '__main__':
    app.run(debug=True)
