from flask import Flask, render_template  # request, url_for, redirect
from ipaddress import ip_network
import requests
from decouple import config
import re


app = Flask(__name__)
# app.jinja_env.lstrip_blocks = False
# app.jinja_env.trim_blocks = False

VDC_NETS = {
    'cdpvdc-bri': '10.234.14.0/24',
    'cdpvdc-slo': '10.234.78.0/24',
    'mia-prd-bri': '10.234.33.176/29',
    'mia-prd-slo': '10.234.99.176/29',
    'mia-stg-bri': '10.234.33.184/29',
    'mia-stg-slo': '10.234.99.184/29',
    'skynet-prd-bri': '10.234.32.128/25',
    'skynet-prd-slo': '10.234.97.128/25',
    'skynet-stg-bri': '10.234.32.0/25',
    'skynet-stg-slo': '10.234.97.0/25',
    'tsf-prd-bri': '10.234.31.32/27',
    'tsf-prd-slo': '10.234.104.32/27',
    'tsf-stg-bri': '10.234.31.64/27',
    'tsf-stg-slo': '10.234.104.64/27',
    'utils-prd-bri-1': '10.234.31.128/29',
    'utils-prd-slo-1': '10.234.104.128/29',
    'utils-stg-bri-1': '10.234.31.136/29',
    'utils-stg-slo-1': '10.234.104.136/29',
    'utils-prd-bri-2': '10.245.225.224/28',
    'utils-prd-slo-2': '10.245.229.224/28',
    'utils-stg-bri-2': '10.245.225.240/28',
    'utils-stg-slo-2': '10.245.229.240/28',
    'vodcm-prd-bri': '10.234.31.96/28',
    'vodcm-prd-slo': '10.234.104.96/28',
    'vodcm-stg-bri': '10.234.31.112/28',
    'vodcm-stg-slo': '10.234.104.112/28',
    'vso-prd-slo': '10.234.79.0/28',
    'vso-stg-slo': '10.234.99.0/25'
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
            acl_facts['vals'] = [i.split()[3:] for i in acl_find]
        else:
            acl_facts['name'] = acl
            acl_facts['type'] = 'both'
            acl_facts['vals'] = []
    else:
        acl_facts = {
            'name': 'all', 'type': 'both', 'vals': 'any', 'tags': 'all'
        }
    return acl_facts


def squid_rule_check(conf):
    squid_rules = [
        dict(
            action=i.split()[1].upper(),
            acls=i.split()[2:]) for i in conf
        if i.startswith('http_access')
        if not i.count(' manager')
        if not i.count('localhost'.lower())
        # if not i.count(' CONNECT ')
    ]
    for rule in squid_rules:
        rule['acls'] = [acl.split('#')[0].strip() for acl in rule['acls']]
        for acl in rule['acls']:
            acl_facts = squid_acl_check(acl, conf)
            acl_type = acl_facts['type']
            if acl_type.startswith('src'):
                rule['src'] = squid_acl_check(acl, conf)
            if acl_type.startswith('dst'):
                rule['dst'] = squid_acl_check(acl, conf)
            if acl_type.startswith('port'):
                rule['dst_port'] = squid_acl_check(acl, conf)
            if acl_type.startswith('method'):
                rule['http_method'] = squid_acl_check(acl, conf)
    return squid_rules


def dante_rule_check(conf):
    client_rules = []
    socks_rules = []
    for x, i in enumerate(conf):
        if (i.count('pass {') or i.count('block {')) and not i.startswith('#'):
            src_net = conf[x+1].split('from: ')[1].split()[0]
            src_bg = [
                bg for bg, net in VDC_NETS.items() if ip_network(
                    src_net, strict=False).subnet_of(ip_network(net))
            ]
            dst_net = conf[x+1].split('to: ')[1].split()[0]
            if i.startswith('socks'):
                socks_rules.append(dict())
                s = len(socks_rules) - 1
                if i.count('pass'):
                    socks_rules[s]['action'] = 'ALLOW'
                else:
                    socks_rules[s]['action'] = 'DENY'
                if src_bg:
                    socks_rules[s]['SRC'] = f'{src_net} - {src_bg[0]}'
                else:
                    socks_rules[s]['SRC'] = f'{src_net}'
                socks_rules[s]['DST'] = dst_net
                if conf[x+1].count('port: '):
                    socks_rules[s]['DST_port'] = (
                        conf[x+1].split('port: ')[1].split()[0]
                    )
                else:
                    socks_rules[s]['DST_port'] = 'ANY'
                if conf[x+2].count('command: '):
                    socks_rules[s]['command'] = conf[x+2].split('command: ')[1]
            if i.startswith('client'):
                client_rules.append(dict())
                c = len(client_rules) - 1
                if i.count('pass'):
                    client_rules[c]['action'] = 'ALLOW'
                else:
                    client_rules[c]['action'] = 'DENY'
                if src_bg:
                    client_rules[c]['SRC'] = f'{src_net} - {src_bg[0]}'
                else:
                    client_rules[c]['SRC'] = f'{src_net}'
                client_rules[c]['DST'] = dst_net
                if conf[x+1].count('port: '):
                    client_rules[c]['DST_port'] = (
                        conf[x+1].split('port: ')[1].split()[0]
                    )
                else:
                    client_rules[c]['DST_port'] = 'ANY'
    return (socks_rules, client_rules)


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
        # rule_type = "client" if "client" in rule else "socks"
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
            command = command_matches.group(1).split() if command_matches else None
            print(f'port: {port}')
            print(f'command: {command}')
            print(f'from: {from_list}')

            # Create a dictionary for each rule
            parsed_rules.append({
                "type": rule_type,
                "action": action,
                "SRC": from_list,
                "DST": to_list,
                "DST_port": port,
                "command": command,
            })

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


@app.route('/dante/prd')
def dante_prd_func():
    dante_prd_conf = update_contents('sockd-prod.conf.j2')
    (socks_prd_rules, client_prd_rules) = dante_rule_check(dante_prd_conf)
    return render_template(
        'dante_prd.html', socks_prd_rules=socks_prd_rules,
        client_prd_rules=client_prd_rules, enumerate=enumerate
    )


# @app.route('/dante/stg')
# def dante_stg_func():
#     dante_stg_conf = update_contents('sockd-stage.conf.j2')
#     (socks_stg_rules, client_stg_rules) = dante_rule_check(dante_stg_conf)
#     return render_template(
#         'dante_stg.html', socks_stg_rules=socks_stg_rules,
#         client_stg_rules=client_stg_rules, enumerate=enumerate
#     )


@app.route('/dante-stg')
def dante_stg_func():
    # Parse the configuration file
    parsed_rules = parse_dante_config('short_sockd-stage.conf.j2')

    # Separate SOCKS and client rules
    socks_rules = [rule for rule in parsed_rules if rule["type"] == "socks"]
    client_rules = [rule for rule in parsed_rules if rule["type"] == "client"]

    return render_template(
        'dante_stg.html',
        socks_stg_rules=socks_rules,
        client_stg_rules=client_rules,
        enumerate=enumerate
    )


if __name__ == '__main__':
    app.run(debug=True)
