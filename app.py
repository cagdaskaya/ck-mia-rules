from flask import Flask, render_template  # request, url_for, redirect
from ipaddress import ip_network
import requests
from decouple import config
import re


app = Flask(__name__)
# app.jinja_env.lstrip_blocks = False
# app.jinja_env.trim_blocks = False

NET_NAME = {
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
    '10.234.99.0/25': 'vso-stg-slo',
    '192.168.169.58/32': 'epg',
    '192.168.169.191/32': 'epg',
    '10.207.121.110/32': 'epg',
    '10.213.20.55/32': 'epg',
    '10.220.1.56/32': 'epg',
    '10.207.40.46/32': 'epg',
    '10.194.48.0/23': 'lmt'
}


def update_contents(template: str):
    """
    Fetches the content of a template file from a GitHub repository and updates
    the local file.

    Args:
        template (str): The name of the template file to be fetched and
                        updated.

    Returns:
        list: A list of strings, each representing a line in the fetched
              template file.

    Raises:
        requests.exceptions.RequestException: If there is an error while
                                              fetching the template from
                                              GitHub.

    Notes:
        - The function determines the appropriate shim based on the template
          name.
        - The GitHub API token is retrieved from the environment variable
          'GIT_TOKEN'.
        - The fetched content is written to a local file with the same name as
          the template.
    """
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
    """
    Check and retrieve details about a Squid ACL from the configuration.

    Args:
        acl (str): The ACL name to check. If it starts with '!',
            it indicates a negated ACL.
        conf (list of str): The Squid configuration lines to search within.

    Returns:
        dict: A dictionary containing the following keys:
            - 'name' (str): The name of the ACL.
            - 'type' (str): The type of the ACL.
            - 'vals' (list of str): The values associated with the ACL.
            - 'tags' (str, optional): A tag indicating special conditions
              (e.g., 'not' for negated ACLs).
    """
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
    """
    Parses a given Squid configuration and extracts rules related to
    HTTP access.

    Args:
        conf (list of str): The Squid configuration lines.

    Returns:
        list of dict: A list of dictionaries where each dictionary
        represents a Squid rule. Each rule dictionary contains:
                - "rule_type": The type of rule (always "squid").
                - "action": The action to be taken (e.g., "ALLOW" or "DENY").
                - "SRC": Source ACL facts (if applicable).
                - "DST": Destination ACL facts (if applicable).
                - "DST_port": Destination port ACL facts (if applicable).
                - "HTTP_method": HTTP method ACL facts (if applicable).
    """
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
                if (acl_type.startswith('src')):
                    rule['SRC'] = acl_facts
                elif (acl_type.startswith('dst')):
                    rule['DST'] = acl_facts
                elif (acl_type.startswith('port')):
                    rule['DST_port'] = acl_facts
                elif (acl_type.startswith('method')):
                    rule['HTTP_method'] = acl_facts
            squid_rules.append(rule)
    return squid_rules


def enrich_network_list(network_list, net_name_dict):
    """
    Enriches a list of network addresses with corresponding names from a
    dictionary.

    Args:
        network_list (list of str): A list of network addresses in string
                                    format.
        net_name_dict (dict): A dictionary where keys are network addresses
                              (in string format) and values are corresponding
                              names.

    Returns:
        list of str: A list of network addresses, where each address is
                     optionally followed by a comment with the corresponding
                     name from the dictionary.
                     If a network address cannot be parsed, it is included
                     as-is.
    """
    enriched_list = []
    for net in network_list:
        try:
            network = ip_network(net, strict=False)
            bg = next(
                (bg_name for net, bg_name in net_name_dict.items()
                    if network.subnet_of(ip_network(net))),
                None)
            if bg:
                enriched_list.append(f"{net} # {bg}")
            else:
                enriched_list.append(net)
        except ValueError:
            enriched_list.append(net)
    return enriched_list


def parse_dante_config(file_path):
    """
    Parses a Dante configuration file and extracts rules into a
    structured format.

    Args:
        file_path (str): The path to the Dante configuration file.

    Returns:
        list: A list of dictionaries, each representing a parsed rule
        with the following keys:
            - rule_type (str): The type of the rule, either 'client' or
              'socks'.
            - action (str): The action of the rule, either 'ALLOW' or
              'DENY'.
            - SRC (dict): A dictionary with 'type' set to 'src' and
              'vals' containing a list of enriched source addresses.
            - DST (dict): A dictionary with 'type' set to 'dst' and
              'vals' containing a list of enriched destination addresses.
            - DST_port (dict): A dictionary with 'type' set to 'port' and
              'vals' containing a list of destination ports.
            - command (dict): A dictionary with 'type' set to 'command'
              and 'vals' containing a list of commands.

    Note:
        - The function assumes that the configuration file contains rules
          in a specific format.
        - The function skips empty lines and comments.
        - The function enriches network lists using the
          `enrich_network_list` function and `NET_NAME` constant.
    """
    with open(file_path, 'r') as f:
        lines = f.readlines()

    serialized_rules = []
    current_rule = []

    # Step 1: Serialize multiline rules into one-liners
    for line in lines:
        line = line.strip()

        # Skip empty lines and comments
        if not line or line.startswith("#"):
            continue

        # Check if the line starts with valid rule types and actions
        valid_start = line.startswith(
            ("socks pass", "socks block", "client pass", "client block")
        )
        if not valid_start and not current_rule:
            continue
        # Handle single-line rules (starting and ending on the same line)
        if valid_start and "{" in line and "}" in line:
            serialized_rules.append(line)
            continue
        # If the line contains an opening brace, start capturing the rule
        if "{" in line and not current_rule:
            current_rule = [line]
        # If the line contains a closing brace, finalize the current rule
        elif "}" in line and current_rule:
            current_rule.append(line)
            serialized_rules.append(
                " ".join(current_rule).replace("\n", " ").replace("\t", " ")
            )
            current_rule = []
        # If within a block, keep appending to the current rule
        elif current_rule:
            current_rule.append(line)
        # Handle single-line rules without braces
        else:
            serialized_rules.append(line)

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

            enriched_src_list = enrich_network_list(from_list, NET_NAME)
            enriched_dst_list = enrich_network_list(to_list, NET_NAME)

            # Create a dictionary for each rule
            parsed_rules.append({
                "rule_type": rule_type,
                "action": action,
                "SRC": {"type": "src", "vals": enriched_src_list},
                "DST": {"type": "dst", "vals": enriched_dst_list},
                "DST_port": {"type": "port", "vals": port},
                "command": {"type": "command", "vals": command},
            })

    return parsed_rules


def separate_rules(parsed_rules):
    """
    Separates parsed rules into socks rules and client rules.

    Args:
        parsed_rules (list): A list of dictionaries where each dictionary
                             represents a rule with a "rule_type" key.

    Returns:
        tuple: A tuple containing two lists:
               - socks_rules (list): A list of rules where "rule_type"
                 is "socks".
               - client_rules (list): A list of rules where "rule_type"
                 is "client".
    """
    socks_rules = [
        rule for rule in parsed_rules if rule["rule_type"] == "socks"
    ]
    client_rules = [
        rule for rule in parsed_rules if rule["rule_type"] == "client"
    ]
    return socks_rules, client_rules


@app.route('/')
def home():
    """
    Renders the home page template.

    Returns:
        A rendered HTML template for the home page.
    """
    return render_template('index.html')


@app.route('/squid/prd')
def squid_prd_func():
    """
    Generates and renders the Squid production rules.

    This function updates the contents of the 'squid-prod.conf.j2'
    configuration file, checks the Squid rules based on the updated
    configuration, and renders the 'squid_prd.html' template with the
    Squid production rules.

    Returns:
        str: Rendered HTML template with Squid production rules.
    """
    squid_prd_conf = update_contents('squid-prod.conf.j2')
    squid_prd_rules = squid_rule_check(squid_prd_conf)
    return render_template(
        'squid_prd.html', squid_prd_rules=squid_prd_rules, enumerate=enumerate
    )


@app.route('/squid/stg')
def squid_stg_func():
    """
    Generates and renders the squid staging rules.

    This function updates the contents of the 'squid-stage.conf.j2'
    configuration file, checks the squid rules based on the updated
    configuration, and then renders the 'squid_stg.html' template with
    the squid staging rules.

    Returns:
        str: The rendered HTML template with the squid staging rules.
    """
    squid_stg_conf = update_contents('squid-stage.conf.j2')
    squid_stg_rules = squid_rule_check(squid_stg_conf)
    return render_template(
        'squid_stg.html', squid_stg_rules=squid_stg_rules, enumerate=enumerate
    )


@app.route('/dante-prd')
def dante_prd_func():
    """
    Parses the Dante configuration file, separates the rules into SOCKS
    and client rules, and renders the 'dante_prd.html' template with
    the parsed rules.

    Returns:
        str: Rendered HTML template with SOCKS and client rules.

    """
    # Parse the configuration file
    update_contents('sockd-prod.conf.j2')
    parsed_rules = parse_dante_config('sockd-prod.conf.j2')
    # parsed_rules = parse_dante_config('short_sockd-prod.conf.j2')

    # Separate SOCKS and client rules
    socks_rules, client_rules = separate_rules(parsed_rules)

    return render_template(
        'dante_prd.html',
        socks_prd_rules=socks_rules,
        client_prd_rules=client_rules,
        enumerate=enumerate
    )


@app.route('/dante-stg')
def dante_stg_func():
    """
    Parses the Dante configuration file and separates the rules into SOCKS
    and client rules. Renders the 'dante_stg.html' template with the
    separated rules.

    Returns:
        str: Rendered HTML template with SOCKS and client rules.

    """
    # Parse the configuration file
    update_contents('sockd-stage.conf.j2')
    parsed_rules = parse_dante_config('sockd-stage.conf.j2')
    # parsed_rules = parse_dante_config('short_sockd-stage.conf.j2')

    # Separate SOCKS and client rules
    socks_rules, client_rules = separate_rules(parsed_rules)

    return render_template(
        'dante_stg.html',
        socks_stg_rules=socks_rules,
        client_stg_rules=client_rules,
        enumerate=enumerate
    )


if __name__ == '__main__':
    app.run(debug=True)
