from flask import Flask, render_template  # request, url_for, redirect
from ipaddress import ip_network
import requests
from decouple import config


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
    'utils-prd-bri': '10.234.31.128/29',
    'utils-prd-slo': '10.234.104.128/29',
    'utils-stg-bri': '10.234.31.136/29',
    'utils-stg-slo': '10.234.104.136/29',
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
    response = requests.get(url, headers=headers).text
    with open(template, 'w') as f:
        f.write(response)
    return [i.strip() for i in response.split('\n')]


def squid_acl_check(acl, conf):
    acl_facts = {}
    if acl != 'all':
        if acl.startswith('!'):
            acl_find = [i for i in conf if i.startswith(f'acl {acl[1:]} ')]
            acl_facts['tags'] = 'not'
        else:
            acl_find = [i for i in conf if i.startswith(f'acl {acl} ')]
        acl_facts['name'] = acl_find[0].split(' ')[1]
        acl_facts['type'] = acl_find[0].split(' ')[2]
        acl_facts['vals'] = [i.split(' ')[3:] for i in acl_find]
    else:
        acl_facts = {
            'name': 'all', 'type': 'both', 'vals': 'any', 'tags': 'all'
        }
    return acl_facts


def squid_rule_check(conf):
    squid_rules = [
        dict(
            action=i.split(' ')[1].upper(),
            acls=i.split(' ')[2:]) for i in conf
        if i.startswith('http_access')
        if not i.count(' manager')
        if not i.count('localhost'.lower())
        if not i.count(' CONNECT ')
    ]
    for rule in squid_rules:
        for acl in rule['acls']:
            if squid_acl_check(acl, conf)['type'].startswith('src'):
                rule['src'] = squid_acl_check(acl, conf)
            if squid_acl_check(acl, conf)['type'].startswith('dst'):
                rule['dst'] = squid_acl_check(acl, conf)
            if squid_acl_check(acl, conf)['type'].startswith('port'):
                rule['dst_port'] = squid_acl_check(acl, conf)
    return squid_rules


def dante_rule_check(conf):
    client_rules = []
    socks_rules = []
    for x, i in enumerate(conf):
        if (i.count('pass {') or i.count('block {')) and not i.startswith('#'):
            src_net = conf[x+1].split('from: ')[1].split(' ')[0]
            src_bg = [
                bg for bg, net in VDC_NETS.items() if ip_network(
                    src_net, strict=False).subnet_of(ip_network(net))
            ]
            dst_net = conf[x+1].split('to: ')[1].split(' ')[0]
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
                        conf[x+1].split('port: ')[1].split(' ')[0]
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
                        conf[x+1].split('port: ')[1].split(' ')[0]
                    )
                else:
                    client_rules[c]['DST_port'] = 'ANY'
    return (socks_rules, client_rules)


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


@app.route('/dante/stg')
def dante_stg_func():
    dante_stg_conf = update_contents('sockd-stage.conf.j2')
    (socks_stg_rules, client_stg_rules) = dante_rule_check(dante_stg_conf)
    return render_template(
        'dante_stg.html', socks_stg_rules=socks_stg_rules,
        client_stg_rules=client_stg_rules, enumerate=enumerate
    )


if __name__ == '__main__':
    app.run(debug=True)
