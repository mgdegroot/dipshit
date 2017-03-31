#!/usr/bin/env python3
# TODO: lots of stuff....

import requests
import os
import sys
import pprint
import shelve
import re
import copy
import subprocess
import argparse
from enum import Enum


class Action(Enum):
    IPSET_REFRESH = 1,
    IPSET_SAVE = 2,
    IPSET_LOAD = 3,
    IPSET_FLUSH = 4,
    IPSET_IS_LOADED = 5,
    IPSET_IS_LATEST = 6,
    IPTABLES_IS_IPSET_ACTIVE = 7,
    IPTABLES_ACTIVATE = 8,
    IPTABLES_DEACTIVATE = 9,
    SHOW_STATUS = 10

SHELVE_DBNAME = '/etc/ipset/list_management.shelve'
RULE_SAVEFILE = '/etc/ipset/{ipset_list}.ipset'

SHELVE_KEY = 'IPSET_LIST_REVISION'
URL_RULES_REVISION = 'http://rules.emergingthreats.net/fwrules/FWrev'
URL_RULES = 'http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt'
BIN_IPSET = '/sbin/ipset'
BIN_IPTABLES = '/sbin/iptables'

DEFAULT_IPTABLES_TABLE = 'filter'
DEFAULT_IPSET_LISTNAME = 'wan_blocks'
DEFAULT_INDEX = 1


def check_requirements():
    """
    Check whether or not all the requirements are available
    and fix if possible.
    RuntimeError will be raised if an unfixable condition is met.
    :return:
    """
    if os.path.exists(BIN_IPSET) is False:
        raise RuntimeError('ipset not found at {}'.format(BIN_IPSET))
    if os.path.exists(BIN_IPTABLES) is False:
        raise RuntimeError('iptables not found at {}'.format(BIN_IPTABLES))
    if os.path.exists(os.path.dirname(SHELVE_DBNAME)) is False:
        print('Config directory not found. Creating...')
        os.makedirs(os.path.dirname(SHELVE_DBNAME))

    print('Requirements ok. Continuing...')


def show_status(chain, ipset_listname, table=DEFAULT_IPTABLES_TABLE):

    """

    :param chain:
    :param ipset_listname:
    """
    ipset_loaded = ipset_check_list_loaded(ipset_listname)
    list_revision_local = list_get_local_revision(ipset_listname)
    list_revision_available = list_get_available_revision(URL_RULES_REVISION, ipset_listname)
    iptables_configured = iptables_check_ipset_referenced(chain, ipset_listname, table)

    print('''
    List {listname} local revision: {local:d}
    List {listname} avail revision: {avail:d}'''.format(listname=ipset_listname,
                                                        local=list_revision_local,
                                                        avail=list_revision_available))
    print('IPset set loaded:' + str(ipset_loaded))
    print('IPTables {chain} list referenced: {is_referenced}'.format(chain=chain,
                                                                     is_referenced=iptables_configured))


def list_convert_and_clean(raw_content, comment_chars='#', separator='\n'):
    """
    Cleanup the raw contents and return entries as a list
    :param comment_chars: Default '#'
    :param separator: Default newline
    :return:
    :param raw_content: Text, entries separated by newline
    :return: List of entries
    """

    ip_list = raw_content.split(separator)
    ip_list_iter = ip_list.copy()

    print('Converting and cleaning up ip address file...')

    # TODO: combine regex to one expression -->
    regex_comment = re.compile('^{comment_chars}.*$'.format(comment_chars=comment_chars))
    regex_empty = re.compile('^\s*$')
    regex_revision = re.compile('^#\sRev\s(\d+).*$')
    recv_revision = -1

    for ip in ip_list_iter:
        # check for revision -->
        match_revision = regex_revision.match(ip)
        if match_revision is not None:
            recv_revision = int(match_revision.group(1))
            print('found revision {:d}'.format(recv_revision))
            print(recv_revision)
        # remove empty or comment lines -->
        if regex_comment.match(ip) is not None or regex_empty.match(ip) is not None:
            print('removing {}'.format(ip))
            ip_list.remove(ip)

    print('\tDone converting. Received {:d} addresses / ip blocks.'.format(len(ip_list)))

    return (recv_revision, ip_list)


def iptables_get_ipset_index(chain, ipset_listname, table=DEFAULT_IPTABLES_TABLE):
    """
    Return the index of the ipset chain
    :param chain: IPTables chain to search
    :param ipset_listname: The list name
    :param table: The IPTables table (Default <DEFAULT_IPTABLES_TABLE>)
    :return: The found index, or -1 if not found.
    """

    p = subprocess.run([BIN_IPTABLES, '-t', table, '-nvL', chain, '--line-numbers'],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    out = str(p.stdout)
    # stderr = str(p.stderr)
    out_lines = out.splitlines()
    regex = re.compile(r'^(\d{1,2}).*')
    idx_ipset_chain_ref = -1

    for i in range(len(out_lines)):
        if ipset_listname in out_lines[i]:
            match_line_nr = regex.match(out_lines[i])
            if match_line_nr is not None:
                idx_ipset_chain_ref = int(match_line_nr.group(1))

    return idx_ipset_chain_ref


def list_get_content(url):

    """
    Fetch document from url and return 'as is'
    :param url:
    :return:
    """
    print('Fetching rules from {}...'.format(url))
    response = requests.get(url)
    response.raise_for_status()

    list_body = response.text

    return list_body


def ipset_restore(path):
    """

    :param path:
    :return:
    """

    print('Restoring ipset list content from file {}'.format(path))
    # TODO: error checking -->
    subprocess.run([BIN_IPSET, '-file', path,'-exist', 'restore'])


def ipset_save(ipset_name, path):
    """

    :param ipset_name:
    :param path:
    :return:
    """

    print('Saving ipset list {} to {}'.format(ipset_name, path))

    subprocess.run([BIN_IPSET, '-file', path, 'save', ipset_name])


def ipset_flush(ipset_name):
    """

    :param ipset_name:
    :return:
    """
    print('flush_ipset')

    print('Flushing ipset list {}'.format(ipset_name))

    subprocess.run([BIN_IPSET, 'flush', ipset_name])


def ipset_check_list_loaded(ipset_name):
    """
    Check whether or not the ipset list <ipset_name> is present
    TODO: also verify whether it has any entries!
    :return: True when present, False otherwise
    """
    ipset_list_loaded = True

    p = subprocess.run([BIN_IPSET, 'list', '-name'],
                       stdout = subprocess.PIPE, stderr = subprocess.PIPE, universal_newlines=True)
    out = str(p.stdout)
    if ipset_name not in out:
        ipset_list_loaded = False

    return ipset_list_loaded


def ipset_update_list(ip_list, ipset_listname):
    """

    :param ip_list:
    :param ipset_listname:
    :return:
    """

    """
    ipset create ip_droplist nethash -exist
    """

    print('Creating ipset list {} if it doesn\'t exists...'.format(ipset_listname))

    subprocess.run([BIN_IPSET, 'create', ipset_listname, 'nethash', '-exist'])
    for ip in ip_list:
        print('\t\tAdding {} to ipset list {}'.format(ip, ipset_listname))
        subprocess.run([BIN_IPSET, 'add', ipset_listname, ip, '-exist'])

    print('\tDone adding addresses to {}'.format(ipset_listname))


def iptables_check_ipset_referenced(chain, ipset_name, table='filter'):
    """
    Check whether or not an ipset match for <ipset_name> is present in the iptables configuration for <chain>.
    Default table is filter but can be changed with the <table> parameter.
    :param chain: The table to query
    :param ipset_name:
    :param table:

    :return: True when present, False otherwise
    """
    is_ipset_list_referenced = True

    p = subprocess.run([BIN_IPTABLES, '-t', table, '-nvL', chain],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    out = str(p.stdout)

    if ipset_name not in out:
        is_ipset_list_referenced = False

    return is_ipset_list_referenced


def iptables_configure_ipset_reference(chain, insert_index, ipset_name, table='filter'):
    """
    :param chain The chain to modify
    :param insert_index The index at which to do the insert
    :param ipset_name The name of the ipset list
    :param table The table to work on, defaults to 'filter'
    :return:

    """
    '''
    iptables -nvL FORWARD
    iptables -A FORWARD -m match-set --set NAME_DROPLIST src,dst -j DROP
    '''

    if iptables_check_ipset_referenced(chain, ipset_name) == True:
        # TODO: remove ipset chain reference
        print('iptables chain {} in table {} already configured for list. Removing first...'.format(chain, table))
        iptables_remove_ipset_chain(chain, ipset_name, table)

    print('iptables chain {} in table {} not present. Adding it to iptables configuration...'.format(chain, table))
    iptables_create_ipset_chain(ipset_name, table)

    subprocess.run([BIN_IPTABLES, '-I', chain, str(insert_index), '-j', ipset_name])


def iptables_create_ipset_chain(ipset_name, table=DEFAULT_IPTABLES_TABLE):
    """
    Create a new chain named <ipset_name> for the ip droplist matching to drop and log
    :param table The table to work in
    :param ipset_name The chain name (the ipset listname is used for this)
    :return:
    """

    Idx_log = 1
    Idx_drop = 2


    p = subprocess.run([BIN_IPTABLES, '-t', table, '-nvL', ipset_name],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    out = str(p.stdout)
    if ipset_name not in out:
        subprocess.run([BIN_IPTABLES, '-t', table, '-N', ipset_name])

        subprocess.run([BIN_IPTABLES, '-t', table, '-I', ipset_name, str(Idx_log), '-m', 'set',
                        '--match-set', ipset_name, 'src,dst', '-j', 'LOG',
                        '--log-prefix', 'IPTables_ipdrop', '--log-level', '4'])
        subprocess.run([BIN_IPTABLES, '-t', table, '-I', ipset_name, str(Idx_drop), '-m', 'set',
                        '--match-set', ipset_name, 'src,dst', '-j', 'DROP'])
    else:
        print('Nothing to do. Chain {} in table {} is already present.'.format(ipset_name, table))


def iptables_remove_ipset_chain(chain, ipset_name, table=DEFAULT_IPTABLES_TABLE):
    """

    :param chain:
    :param ipset_name:
    :param table:
    """

    idx = iptables_get_ipset_index(chain, ipset_name, table)
    if idx > 0:
        print('Reference for list {list_name} in {table}.{chain} found. Removing...'.format(
            list_name=ipset_name, table=table,chain=chain))
        # remove reference, flush chain, destroy chain -->
        subprocess.run([BIN_IPTABLES, '-t', table, '-D', chain, str(idx)])
    else:
        print('No action: Reference for list {list_name} in {table}.{chain} not found.'.format(
            list_name=ipset_name, table=table, chain=chain))

    # lastly remove ipset chain -->
    subprocess.run([BIN_IPTABLES, '-t', table, '-F', ipset_name])
    subprocess.run([BIN_IPTABLES, '-t', table, '-X', ipset_name])


def list_get_local_revision(ipset_listname):
    """
    Retrieve the last successful rule update version
    :param ipset_listname:
    :return:
    :return:
    """

    shelve_db = shelve.open(SHELVE_DBNAME)
    revision = shelve_db.get("{}-{}".format(SHELVE_KEY, ipset_listname), -1)
    shelve_db.close()
    return revision


def list_store_local_revision(ipset_listname, revision_rules):
    """

    :param ipset_listname:
    :param revision_rules:
    """
    shelve_db = shelve.open(SHELVE_DBNAME)
    shelve_db["{}-{}".format(SHELVE_KEY, ipset_listname)] = revision_rules
    shelve_db.close()


def list_get_available_revision(url, ipset_listname=None):
    """

    :param ipset_listname:
    :param url:
    :return:
    """

    revision = -1
    response = requests.get(url)
    response.raise_for_status()
    try:
        revision = int(response.text)
    except Exception as exc:
        print('Error getting revision: {}'.format(exc))
    return revision


def list_update_available(list_revision_url, ipset_listname):
    """

    :param list_revision_url:
    :param ipset_listname:
    :return:
    """
    local_revision = list_get_local_revision(ipset_listname)
    avail_revision = list_get_available_revision(list_revision_url, ipset_listname)

    return local_revision < avail_revision


def list_handle_refresh(ipset_listname, savepath, force_refresh=False):
    if list_update_available(URL_RULES_REVISION, ipset_listname) or force_refresh:
        raw = list_get_content(URL_RULES)
        clean_result = list_convert_and_clean(raw)
        revision = clean_result[0]
        list_clean = clean_result[1]
        ipset_update_list(list_clean, ipset_listname)
        ipset_save(ipset_listname, savepath)
        list_store_local_revision(ipset_listname, revision)


def parse_args():
    action_choices = ['status', 'refresh', 'list-save', 'list-load', 'list=flush', 'activate', 'deactivate']

    user_opts = {
        'table': DEFAULT_IPTABLES_TABLE,
        'chains': [],
        'index': DEFAULT_INDEX,
        'listname': DEFAULT_IPSET_LISTNAME,
        'action': Action.IPTABLES_ACTIVATE,
        'force': False,
        'with_refresh': False
    }

    parser = argparse.ArgumentParser()

    parser.add_argument('action', choices=action_choices, type=str,
                        help='Action to do.')
    parser.add_argument('chains', nargs='+',
                        help='IPTables chains to modify')
    parser.add_argument('--table', default=DEFAULT_IPTABLES_TABLE, type=str,
                        help='IPTables table to work in. Default is filter')
    parser.add_argument('--index', default=DEFAULT_INDEX, type=int,
                        help='index line number to insert ipset check')
    parser.add_argument('--listname', default=DEFAULT_IPSET_LISTNAME, type=str,
                        help='Name of the ipset list to fill')
    # parser.add_argument('--ipset-listname', dest=ipset_listname, default=DEFAULT_IPSET_LISTNAME, type=str,
    #                     help='Name of the ipset list to fill')
    parser.add_argument('--status', action='store_true', dest='status', default=False,
                        help='Show status and list version')
    # parser.add_argument('--configure-only', action='store_true', dest='configure_only', default=False,
    #                     help='No download, only activate iptables config')
    parser.add_argument('--force', action='store_true', default=False,
                        help='Force action even if not needed')
    parser.add_argument('--with-refresh', action='store_true', dest='with_refresh', default=False,
                        help='Before doing the action also do a refresh of the list.')

    args = parser.parse_args()

    if args.action:
        useraction = Action.IPTABLES_ACTIVATE

        if args.action == 'refresh':
            useraction = Action.IPSET_REFRESH
        elif args.action == 'list-save':
            useraction = Action.IPSET_SAVE
        elif args.action == 'list-load':
            useraction = Action.IPSET_LOAD
        elif args.action == 'list-flush':
            useraction = Action.IPSET_FLUSH
        elif args.action == 'activate':
            useraction = Action.IPTABLES_ACTIVATE
        elif args.action == 'deactivate':
            useraction = Action.IPTABLES_DEACTIVATE
        elif args.action == 'status':
            useraction = Action.SHOW_STATUS

        user_opts['action'] = useraction

    if args.chains:
        user_opts['chains'] = args.chains
    if args.index:
        user_opts['index'] = args.index
    if args.listname:
        user_opts['listname'] = args.listname
    if args.with_refresh:
        user_opts['with_refresh'] = args.with_refresh

    return user_opts


def main():

    # with open(os.path.expanduser('~/test/emerging-ips.txt'), 'r') as testfile:
    #     content = testfile.read()
    #
    # res = list_convert_and_clean(content)
    #
    # revi = res[0]
    # exit(0)

    check_requirements()

    user_opts = parse_args()

    action = user_opts['action']
    table = user_opts['table']
    # TODO: handle iteration over list -->
    chain = user_opts['chains'][0]
    iptables_index = user_opts['index']
    ipset_listname = user_opts['listname']
    ipset_savepath = RULE_SAVEFILE.format(ipset_list=ipset_listname)
    force_action = user_opts['force']
    with_refresh = user_opts['with_refresh']

    if with_refresh is True and action != Action.IPSET_REFRESH:
        list_handle_refresh(ipset_listname, ipset_savepath)


    if action == Action.IPSET_LOAD:
        ipset_restore(ipset_savepath)
    elif action == Action.IPSET_IS_LATEST:
        update_available = list_update_available(URL_RULES_REVISION, ipset_listname)

        if update_available:
            print('Newer version available')
        else:
            print('Up to date')
    elif action == Action.IPSET_SAVE:
        ipset_save(ipset_listname, ipset_savepath)
    elif action == Action.IPSET_IS_LOADED:
        ipset_loaded = ipset_check_list_loaded(ipset_listname)
        if ipset_loaded:
            print('IPSet list {} is loaded in memory')
        else:
            print('IPSet list {} is NOT loaded in memory')
    elif action == Action.IPSET_FLUSH:
        ipset_flush(ipset_listname)
    elif action == Action.IPSET_REFRESH:
        list_handle_refresh(ipset_listname, ipset_savepath)
    elif action == Action.IPTABLES_ACTIVATE:

        is_ipset_in_memory = ipset_check_list_loaded(ipset_listname)

        if not is_ipset_in_memory or force_action:
            print('Loading list in ipset...')
            ipset_restore(ipset_savepath)
        else:
            print('List already in ipset memory.')

        iptables_configure_ipset_reference(chain, iptables_index, ipset_listname)
    elif action == Action.IPTABLES_DEACTIVATE:
        print('iptables deactivate')
        iptables_remove_ipset_chain(chain, ipset_listname, table)
    elif action == Action.IPTABLES_IS_IPSET_ACTIVE:
        is_ipset_in_memory = ipset_check_list_loaded(ipset_listname)
        is_ipset_referenced = iptables_check_ipset_referenced(chain, ipset_listname, table=table)
        print('IP set in memory: {}\nIPTables configured: {}'.format(is_ipset_in_memory, is_ipset_referenced))
    elif action == Action.SHOW_STATUS:
        show_status(chain, ipset_listname, table)


if __name__ == '__main__':
    main()
