import getpass
import secrets
import string
import sys
import argparse
from ldap3 import Connection, Reader, Writer, ObjectDef

SECRET_SIZE = 16

SERVER = '127.0.0.1'
BASE_DN = 'dc=example,dc=org'
USER_BASE_DN = BASE_DN

def generate_dn(ip):
    dn = f'radiusClientIdentifier={ip},{BASE_DN}'
    return dn

def generate_secret():
    alphabet = string.ascii_letters + string.digits
    secret = ''.join(secrets.choice(alphabet) for i in range(SECRET_SIZE))
    return secret

def get_user_dn(args):
    if args.dn:
        dn = args.dn
    else:
        if args.user:
            user = args.user
        else:
            user = getpass.getuser()
        dn = f'cn={user},{USER_BASE_DN}'
    return dn

def get_user_password(args):
    if args.password:
        password = args.password
    else:
        password = getpass.getpass()
    return password

def print_clients(clients):
    for client in clients:
        print(f'{str(client.radiusClientIdentifier):15} | {str(client.radiusClientShortname):8} | {str(client.radiusClientSecret):16} | {client.radiusClientComment}')

def list_clients(c, o, args):
    r = Reader(c, o, BASE_DN)
    r.search()
    print_clients(r)

def delete_client(c, o, args):
    if input("Are you sure? (y/N) ") == "y":
        dn = generate_dn(args.ip)
        if c.delete(dn):
            print('Deleted')
        else:
            print('Not found')

def add_client(c, o, args):
    r = Reader(c, o, BASE_DN)
    r.search()
    if r.match('radiusClientIdentifier', args.ip):
        sys.exit("Error: IP already exists")
    if r.match('radiusClientComment', args.name):
        sys.exit("Error: Name already exists")
    if args.secret:
        if r.match('radiusClientSecret', args.secret):
            sys.exit("Error: Secret already exists")
        else:
            secret = args.secret
    else:
        secret = generate_secret()

    w = Writer(c, o)
    dn = generate_dn(args.ip)
    client = w.new(dn)
    client.radiusClientIdentifier = args.ip
    client.radiusClientShortname = args.group
    client.radiusClientSecret = secret
    client.radiusClientComment = args.name
    if (w.commit()):
        print(f'Success | Secret: {secret}')
    else:
        sys.exit("Failed")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Manage radius devices in LDAP")
    parser_user = parser.add_mutually_exclusive_group()
    parser_user.add_argument('-u', '--user', help='Username')
    parser_user.add_argument('-d', '--dn', help='User DN')
    parser.add_argument('-p', '--password', help='Password')
    subparsers = parser.add_subparsers(dest='cmd', required=True, help='Commands')
    parser_list = subparsers.add_parser('list', description='List devices')
    parser_list.set_defaults(func=list_clients)
    parser_del = subparsers.add_parser('del', description='Delete a device')
    parser_del.add_argument('ip', help='IP address of device to delete')
    parser_del.set_defaults(func=delete_client)
    parser_add = subparsers.add_parser('add', description='Add a device')
    parser_add.add_argument('ip', help='IP address of device to add')
    parser_add.add_argument('group', help='Device group')
    parser_add.add_argument('name', help='Fqdn of device')
    parser_add.add_argument('-s', '--secret', help='Unique radius secret')
    parser_add.set_defaults(func=add_client)
    args = parser.parse_args()

    user_dn = get_user_dn(args)
    password = get_user_password(args)

    c = Connection(SERVER, user_dn, password, auto_bind=True)
    o = ObjectDef('radiusClient', c)
    args.func(c, o, args)