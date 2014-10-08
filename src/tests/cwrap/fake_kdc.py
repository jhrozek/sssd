#!/usr/bin/python2

import tempfile
import subprocess
import shutil
import time
import os
import os.path
import signal
from string import Template

mock_kdc_conf = \
"""
[kdcdefaults]
 kdc_ports = $KDC_PORT, $KADMIN_PORT
 kdc_tcp_ports = $KDC_PORT, $KADMIN_PORT

[logging]
 default = FILE:$DIR/krb5.log
 kdc = FILE:$DIR/kdc.log
 admin_server = FILE:$DIR/kadmind.log

[realms]
 $REALM = {
  key_stash_file = $DIR/key_stash
  acl_file = $KADM_ACL_FILE
  admin_keytab = $DIR/kadm5.keytab
  supported_enctypes = aes256-cts:normal aes128-cts:normal des3-hmac-sha1:normal arcfour-hmac:normal camellia256-cts:normal camellia128-cts:normal des-hmac-sha1:normal des-cbc-md5:normal des-cbc-crc:normal
  database_name = $DIR/database
 }
"""

mock_krb5_conf = \
"""
[logging]
 default = FILE:$DIR/krb5.log
 kdc = FILE:$DIR/kdc.log
 admin_server = FILE:$DIR/kadmind.log

[libdefaults]
 dns_lookup_realm = false
 default_realm = $REALM
 rdns = false

[realms]
 $REALM = {
   kdc = $KDC_HOSTNAME:$KDC_PORT
   master_kdc = $KDC_HOSTNAME:$KDC_PORT
   admin_server = $KADMIN_HOSTNAME:$KADMIN_PORT
   kpasswd_server = $KADMIN_HOSTNAME:$KADMIN_PORT
 }

[domain_realm]
 $KDC_HOSTNAME = $REALM
"""

mock_kadm_acl = "*/admin@$REALM      *"

def tmpfile_from_template(template, basename, dir, **subst_dict):
    tmpl = Template(template)
    content = tmpl.substitute(**subst_dict)
    full_path = os.path.join(dir, basename)

    with open(full_path, 'w') as f:
        f.write(content)
        f.flush()

    return full_path

def mock_kdc(wdir, users):
    subst_dict = {
            'REALM' : 'SSSD.MOCK',
            'KDC_HOSTNAME' : 'localhost',
            'KADMIN_HOSTNAME' : 'localhost',
            'KDC_PORT' : '20088',
            'KADMIN_PORT' : '20750',
            'DIR' : wdir,
    }

    env = dict(os.environ)

    kadm_acl = tmpfile_from_template(mock_kadm_acl, 'kadm5.acl', wdir, **subst_dict)

    subst_dict['KADM_ACL_FILE'] = kadm_acl
    kdc_conf = tmpfile_from_template(mock_kdc_conf, 'kdc.conf', wdir, **subst_dict)
    env['KRB5_KDC_PROFILE'] = kdc_conf

    krb5_conf = tmpfile_from_template(mock_krb5_conf, 'krb5.conf', wdir, **subst_dict)
    env['KRB5_CONFIG'] = krb5_conf

    # Generate the KDC database, undocumented -W argument: no strong random
    kdb_util = subprocess.Popen(['kdb5_util', 'create', '-r',
                                 subst_dict['REALM'], '-s', '-W',
                                 '-P', 'foobar'],
                                 env = env,
                                 cwd = wdir)
    kdb_util.communicate()

    addprinc_cmd = [ 'kadmin.local', '-r', subst_dict['REALM'], '-q' ]

    for username, password in users.iteritems():
        addprinc_arg = 'addprinc -pw %s -clearpolicy %s' % (password, username)
        kadmin = subprocess.Popen(addprinc_cmd + [addprinc_arg],
                                  env = env, cwd = wdir)
        kadmin.communicate()

    pidfile = os.path.join(wdir, "kdc.pid")
    kdc = subprocess.Popen(['krb5kdc', '-P', pidfile, '-r', subst_dict['REALM']],
                           env = env, cwd = wdir)
    kdc.communicate()

    # Wait for the KDC to come up
    for i in range(1, 10):
        try:
            with open(pidfile) as pf:
                pid = int(pf.read())
        except IOError:
            time.sleep(1)

    return (krb5_conf, pid)

if __name__ == "__main__":
    users = { 'root/admin' : 'TurboGoesToRocket',
              'foobar' : 'Secret123' }
    realm = 'SSSD.MOCK'

    wdir = tempfile.mkdtemp(prefix='sssd_mock_kdc')
    kdc_pid = None
    try:
        krb5_conf, kdc_pid = mock_kdc(wdir, users)
        print "KRB5_CONFIG=%s" % krb5_conf
        print "PID=%d" % kdc_pid
        raw_input()
    finally:
        shutil.rmtree(wdir)
        if kdc_pid:
            os.kill(kdc_pid, signal.SIGTERM)
