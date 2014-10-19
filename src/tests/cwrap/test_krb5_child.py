#!/usr/bin/python2

import unittest
import os
import os.path
import sys
import tempfile
import subprocess
import shutil
import signal

from fake_kdc import mock_kdc

test_bin = '../../../krb5-child-test'

class Krb5ChildTest(unittest.TestCase):
    def setUp(self):
        # No point in running the tests without wrappers in place
        self.assertWrappers()

        # It would be nice to not pollute /tmp with testing data, but
        # it's not really possible to chown a directory to the test user
        # either
        self.ccache_dir = '/tmp'
        self.realm = 'SSSD.MOCK'
        self.users = { 'root/admin' : 'TurboGoesToRocket',
                       'foobar' : 'Secret123' }

        self.wdir = tempfile.mkdtemp(prefix='sssd_mock_kdc')

        self.krb5_conf, self.kdc_pid = mock_kdc(self.wdir, self.users)
        self.env = dict(os.environ)
        self.env['KRB5_CONFIG'] = self.krb5_conf

    def tearDown(self):
        os.kill(self.kdc_pid, signal.SIGTERM)
        shutil.rmtree(self.wdir)

    def testKinit(self):
        username = 'foobar'

        child_test = subprocess.Popen([test_bin, '-u', username,
                                     '-w', self.users[username],
                                     '-r', self.realm,
                                     '--debug', '10',
                                     '-c', 'FILE:%s' % self.ccache_path(username),
                                     '-k'],
                                     env = self.env)
        child_test.communicate()
        self.assertEqual(child_test.returncode, 0)
        self.assertPrincipalInCcache(self.principal(username, self.realm),
                                     self.ccache_path(username))

    def testKinitBadPassword(self):
        username = 'foobar'

        child_test = subprocess.Popen([test_bin, '-u', username,
                                     '-w', 'NotTheRightOne',
                                     '-r', self.realm,
                                     '--debug', '10',
                                     '-c', 'FILE:%s' % self.ccache_path(username)],
                                     env = self.env)
        child_test.communicate()
        self.assertEqual(child_test.returncode, 6)

    #def testChpass(self):
    #    username = 'foobar'

    #    oldpass = self.users[username]
    #    self.users[username] = 'ThisIsANewPassword'

    #    child_test = subprocess.Popen([test_bin, '--chpass', '-u', username,
    #                                 '-w', oldpass,
    #                                 '--new-password', self.users[username],
    #                                 '-r', self.realm,
    #                                 '--debug', '10',
    #                                 '-c', 'FILE:%s' % self.ccache_path(username),
    #                                 '-k'],
    #                                 env = self.env)
    #    child_test.communicate()
    #    self.assertEqual(child_test.returncode, 0)
    #    self.assertPrincipalInCcache(self.principal(username, self.realm),
    #                                 self.ccache_path(username))

    def assertPrincipalInCcache(self, principal, ccache):
        klist = subprocess.Popen(['klist', ccache], stdout=subprocess.PIPE)
        klist.communicate()
        # FIXME - open the ccache with python-kerberos and check the contents
        self.assertEqual(klist.returncode, 0)

    def assertWrappers(self):
        required_vars = [ 'UID_WRAPPER', 'UID_WRAPPER_ROOT',
                          'NSS_WRAPPER_PASSWD', 'NSS_WRAPPER_GROUP' ]
        for v in required_vars:
            assert v in os.environ

    def principal(self, username, realm):
        return '%s@%s' % (username, realm)

    def ccache_path(self, username):
        return os.path.join(self.ccache_dir, "%s_ccache" % username)

if __name__ == "__main__":
    error = 0

    try:
        subprocess.call(["krb5kdc"])
    except OSError as e:
        if e.errno == os.errno.ENOENT:
            print "KRB5KDC not found, cannot run tests!\n"
            sys.exit(error)
        else:
            # Something else went wrong while trying to run `wget`
            raise

    suite = unittest.TestLoader().loadTestsFromTestCase(Krb5ChildTest)
    res = unittest.TextTestRunner().run(suite)
    if not res.wasSuccessful():
        error |= 0x1

    sys.exit(error)
