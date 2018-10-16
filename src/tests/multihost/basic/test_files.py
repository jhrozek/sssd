"""
Files test provider cases
"""
import pytest
from sssd.testlib.common.utils import SSHClient


def get_sss_entry(multihost, db, ent_name):
    cmd = multihost.master[0].run_command(
                                    'getent %s -s sss %s' % (db, ent_name),
                                    raiseonerr=False)
    return cmd.returncode, cmd.stdout_text


def get_sss_user(multihost, username):
    return get_sss_entry(multihost, 'passwd', username)

@pytest.fixture
def record_user_and_group(request, session_multihost):
    users = ('recuser_direct', 'recuser_group')
    groups = ('recgroup', )

    for user in users:
        useradd_cmd = "useradd %s" % (user)
        session_multihost.master[0].run_command(useradd_cmd)

    for group in groups:
        groupadd_cmd = "groupadd %s" % (group)
        session_multihost.master[0].run_command(groupadd_cmd)

    usermod_cmd = "usermod -a -G %s %s" % ('recgroup', 'recuser_group')
    session_multihost.master[0].run_command(usermod_cmd)

    def teardown_record_user_and_group():
        for user in users:
            userdel_cmd = "userdel %s" % (user)
            session_multihost.master[0].run_command(userdel_cmd)
        for group in groups:
            groupdel_cmd = "groupdel %s" % (group)
            session_multihost.master[0].run_command(groupdel_cmd)
    request.addfinalizer(teardown_files_domain_users)


@pytest.fixture
def setup_session_recording(request, session_multihost):
    session_multihost.master[0].transport.get_file('/etc/sssd/sssd.conf',
                                                   '/tmp/sssd.conf')
    sssdconfig = ConfigParser.SafeConfigParser()
    sssdconfig.read('/tmp/sssd.conf')
    sssd_section = 'sssd'
    if sssd_section in sssdconfig.sections():
        sssdconfig.set(sssd_section, 'enable_files_domain', 'true')
        with open('/tmp/sssd.conf', "w") as sssconf:
            sssdconfig.write(sssconf)
    session_multihost.master[0].transport.put_file('/tmp/sssd.conf',
                                                   '/etc/sssd/sssd.conf')
    session_multihost.master[0].service_sssd('restart')

@pytest.mark.usefixtures('enable_files_domain', 'files_domain_users_class')
class TestImplicitFilesProvider(object):
    """
    Test the files provider. This test runs the implicit files provider
    together with another domain to stick close to what users use in Fedora
    """
    def test_files_does_not_handle_root(self, multihost):
        """ The files provider does not handle root """
        exit_status, _ = get_sss_user(multihost, 'root')
        assert exit_status == 2

    def test_files_sanity(self, multihost):
        """ Test that the files provider can resolve a user """
        exit_status, _ = get_sss_user(multihost, 'lcl1')
        assert exit_status == 0

    def test_files_enumeration(self, multihost):
        """
        Since nss_files enumerates and libc would concatenate the results,
        the files provider of SSSD should not enumerate
        """
        cmd = multihost.master[0].run_command('getent passwd -s sss')
        assert len(cmd.stdout_text) == 0

    def test_files_session_recording(self, multihost, record_user_and_group):
        """
        A regression test for #3855 session not recording for local user
        when groups defined
        """
        pass
