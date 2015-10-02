#
# LDAP integration test
#
# Copyright (c) 2015 Red Hat, Inc.
# Author: Nikolai Kondrashov <Nikolai.Kondrashov@redhat.com>
#
# This is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 only
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
import os
import sys
import stat
import pwd
import grp
import ent
import config
import signal
import subprocess
import time
import ldap
import pytest
import ds_openldap
import ldap_ent
from util import *

LDAP_BASE_DN="dc=example,dc=com"


@pytest.fixture(scope="module")
def ds_inst(request):
    """LDAP server instance fixture"""
    ds_inst = ds_openldap.DSOpenLDAP(
                config.PREFIX, 10389, LDAP_BASE_DN,
                "cn=admin", "Secret123")
    try:
        ds_inst.setup()
    except:
        ds_inst.teardown()
        raise
    request.addfinalizer(lambda: ds_inst.teardown())
    return ds_inst


@pytest.fixture(scope="module")
def ldap_conn(request, ds_inst):
    """LDAP server connection fixture"""
    ldap_conn = ds_inst.bind()
    ldap_conn.ds_inst = ds_inst
    request.addfinalizer(lambda: ldap_conn.unbind_s())
    return ldap_conn


def create_ldap_entries(ldap_conn, ent_list = None):
    """Add LDAP entries from ent_list"""
    if ent_list != None:
        for entry in ent_list:
            ldap_conn.add_s(entry[0], entry[1])


def cleanup_ldap_entries(ldap_conn, ent_list = None):
    """Remove LDAP entries added by create_ldap_entries"""
    if ent_list == None:
        for ou in ("Users", "Groups", "Netgroups", "Services", "Policies"):
            for entry in ldap_conn.search_s("ou=" + ou + "," +
                                            ldap_conn.ds_inst.base_dn,
                                            ldap.SCOPE_ONELEVEL,
                                            attrlist=[]):
                ldap_conn.delete_s(entry[0])
    else:
        for entry in ent_list:
            ldap_conn.delete_s(entry[0])


def create_ldap_cleanup(request, ldap_conn, ent_list = None):
    """Add teardown for removing all user/group LDAP entries"""
    request.addfinalizer(lambda: cleanup_ldap_entries(ldap_conn, ent_list))


def create_ldap_fixture(request, ldap_conn, ent_list = None):
    """Add LDAP entries and add teardown for removing them"""
    create_ldap_entries(ldap_conn, ent_list)
    create_ldap_cleanup(request, ldap_conn, ent_list)


def format_basic_conf(ldap_conn, bis, enum):
    """Format a basic SSSD configuration"""
    if bis:
        schema_conf = unindent("""\
            ldap_schema             = rfc2307bis
            ldap_group_object_class = groupOfNames
        """)
    else:
        schema_conf = unindent("""\
            ldap_schema             = rfc2307
        """)
    return unindent("""\
        [sssd]
        debug_level         = 0xffff
        domains             = LDAP
        services            = nss, pam

        [nss]
        debug_level         = 0xffff
        memcache_timeout    = 0

        [pam]
        debug_level         = 0xffff

        [domain/LDAP]
        ldap_auth_disable_tls_never_use_in_production = true
        debug_level         = 0xffff
        enumerate           = {enum}
        {schema_conf}
        id_provider         = ldap
        auth_provider       = ldap
        ldap_uri            = {ldap_conn.ds_inst.ldap_url}
        ldap_search_base    = {ldap_conn.ds_inst.base_dn}
    """).format(**locals())


def create_conf_file(contents):
    """Create sssd.conf with specified contents"""
    conf = open(config.CONF_PATH, "w")
    conf.write(contents)
    conf.close()
    os.chmod(config.CONF_PATH, stat.S_IRUSR | stat.S_IWUSR)


def cleanup_conf_file():
    """Remove sssd.conf, if it exists"""
    if os.path.lexists(config.CONF_PATH):
        os.unlink(config.CONF_PATH)


def create_conf_cleanup(request):
    """Add teardown for removing sssd.conf"""
    request.addfinalizer(cleanup_conf_file)


def create_conf_fixture(request, contents):
    """
    Create sssd.conf with specified contents and add teardown for removing it
    """
    create_conf_file(contents)
    create_conf_cleanup(request)


def create_sssd_process():
    """Start the SSSD process"""
    if subprocess.call(["sssd", "-D", "-f"]) != 0:
        raise Exception("sssd start failed")


def cleanup_sssd_process():
    """Stop the SSSD process and remove its state"""
    try:
        pid_file = open(config.PIDFILE_PATH, "r")
        pid = int(pid_file.read())
        os.kill(pid, signal.SIGTERM)
        while True:
            try:
                os.kill(pid, signal.SIGCONT)
            except:
                break
            time.sleep(1)
    except:
        pass
    subprocess.call(["sss_cache", "-E"])
    for path in os.listdir(config.DB_PATH):
        os.unlink(config.DB_PATH + "/" + path)
    for path in os.listdir(config.MCACHE_PATH):
        os.unlink(config.MCACHE_PATH + "/" + path)


def create_sssd_cleanup(request):
    """Add teardown for stopping SSSD and removing its state"""
    request.addfinalizer(cleanup_sssd_process)


def create_sssd_fixture(request):
    """Start SSSD and add teardown for stopping it and removing its state"""
    create_sssd_process()
    create_sssd_cleanup(request)


@pytest.fixture
def sanity(request, ldap_conn):
    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)
    ent_list.add_user("user1", 1001, 2001)
    ent_list.add_user("user2", 1002, 2002)
    ent_list.add_user("user3", 1003, 2003)

    ent_list.add_group("group1", 2001)
    ent_list.add_group("group2", 2002)
    ent_list.add_group("group3", 2003)

    ent_list.add_group("empty_group", 2010)

    ent_list.add_group("two_user_group", 2012, ["user1", "user2"])
    create_ldap_fixture(request, ldap_conn, ent_list)

    create_conf_fixture(request, format_basic_conf(ldap_conn, False, True))
    create_sssd_fixture(request)
    return None


@pytest.fixture
def simple(request, ldap_conn):
    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)
    ent_list.add_user('usr\\\\001', 181818, 181818)
    ent_list.add_group("group1", 181818)
    create_ldap_fixture(request, ldap_conn, ent_list)
    create_conf_fixture(request, format_basic_conf(ldap_conn, False, False))
    create_sssd_fixture(request)
    return None


@pytest.fixture
def sanity_bis(request, ldap_conn):
    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)
    ent_list.add_user("user1", 1001, 2001)
    ent_list.add_user("user2", 1002, 2002)
    ent_list.add_user("user3", 1003, 2003)

    ent_list.add_group_bis("group1", 2001)
    ent_list.add_group_bis("group2", 2002)
    ent_list.add_group_bis("group3", 2003)

    ent_list.add_group_bis("empty_group1", 2010)
    ent_list.add_group_bis("empty_group2", 2011)

    ent_list.add_group_bis("two_user_group", 2012, ["user1", "user2"])
    ent_list.add_group_bis("group_empty_group", 2013, [], ["empty_group1"])
    ent_list.add_group_bis("group_two_empty_groups", 2014,
                           [], ["empty_group1", "empty_group2"])
    ent_list.add_group_bis("one_user_group1", 2015, ["user1"])
    ent_list.add_group_bis("one_user_group2", 2016, ["user2"])
    ent_list.add_group_bis("group_one_user_group", 2017,
                           [], ["one_user_group1"])
    ent_list.add_group_bis("group_two_user_group", 2018,
                           [], ["two_user_group"])
    ent_list.add_group_bis("group_two_one_user_groups", 2019,
                           [], ["one_user_group1", "one_user_group2"])

    create_ldap_fixture(request, ldap_conn, ent_list)
    create_conf_fixture(request, format_basic_conf(ldap_conn, True, True))
    create_sssd_fixture(request)
    return None


def test_regression_ticket2163(ldap_conn, simple):
    ent.assert_passwd_by_name(
        'usr\\001',
        dict(name='usr\\001', passwd='*', uid=181818, gid=181818,
             gecos='181818', shell='/bin/bash'))


def test_sanity(ldap_conn, sanity):
    passwd_pattern = ent.contains_only(
        dict(name='user1', passwd='*', uid=1001, gid=2001, gecos='1001', dir='/home/user1', shell='/bin/bash'),
        dict(name='user2', passwd='*', uid=1002, gid=2002, gecos='1002', dir='/home/user2', shell='/bin/bash'),
        dict(name='user3', passwd='*', uid=1003, gid=2003, gecos='1003', dir='/home/user3', shell='/bin/bash')
    )
    ent.assert_passwd(passwd_pattern)

    group_pattern = ent.contains_only(
        dict(name='group1', passwd='*', gid=2001, mem=ent.contains_only()),
        dict(name='group2', passwd='*', gid=2002, mem=ent.contains_only()),
        dict(name='group3', passwd='*', gid=2003, mem=ent.contains_only()),
        dict(name='empty_group', passwd='*', gid=2010, mem=ent.contains_only()),
        dict(name='two_user_group', passwd='*', gid=2012, mem=ent.contains_only("user1", "user2"))
    )
    ent.assert_group(group_pattern)

    with pytest.raises(KeyError):
        pwd.getpwnam("non_existent_user")
    with pytest.raises(KeyError):
        pwd.getpwuid(1)
    with pytest.raises(KeyError):
        grp.getgrnam("non_existent_group")
    with pytest.raises(KeyError):
        grp.getgrgid(1)


def test_sanity_bis(ldap_conn, sanity_bis):
    passwd_pattern = ent.contains_only(
        dict(name='user1', passwd='*', uid=1001, gid=2001, gecos='1001', dir='/home/user1', shell='/bin/bash'),
        dict(name='user2', passwd='*', uid=1002, gid=2002, gecos='1002', dir='/home/user2', shell='/bin/bash'),
        dict(name='user3', passwd='*', uid=1003, gid=2003, gecos='1003', dir='/home/user3', shell='/bin/bash')
    )
    ent.assert_passwd(passwd_pattern)

    group_pattern = ent.contains_only(
        dict(name='group1', passwd='*', gid=2001, mem=ent.contains_only()),
        dict(name='group2', passwd='*', gid=2002, mem=ent.contains_only()),
        dict(name='group3', passwd='*', gid=2003, mem=ent.contains_only()),
        dict(name='empty_group1', passwd='*', gid=2010, mem=ent.contains_only()),
        dict(name='empty_group2', passwd='*', gid=2011, mem=ent.contains_only()),
        dict(name='two_user_group', passwd='*', gid=2012, mem=ent.contains_only("user1", "user2")),
        dict(name='group_empty_group', passwd='*', gid=2013, mem=ent.contains_only()),
        dict(name='group_two_empty_groups', passwd='*', gid=2014, mem=ent.contains_only()),
        dict(name='one_user_group1', passwd='*', gid=2015, mem=ent.contains_only("user1")),
        dict(name='one_user_group2', passwd='*', gid=2016, mem=ent.contains_only("user2")),
        dict(name='group_one_user_group', passwd='*', gid=2017, mem=ent.contains_only("user1")),
        dict(name='group_two_user_group', passwd='*', gid=2018, mem=ent.contains_only("user1", "user2")),
        dict(name='group_two_one_user_groups', passwd='*', gid=2019, mem=ent.contains_only("user1", "user2"))
    )
    ent.assert_group(group_pattern)

    with pytest.raises(KeyError):
        pwd.getpwnam("non_existent_user")
    with pytest.raises(KeyError):
        pwd.getpwuid(1)
    with pytest.raises(KeyError):
        grp.getgrnam("non_existent_group")
    with pytest.raises(KeyError):
        grp.getgrgid(1)


@pytest.fixture
def refresh_after_cleanup_task(request, ldap_conn):
    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)
    ent_list.add_user("user1", 1001, 2001)

    ent_list.add_group_bis("group1", 2001, ["user1"])
    ent_list.add_group_bis("group2", 2002, [], ["group1"])

    create_ldap_fixture(request, ldap_conn, ent_list)

    conf = \
        format_basic_conf(ldap_conn, True, False) + \
        unindent("""
            [domain/LDAP]
            entry_cache_user_timeout = 1
            entry_cache_group_timeout = 5000
            ldap_purge_cache_timeout = 3
        """).format(**locals())
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)
    return None


def test_refresh_after_cleanup_task(ldap_conn, refresh_after_cleanup_task):
    """
    Regression test for ticket:
    https://fedorahosted.org/sssd/ticket/2676
    """
    ent.assert_group_by_name(
        "group2",
        dict(mem=ent.contains_only("user1")))

    ent.assert_passwd_by_name(
        'user1',
        dict(name='user1', passwd='*', uid=1001, gid=2001,
             gecos='1001', shell='/bin/bash'))

    time.sleep(15)

    ent.assert_group_by_name(
        "group2",
        dict(mem=ent.contains_only("user1")))
