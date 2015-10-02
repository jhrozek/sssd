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


def format_basic_conf(ldap_conn, schema, enum):
    """Format a basic SSSD configuration"""
    schema_conf = unindent("""\
        ldap_schema             = {schema}
    """).format(**locals())

    if schema == 'rfc2307bis':
        schema_conf += unindent("""
            ldap_group_object_class = groupOfNames
        """).format(**locals())

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

def format_conf_2307(ldap_conn, enum):
    """Format a basic SSSD configuration for the rfc2307 schema"""
    return format_basic_conf(ldap_conn, "rfc2307", enum);


def format_conf_2307_bis(ldap_conn, enum):
    """Format a basic SSSD configuration for the rfc2307bis schema"""
    return format_basic_conf(ldap_conn, "rfc2307bis", enum);


def format_conf_ad(ldap_conn, enum):
    """Format a basic SSSD configuration for the AD LDAP schema"""
    return format_basic_conf(ldap_conn, "ad", enum);


def format_interactive_conf_2307(ldap_conn):
    """
       Format an SSSD configuration with all caches refreshing in 4 seconds
       using the rfc2307 schema
    """
    return \
        format_conf_2307(ldap_conn, True) + \
        unindent("""
            [nss]
            memcache_timeout                    = 4
            enum_cache_timeout                  = 4
            entry_negative_timeout              = 4

            [domain/LDAP]
            ldap_enumeration_refresh_timeout    = 4
            ldap_purge_cache_timeout            = 1
            entry_cache_timeout                 = 4
        """)

def format_interactive_conf_2307bis(ldap_conn):
    """
       Format an SSSD configuration with all caches refreshing in 4 seconds
       using the rfc2307bis schema
    """
    return \
        format_conf_2307_bis(ldap_conn, True) + \
        unindent("""
            [nss]
            memcache_timeout                    = 4
            enum_cache_timeout                  = 4
            entry_negative_timeout              = 4

            [domain/LDAP]
            ldap_enumeration_refresh_timeout    = 4
            ldap_purge_cache_timeout            = 1
            entry_cache_timeout                 = 4
        """)


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

    create_conf_fixture(request, format_conf_2307(ldap_conn, True))
    create_sssd_fixture(request)
    return None


@pytest.fixture
def simple(request, ldap_conn):
    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)
    ent_list.add_user('usr\\\\001', 181818, 181818)
    ent_list.add_group("group1", 181818)
    create_ldap_fixture(request, ldap_conn, ent_list)
    create_conf_fixture(request, format_conf_2307(ldap_conn, False))
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
    create_conf_fixture(request, format_conf_2307_bis(ldap_conn, True))
    create_sssd_fixture(request)
    return None

@pytest.fixture
def neg_posix_attrs(request, ldap_conn):
    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)
    ent_list.add_user('neg_user', -1, -1)
    create_ldap_fixture(request, ldap_conn, ent_list)
    conf = \
        format_conf_ad(ldap_conn, False) + \
        unindent("""
            [domain/LDAP]
            ldap_user_object_class = posixAccount
            ldap_user_name = uid
        """).format(**locals())
    print conf
    create_conf_fixture(request, conf)
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
        format_conf_2307_bis(ldap_conn, False) + \
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


@pytest.fixture
def blank(request, ldap_conn):
    """Create blank RFC2307 directory fixture with interactive SSSD conf"""
    create_ldap_cleanup(request, ldap_conn)
    create_conf_fixture(request, format_interactive_conf_2307(ldap_conn))
    create_sssd_fixture(request)


@pytest.fixture
def blank_bis(request, ldap_conn):
    """Create blank RFC2307bis directory fixture with interactive SSSD conf"""
    create_ldap_cleanup(request, ldap_conn)
    create_conf_fixture(request, format_interactive_conf_2307bis(ldap_conn))
    create_sssd_fixture(request)


@pytest.fixture
def user_and_group(request, ldap_conn):
    """
    Create an RFC2307 directory fixture with interactive SSSD conf,
    one user and one group
    """
    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)
    ent_list.add_user("user", 1001, 2000)
    ent_list.add_group("group", 2001)
    create_ldap_fixture(request, ldap_conn, ent_list)
    create_conf_fixture(request, format_interactive_conf_2307(ldap_conn))
    create_sssd_fixture(request)
    return None


@pytest.fixture
def user_and_groups_bis(request, ldap_conn):
    """
    Create an RFC2307bis directory fixture with interactive SSSD conf,
    one user and two groups
    """
    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)
    ent_list.add_user("user", 1001, 2000)
    ent_list.add_group_bis("group1", 2001)
    ent_list.add_group_bis("group2", 2002)
    create_ldap_fixture(request, ldap_conn, ent_list)
    create_conf_fixture(request, format_interactive_conf_2307bis(ldap_conn))
    create_sssd_fixture(request)
    return None


def test_add_remove_user(ldap_conn, blank):
    """Test user addition and removal are reflected by SSSD"""
    e = ldap_ent.user(ldap_conn.ds_inst.base_dn, "user", 1001, 2000)
    time.sleep(2)
    # Add the user
    ent.assert_passwd(ent.contains_only())
    ldap_conn.add_s(*e)
    ent.assert_passwd(ent.contains_only())
    time.sleep(4)
    ent.assert_passwd(ent.contains_only(dict(name="user", uid=1001)))
    # Remove the user
    ldap_conn.delete_s(e[0])
    ent.assert_passwd(ent.contains_only(dict(name="user", uid=1001)))
    time.sleep(4)
    ent.assert_passwd(ent.contains_only())


def test_add_remove_group(ldap_conn, blank):
    """Test RFC2307 group addition and removal are reflected by SSSD"""
    e = ldap_ent.group(ldap_conn.ds_inst.base_dn, "group", 2001)
    time.sleep(2)
    # Add the group
    ent.assert_group(ent.contains_only())
    ldap_conn.add_s(*e)
    ent.assert_group(ent.contains_only())
    time.sleep(4)
    ent.assert_group(ent.contains_only(dict(name="group", gid=2001)))
    # Remove the group
    ldap_conn.delete_s(e[0])
    ent.assert_group(ent.contains_only(dict(name="group", gid=2001)))
    time.sleep(4)
    ent.assert_group(ent.contains_only())


def test_add_remove_group_bis(ldap_conn, blank_bis):
    """Test RFC2307bis group addition and removal are reflected by SSSD"""
    e = ldap_ent.group_bis(ldap_conn.ds_inst.base_dn, "group", 2001)
    time.sleep(2)
    # Add the group
    ent.assert_group(ent.contains_only())
    ldap_conn.add_s(*e)
    ent.assert_group(ent.contains_only())
    time.sleep(4)
    ent.assert_group(ent.contains_only(dict(name="group", gid=2001)))
    # Remove the group
    ldap_conn.delete_s(e[0])
    ent.assert_group(ent.contains_only(dict(name="group", gid=2001)))
    time.sleep(4)
    ent.assert_group(ent.contains_only())


def test_add_remove_membership(ldap_conn, user_and_group):
    """Test user membership addition and removal are reflected by SSSD"""
    time.sleep(2)
    # Add user to group
    ent.assert_group_by_name("group", dict(mem = ent.contains_only()))
    ldap_conn.modify_s("cn=group,ou=Groups," + ldap_conn.ds_inst.base_dn,
                       [(ldap.MOD_REPLACE, "memberUid", "user")])
    ent.assert_group_by_name("group", dict(mem = ent.contains_only()))
    time.sleep(4)
    ent.assert_group_by_name("group", dict(mem = ent.contains_only("user")))
    # Remove user from group
    ldap_conn.modify_s("cn=group,ou=Groups," + ldap_conn.ds_inst.base_dn,
                       [(ldap.MOD_DELETE, "memberUid", None)])
    ent.assert_group_by_name("group", dict(mem = ent.contains_only("user")))
    time.sleep(4)
    ent.assert_group_by_name("group", dict(mem = ent.contains_only()))


def test_add_remove_membership_bis(ldap_conn, user_and_groups_bis):
    """
    Test user and group membership addition and removal are reflected by SSSD,
    with RFC2307bis schema
    """
    time.sleep(2)
    # Add user to group1
    ent.assert_group_by_name("group1", dict(mem = ent.contains_only()))
    ldap_conn.modify_s("cn=group1,ou=Groups," + ldap_conn.ds_inst.base_dn,
                       [(ldap.MOD_REPLACE, "member",
                         "uid=user,ou=Users," + ldap_conn.ds_inst.base_dn)])
    ent.assert_group_by_name("group1", dict(mem = ent.contains_only()))
    time.sleep(4)
    ent.assert_group_by_name("group1", dict(mem = ent.contains_only("user")))

    # Add group1 to group2
    ldap_conn.modify_s("cn=group2,ou=Groups," + ldap_conn.ds_inst.base_dn,
                       [(ldap.MOD_REPLACE, "member",
                         "cn=group1,ou=Groups," + ldap_conn.ds_inst.base_dn)])
    ent.assert_group_by_name("group2", dict(mem = ent.contains_only()))
    time.sleep(4)
    ent.assert_group_by_name("group2", dict(mem = ent.contains_only("user")))

    # Remove group1 from group2
    ldap_conn.modify_s("cn=group2,ou=Groups," + ldap_conn.ds_inst.base_dn,
                       [(ldap.MOD_DELETE, "member", None)])
    ent.assert_group_by_name("group2", dict(mem = ent.contains_only("user")))
    time.sleep(4)
    ent.assert_group_by_name("group2", dict(mem = ent.contains_only()))

    # Remove user from group1
    ldap_conn.modify_s("cn=group1,ou=Groups," + ldap_conn.ds_inst.base_dn,
                       [(ldap.MOD_DELETE, "member", None)])
    ent.assert_group_by_name("group1", dict(mem = ent.contains_only("user")))
    time.sleep(4)
    ent.assert_group_by_name("group1", dict(mem = ent.contains_only()))


@pytest.fixture
def blank(request, ldap_conn):
    """Create blank RFC2307 directory fixture with interactive SSSD conf"""
    create_ldap_cleanup(request, ldap_conn)
    create_conf_fixture(request, format_interactive_conf_2307(ldap_conn))
    create_sssd_fixture(request)


@pytest.fixture
def void_conf(request):
    create_conf_cleanup(request)


@pytest.fixture
def void_sssd(request):
    create_sssd_cleanup(request)


@pytest.fixture
def three_users_three_groups(request, ldap_conn):
    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)
    ent_list.add_user("user1", 1001, 2001)
    ent_list.add_user("user2", 1002, 2002)
    ent_list.add_user("user3", 1003, 2003)
    ent_list.add_group("group1", 2001, ["user1"])
    ent_list.add_group("group2", 2002, ["user2"])
    ent_list.add_group("group3", 2003, ["user3"])
    create_ldap_fixture(request, ldap_conn, ent_list)


def test_filter_users(request, ldap_conn, three_users_three_groups,
                      void_conf, void_sssd):
    """Test the effect of the "filter_users" option"""
    all_users = frozenset([1, 2, 3])
    for filter_users_in_groups in [False, True]:
        for filter_users in [frozenset([]),
                             frozenset([1]),
                             frozenset([1, 2]),
                             frozenset([1, 2, 3])]:
            unfiltered_users = all_users - filter_users
            filter_users_str = ",".join(map(lambda i: "user" + str(i),
                                            filter_users))

            conf = \
                format_conf_2307(ldap_conn, True) + \
                unindent("""
                    [nss]
                    filter_users            = {filter_users_str}
                    filter_users_in_groups  = {filter_users_in_groups}
                """).format(**locals())
            create_conf_file(conf)
            create_sssd_process()
            ent.assert_passwd(
                ent.contains_only(
                    *map(
                        lambda i: \
                            dict(name = "user" + str(i), uid = 1000 + i),
                        unfiltered_users
                    )
                )
            )
            ent.assert_group(
                ent.contains_only(
                    *map(
                        lambda i: \
                            dict(
                                name = "group" + str(i),
                                gid = 2000 + i,
                                mem = ent.contains_only() \
                                        if filter_users_in_groups and \
                                           i in filter_users else \
                                            ent.contains_only("user" + str(i))
                            ),
                        all_users
                    )
                )
            )
            cleanup_sssd_process()
            cleanup_conf_file()


def test_filter_groups(request, ldap_conn, three_users_three_groups,
                       void_conf, void_sssd):
    """Test the effect of the "filter_groups" option with RFC2307 groups"""
    all_groups = frozenset([1, 2, 3])
    for filter_groups in [frozenset([]),
                          frozenset([1]),
                          frozenset([1, 2]),
                          frozenset([1, 2, 3])]:
        unfiltered_groups = all_groups - filter_groups
        filter_groups_str = ",".join(map(lambda i: "group" + str(i),
                                         filter_groups))

        conf = \
            format_conf_2307(ldap_conn, True) + \
            unindent("""
                [nss]
                filter_groups   = {filter_groups_str}
            """).format(**locals())
        create_conf_file(conf)
        create_sssd_process()
        ent.assert_group(
            ent.contains_only(
                *map(
                    lambda i: \
                        dict(
                            name = "group" + str(i),
                            gid = 2000 + i,
                            mem = ent.contains_only("user" + str(i))
                        ),
                    unfiltered_groups
                )
            )
        )
        cleanup_sssd_process()
        cleanup_conf_file()


@pytest.fixture
def three_users_three_groups_bis(request, ldap_conn):
    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)
    ent_list.add_user("user1", 1001, 2001)
    ent_list.add_user("user2", 1002, 2002)
    ent_list.add_user("user3", 1003, 2003)
    ent_list.add_group_bis("group1", 2001, ["user1"])
    ent_list.add_group_bis("group2", 2002, ["user2"], ["group1"])
    ent_list.add_group_bis("group3", 2003, ["user3"], ["group2"])
    create_ldap_fixture(request, ldap_conn, ent_list)


def test_filter_groups_bis(request, ldap_conn, three_users_three_groups_bis,
                           void_conf, void_sssd):
    """Test the effect of the "filter_groups" option with RFC2307bis groups"""
    all_groups = frozenset([1, 2, 3])
    for filter_groups in [frozenset([]),
                          frozenset([1]),
                          frozenset([1, 2]),
                          frozenset([1, 2, 3])]:
        unfiltered_groups = all_groups - filter_groups
        filter_groups_str = ",".join(map(lambda i: "group" + str(i),
                                         filter_groups))

        conf = \
            format_conf_2307_bis(ldap_conn, True) + \
            unindent("""
                [nss]
                filter_groups   = {filter_groups_str}
            """).format(**locals())
        create_conf_file(conf)
        create_sssd_process()
        ent.assert_group(
            ent.contains_only(
                *map(
                    lambda i: \
                        dict(
                            name = "group" + str(i),
                            gid = 2000 + i,
                            mem = ent.contains_only(
                                    *map(lambda j: "user" + str(j),
                                         range(1, i + 1)))
                        ),
                    unfiltered_groups
                )
            )
        )
        cleanup_sssd_process()
        cleanup_conf_file()


@pytest.fixture
def override_homedir(request, ldap_conn):
    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)
    ent_list.add_user("user_with_homedir_A", 1001, 2001,
                      homeDirectory = "/home/A")
    ent_list.add_user("user_with_homedir_B", 1002, 2002,
                      homeDirectory = "/home/B")
    ent_list.add_user("user_with_empty_homedir", 1003, 2003,
                      homeDirectory = "")
    create_ldap_fixture(request, ldap_conn, ent_list)
    conf = \
        format_conf_2307(ldap_conn, True) + \
        unindent("""\
            [nss]
            override_homedir    = /home/B
        """).format(**locals())
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)


def test_override_homedir(override_homedir):
    """Test the effect of the "override_homedir" option"""
    ent.assert_passwd(
        ent.contains_only(
            dict(name="user_with_homedir_A", uid=1001, dir="/home/B"),
            dict(name="user_with_homedir_B", uid=1002, dir="/home/B"),
            dict(name="user_with_empty_homedir", uid=1003, dir="/home/B")
        )
    )


@pytest.fixture
def fallback_homedir(request, ldap_conn):
    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)
    ent_list.add_user("user_with_homedir_A", 1001, 2001,
                      homeDirectory = "/home/A")
    ent_list.add_user("user_with_homedir_B", 1002, 2002,
                      homeDirectory = "/home/B")
    ent_list.add_user("user_with_empty_homedir", 1003, 2003,
                      homeDirectory = "")
    create_ldap_fixture(request, ldap_conn, ent_list)
    conf = \
        format_conf_2307(ldap_conn, True) + \
        unindent("""\
            [nss]
            fallback_homedir    = /home/B
        """).format(**locals())
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)


def test_fallback_homedir(fallback_homedir):
    """Test the effect of the "fallback_homedir" option"""
    ent.assert_passwd(
        ent.contains_only(
            dict(name="user_with_homedir_A", uid=1001, dir="/home/A"),
            dict(name="user_with_homedir_B", uid=1002, dir="/home/B"),
            dict(name="user_with_empty_homedir", uid=1003, dir="/home/B")
        )
    )


@pytest.fixture
def override_shell(request, ldap_conn):
    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)
    ent_list.add_user("user_with_shell_A", 1001, 2001,
                      loginShell = "/bin/A")
    ent_list.add_user("user_with_shell_B", 1002, 2002,
                      loginShell = "/bin/B")
    ent_list.add_user("user_with_empty_shell", 1003, 2003,
                      loginShell = "")
    create_ldap_fixture(request, ldap_conn, ent_list)
    conf = \
        format_conf_2307(ldap_conn, True) + \
        unindent("""\
            [nss]
            override_shell      = /bin/B
        """).format(**locals())
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)


def test_override_shell(override_shell):
    """Test the effect of the "override_shell" option"""
    ent.assert_passwd(
        ent.contains_only(
            dict(name="user_with_shell_A", uid=1001, shell="/bin/B"),
            dict(name="user_with_shell_B", uid=1002, shell="/bin/B"),
            dict(name="user_with_empty_shell", uid=1003, shell="/bin/B")
        )
    )


@pytest.fixture
def shell_fallback(request, ldap_conn):
    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)
    ent_list.add_user("user_with_sh_shell", 1001, 2001,
                      loginShell = "/bin/sh")
    ent_list.add_user("user_with_not_installed_shell", 1002, 2002,
                      loginShell = "/bin/not_installed")
    ent_list.add_user("user_with_empty_shell", 1003, 2003,
                      loginShell = "")
    create_ldap_fixture(request, ldap_conn, ent_list)
    conf = \
        format_conf_2307(ldap_conn, True) + \
        unindent("""\
            [nss]
            shell_fallback      = /bin/fallback
            allowed_shells      = /bin/not_installed
        """).format(**locals())
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)


def test_shell_fallback(shell_fallback):
    """Test the effect of the "shell_fallback" option"""
    ent.assert_passwd(
        ent.contains_only(
            dict(name="user_with_sh_shell", uid=1001, shell="/bin/sh"),
            dict(name="user_with_not_installed_shell", uid=1002,
                 shell="/bin/fallback"),
            dict(name="user_with_empty_shell", uid=1003, shell="")
        )
    )


@pytest.fixture
def default_shell(request, ldap_conn):
    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)
    ent_list.add_user("user_with_sh_shell", 1001, 2001,
                      loginShell = "/bin/sh")
    ent_list.add_user("user_with_not_installed_shell", 1002, 2002,
                      loginShell = "/bin/not_installed")
    ent_list.add_user("user_with_empty_shell", 1003, 2003,
                      loginShell = "")
    create_ldap_fixture(request, ldap_conn, ent_list)
    conf = \
        format_conf_2307(ldap_conn, True) + \
        unindent("""\
            [nss]
            default_shell       = /bin/default
            allowed_shells      = /bin/default, /bin/not_installed
            shell_fallback      = /bin/fallback
        """).format(**locals())
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)


def test_default_shell(default_shell):
    """Test the effect of the "default_shell" option"""
    ent.assert_passwd(
        ent.contains_only(
            dict(name="user_with_sh_shell", uid=1001, shell="/bin/sh"),
            dict(name="user_with_not_installed_shell", uid=1002,
                 shell="/bin/fallback"),
            dict(name="user_with_empty_shell", uid=1003,
                 shell="/bin/default")
        )
    )


@pytest.fixture
def vetoed_shells(request, ldap_conn):
    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)
    ent_list.add_user("user_with_sh_shell", 1001, 2001,
                      loginShell = "/bin/sh")
    ent_list.add_user("user_with_vetoed_shell", 1002, 2002,
                      loginShell = "/bin/vetoed")
    ent_list.add_user("user_with_empty_shell", 1003, 2003,
                      loginShell = "")
    create_ldap_fixture(request, ldap_conn, ent_list)
    conf = \
        format_conf_2307(ldap_conn, True) + \
        unindent("""\
            [nss]
            default_shell       = /bin/default
            vetoed_shells       = /bin/vetoed
            shell_fallback      = /bin/fallback
        """).format(**locals())
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)


def test_vetoed_shells(vetoed_shells):
    """Test the effect of the "vetoed_shells" option"""
    ent.assert_passwd(
        ent.contains_only(
            dict(name="user_with_sh_shell", uid=1001, shell="/bin/sh"),
            dict(name="user_with_vetoed_shell", uid=1002,
                 shell="/bin/fallback"),
            dict(name="user_with_empty_shell", uid=1003,
                 shell="/bin/default")
        )
    )

def test_broken_posix_in_ad(ldap_conn, neg_posix_attrs):
    """ Test that LDAP provider with AD schema doesn't go offline on
        encountering a wrong POSIX attribute
    """

    try:
        ent.get_passwd_by_name("no_such_user")
    except KeyError as err:
        pass
    else:
        raise KeyError("Unexpected user found!\n")

    time.sleep(2)

    # Add the user
    e = ldap_ent.user(ldap_conn.ds_inst.base_dn, "user", 1001, 2000)
    ldap_conn.add_s(*e)
    time.sleep(2)

    ent.assert_passwd_by_name(
        'user',
        dict(name='user', passwd='*', uid=1001, gid=2000)),
