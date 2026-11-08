# -*- coding: utf-8 -*-
from __future__ import absolute_import, print_function, division

import pytest

import petl as etl
from petl.test.helpers import ieq

# petl.io.ldap defers the ldap3 import to its iterator, so importing the
# module above already works without the optional dependency installed
from petl.io.ldap import fromldap

ldap3 = pytest.importorskip("ldap3")


# region Test Cases


def test_fromldap_single_page():
    connection = FakeConnection(
        pages=[
            [
                {'dn': 'cn=bob,ou=people,dc=example,dc=org',
                 'attributes': {'cn': ['bob'],
                                'mail': ['bob@example.org', 'bob@home.org']}},
                {'dn': 'cn=jim,ou=people,dc=example,dc=org',
                 'attributes': {'cn': ['jim'],
                                'mail': ['jim@example.org'],
                                'manager': ['cn=anne,ou=people,dc=example,dc=org']}},
            ],
        ],
        # an empty cookie ends the search after the only page
        cookies=[''],
    )
    actual = fromldap(connection,
                      base_ou='ou=people,dc=example,dc=org',
                      query='(objectClass=person)',
                      attributes=['cn', 'mail', 'phone', 'manager'],
                      defaults={'phone': 'unlisted'})
    expect = [['cn', 'mail', 'phone', 'manager'],
              ['bob', 'bob@example.org;bob@home.org', 'unlisted', None],
              ['jim', 'jim@example.org', 'unlisted',
               'cn=anne,ou=people,dc=example,dc=org']]
    ieq(expect, actual)
    ieq(expect, actual)  # verify can iterate twice
    # the search asked for the whole subtree under the base
    assert connection.searches[0]['search_base'] == \
        'ou=people,dc=example,dc=org'
    assert connection.searches[0]['search_filter'] == '(objectClass=person)'
    assert connection.searches[0]['search_scope'] == ldap3.SUBTREE
    assert connection.searches[0]['attributes'] == \
        ['cn', 'mail', 'phone', 'manager']
    # every finished iteration bound and unbound the connection
    assert connection.binds == 2
    assert connection.unbinds == 2


def test_fromldap_multi_page():
    connection = FakeConnection(
        pages=[
            [
                {'dn': 'cn=bob,ou=people,dc=example,dc=org',
                 'attributes': {'cn': ['bob']}},
            ],
            [
                # a continuation reference carries no attributes,
                # so it is not a row of the table
                {'uri': ['ldap://dc=example.org/cn=jim']},
                {'dn': 'cn=jim,ou=people,dc=example,dc=org',
                 'attributes': {'cn': ['jim']}},
            ],
        ],
        # the first page reports a cookie, the second one ends the search
        cookies=['cookie-of-page-2', ''],
    )
    actual = fromldap(connection,
                      base_ou='ou=people,dc=example,dc=org',
                      query='(objectClass=person)',
                      attributes=['cn'],
                      page_size=1)
    expect = [['cn'], ['bob'], ['jim']]
    ieq(expect, actual)
    ieq(expect, actual)  # verify can iterate twice
    # each iteration paged through both scripted pages
    assert len(connection.searches) == 4
    assert connection.searches[0]['paged_size'] == 1
    assert connection.searches[0]['paged_cookie'] is None
    assert connection.searches[1]['paged_cookie'] == 'cookie-of-page-2'
    assert connection.searches[2]['paged_cookie'] is None


def test_fromldap_scope_and_joiner():
    connection = FakeConnection(
        pages=[
            [{'dn': 'cn=anne,ou=people,dc=example,dc=org',
              'attributes': {'cn': ['anne', 'anna', 'annie']}}],
        ],
        # a missing cookie also ends the search
        cookies=[None],
    )
    actual = fromldap(connection,
                      base_ou='ou=people,dc=example,dc=org',
                      query='(cn=anne)',
                      attributes=['cn'],
                      scope=ldap3.BASE,
                      joiner=' + ')
    ieq([['cn'], ['anne + anna + annie']], actual)
    assert connection.searches[0]['search_scope'] == ldap3.BASE


def test_fromldap_header_first_and_unbind_when_stopped_early():
    connection = FakeConnection(
        pages=[
            [{'dn': 'cn=bob', 'attributes': {'cn': ['bob']}},
             {'dn': 'cn=jim', 'attributes': {'cn': ['jim']}}],
        ],
        cookies=[''],
    )
    rows = iter(fromldap(connection, 'ou=people', '(objectClass=*)', ['cn']))
    # the header is the first row yielded
    assert next(rows) == ('cn',)
    assert next(rows) == ('bob',)
    # abandoning the iteration still unbinds the connection
    rows.close()
    assert connection.unbinds == 1


def test_fromldap_requires_attributes():
    connection = FakeConnection(pages=[], cookies=[])
    with pytest.raises(ValueError):
        fromldap(connection, 'ou=people', '(objectClass=*)', None)


def test_fromldap_feeds_petl_transforms():
    connection = FakeConnection(
        pages=[
            [{'dn': 'cn=bob', 'attributes': {'cn': ['bob'],
                                             'mail': ['bob@example.org']}}],
            [{'dn': 'cn=jim', 'attributes': {'cn': ['jim'],
                                             'mail': ['jim@example.org']}}],
        ],
        cookies=['cookie-of-page-2', ''],
    )
    people = fromldap(connection, 'ou=people', '(objectClass=person)',
                      ['cn', 'mail'], page_size=1)
    ieq([['mail'], ['bob@example.org'], ['jim@example.org']],
        etl.cut(people, 'mail'))


# endregion

# region Helpers


class FakeConnection(object):
    """Stand-in for a ``ldap3.Connection`` running a scripted paged search.

    Every ``bind()`` restarts the scripted pages, so a view can be iterated
    more than once, as over a live directory. After each ``search()`` the
    scripted cookie of the page just served shows up under the paged
    results control of ``result``.
    """

    def __init__(self, pages, cookies):
        assert len(cookies) >= len(pages)
        self.pages = pages
        self.cookies = cookies
        self.searches = []
        self.binds = 0
        self.unbinds = 0
        self.response = None
        self.result = {}
        self._page_at = 0

    def bind(self):
        self.binds += 1
        self._page_at = 0
        return True

    def unbind(self):
        self.unbinds += 1
        return True

    def search(self, **kwargs):
        self.searches.append(kwargs)
        at = self._page_at
        self.response = self.pages[at] if at < len(self.pages) else []
        cookie = self.cookies[at] if at < len(self.cookies) else None
        self.result = {
            'controls': {
                '1.2.840.113556.1.4.319': {'value': {'cookie': cookie}},
            },
        }
        self._page_at += 1
        return True


# endregion

# end of tests #
