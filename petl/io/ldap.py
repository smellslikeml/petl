# -*- coding: utf-8 -*-
from __future__ import absolute_import, division, print_function

from petl.compat import string_types, text_type
from petl.util.base import Table

# the OID of the Microsoft paged results control, under which ldap3 reports
# the cookie used to ask for the next page of a search
PAGED_RESULTS_CONTROL_OID = '1.2.840.113556.1.4.319'

# region API


def fromldap(connection, base_ou, query, attributes=None, scope=None,
             page_size=500, defaults=None, joiner=';'):
    """Extract a table from the entries of an LDAP directory.

    The `connection` argument is a `ldap3.Connection` to the directory
    server. It is bound when the iteration starts and unbound when the
    iteration finishes, so iterating a view again runs the search once
    more over the same connection.

    The `base_ou` argument is the distinguished name of the entry where the
    search starts, e.g., ``'ou=people,dc=example,dc=org'``.

    The `query` argument is the search filter in RFC 2254 format, e.g.,
    ``'(objectClass=person)'``.

    The `attributes` argument is the list of attribute names to extract,
    and is required: it defines the fields of the returned table, in the
    same order, whatever attributes each entry carries.

    The `scope` argument is the search scope, one of the ``ldap3`` scope
    constants ``ldap3.BASE``, ``ldap3.LEVEL`` or ``ldap3.SUBTREE``. It
    defaults to ``ldap3.SUBTREE``.

    The `page_size` argument (int, optional) is how many entries are asked
    per page through the paged results control. The search follows the
    paging cookie until the directory reports no more pages, so directories
    larger than the server size limit can still be read.

    The `defaults` argument (dict, optional) maps an attribute name to the
    value used by the entries that do not carry that attribute. An
    attribute missing from an entry and from `defaults` turns up as
    ``None``.

    The `joiner` argument (string, optional) joins the values of a
    multi-valued attribute into a single cell value. An attribute holding a
    single value is unwrapped from its list.

    Example usage::

        >>> import petl as etl
        >>> import ldap3  # doctest: +SKIP
        >>> server = ldap3.Server('ldap.example.org')  # doctest: +SKIP
        >>> connection = ldap3.Connection(server,
        ...                               user='uid=admin,dc=example,dc=org',
        ...                               password='secret')  # doctest: +SKIP
        >>> people = etl.fromldap(connection,
        ...                       base_ou='ou=people,dc=example,dc=org',
        ...                       query='(objectClass=person)',
        ...                       attributes=['cn', 'mail',
        ...                                   'manager'])  # doctest: +SKIP
        >>> people.look()  # doctest: +SKIP

    Inspired by PGower/petl_ldap3 (BSD-3-Clause); re-implemented for petl.

    .. versionadded:: 1.7.32

    """

    if not attributes:
        raise ValueError('an explicit list of attribute names is required, '
                         'so the header of the table is deterministic')
    return LdapView(connection=connection,
                    base_ou=base_ou,
                    query=query,
                    attributes=attributes,
                    scope=scope,
                    page_size=page_size,
                    defaults=defaults,
                    joiner=joiner)


# endregion API

# region Implementation


class LdapView(Table):
    '''Read rows from the paged search of a live LDAP connection'''

    def __init__(self, connection, base_ou, query, attributes, scope=None,
                 page_size=500, defaults=None, joiner=';'):
        self.connection = connection
        self.base_ou = base_ou
        self.query = query
        # copy the attributes, so editing the list of the caller later does
        # not change the header of this view
        self.attributes = list(attributes)
        self.scope = scope
        self.page_size = page_size
        self.defaults = {} if defaults is None else defaults
        self.joiner = joiner

    def __iter__(self):
        # delay the import of ldap3 for not breaking when unused
        import ldap3

        search_scope = ldap3.SUBTREE if self.scope is None else self.scope
        yield tuple(self.attributes)
        cookie = None
        try:
            self.connection.bind()
            while True:
                self.connection.search(search_base=self.base_ou,
                                       search_filter=self.query,
                                       search_scope=search_scope,
                                       attributes=self.attributes,
                                       paged_size=self.page_size,
                                       paged_cookie=cookie)
                for entry in self.connection.response or []:
                    entry_attributes = _entry_attributes(entry)
                    if entry_attributes is None:
                        continue
                    yield tuple(_attribute_value(entry_attributes, name,
                                                 self.defaults, self.joiner)
                                for name in self.attributes)
                cookie = _paged_cookie(self.connection.result)
                if not cookie:
                    break
        finally:
            self.connection.unbind()


# endregion Implementation

# region Helpers


def _entry_attributes(entry):
    '''the attributes of a search entry, or None when the entry carries
    none, as a search result continuation reference'''
    if isinstance(entry, dict) and 'attributes' in entry:
        return entry['attributes']
    return None


def _attribute_value(entry_attributes, name, defaults, joiner):
    '''map one attribute of an entry to a cell value: a multi-valued
    attribute is joined with the joiner, a single value is unwrapped from
    its list, and an attribute missing from the entry falls back to the
    matching default, else None'''
    if name not in entry_attributes:
        return defaults.get(name)
    value = entry_attributes[name]
    if isinstance(value, (list, tuple)):
        if len(value) == 1:
            return value[0]
        return joiner.join(_as_text(item) for item in value)
    return value


def _as_text(value):
    return value if isinstance(value, string_types) else text_type(value)


def _paged_cookie(result):
    '''dig the cookie of the next page out of the controls of a result'''
    if not isinstance(result, dict):
        return None
    controls = result.get('controls') or {}
    control = controls.get(PAGED_RESULTS_CONTROL_OID) or {}
    value = control.get('value') or {}
    return value.get('cookie')


# endregion
