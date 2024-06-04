from __future__ import annotations

import pytest
import time
from sssd_test_framework.topology import KnownTopology, KnownTopologyGroup
# from sssd_test_framework.roles.client import Client
# from sssd_test_framework.roles.generic import GenericProvider
# from sssd_test_framework.topology import KnownTopologyGroup

@pytest.mark.ticket(bz=748833)
@pytest.mark.topology(KnownTopology.AD) 
def test_enumerate_and_authenticate_user01_over_STARTTLS(client: Client, ad: AD):
    """
    :title: Enumerate and Authenticate user01 over STARTTLS bz748833
    :steps:
        1. Create dummy user in AD
        2. Setup sssd config on client to connect to AD using LDAP
        3. Start sssd on client
        4. Check user exists and that we can login as user via ssh
    :expectedresults:
        1. User exists
        2. Authentication with password is successful
    :customerscenario: True
    """
    ad.user('lkuser01').add()

    client.sssd.config["domain/test"] = {
        'debug_level': '0xFFF0',
        'description': 'LDAP domain with AD server',
        'id_provider': 'ldap',
        'ldap_id_use_start_tls': 'true',
        'ldap_uri': "ldap://ad.test",
        'ldap_schema': 'ad',
        'ldap_default_bind_dn': "cn=Administrator,cn=Users,dc=ad,dc=test",
        'ldap_tls_cacert': '/data/certs/ca.crt',
        'ldap_default_authtok': 'vagrant',
        'ldap_search_base': 'cn=Users,dc=ad,dc=test',
        'ldap_force_upper_case_realm': 'True',
        'ldap_referrals': 'false',
        # 'krb5_keytab': '/enrollment/ad.keytab',
        # 'ldap_krb5_keytab': '/enrollment/ad.keytab',
    }
    client.sssd.config["nss"] = {
        'filter_groups': 'root',
        'filter_users': 'root',
    }

    client.sssd.start()
    time.sleep(120)
    assert client.tools.id('lkuser01') is not None
    assert client.auth.ssh.password('lkuser01', 'Secret123')