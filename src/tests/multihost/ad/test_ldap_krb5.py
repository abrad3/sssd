import pytest
from sssd_test_framework.topology import KnownTopology
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.generic import GenericProvider
from sssd_test_framework.topology import KnownTopologyGroup
from sssd_passwd import (call_sssd_getpwnam)
from sssd_nss import NssReturnCode

@pytest.mark.ticket(bz=748833)
@pytest.mark.topology(KnownTopology.AD)
def test_enumerate_and_authenticate_user01_over_STARTTLS(client: Client, ad: AD):
    """
    :title: Enumerate and Authenticate user01 over STARTTLS bz748833
    :setup:
        1. Configure SSSD connectivity to AD. Create user??
        2. Wait 20 seconds after config and sssd restart (is this still necessary??)
    :steps:
        1. $(getent -s sss passwd lkuser01-${JOBID}) runs with output 0
        2. Password auth as user with $(ssh_user_password_login lkuser01-${JOBID} Secret123)
    :expectedresults:
        1. User exists
        2. Authentication with password is successful
    :customerscenario: True
    """
    ad.user('lkuser01').add()

    client.sssd.config["domain/AD"] = {
        'ldap_uri': "ldap://"+ad.host.hostname,
        'ldap_schema': 'ad',
        'debug_level': '0xFFF0',
        'description': 'LDAP domain with AD server',
        'id_provider': 'ldap',
        'ldap_id_use_start_tls': 'true',
        'ldap_default_bind_dn': "cn=Administrator,cn=Users,"+ad.domain,
        'ldap_tls_cacert': '/etc/openldap/certs/ad_cert.pem',
        'ldap_default_authtok': 'Secret123',
        'ldap_search_base': ad.domain,
        'ldap_force_upper_case_realm': 'True',
        'ldap_referrals': 'false',
    }
    client.sssd.start()
    assert client.tools.id('lkuser01') is not None
    assert client.auth.ssh.password('lkuser01', 'Secret123')