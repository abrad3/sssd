import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.generic import GenericProvider
from sssd_test_framework.topology import KnownTopologyGroup
from sssd_passwd import (call_sssd_getpwnam)
from sssd_nss import NssReturnCode

@pytest.mark.ticket(bz=748833)
@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.topology(KnownTopology.AD)
def test_enumerate_and_authenticate_user01_over_STARTTLS(multihost, create_aduser_group):
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
    (aduser, _) = create_aduser_group
    client = sssdTools(multihost.client[0], multihost.ad[0])
    dom_section = "XXX" # f'domain/{client.get_domain_section_name()}'
    sssd_params = {
        'ldap_uri': "ldap://"+multihost.ad[0].hostname,
        'ldap_schema': 'ad',
        'debug_level': '0xFFF0',
        'description': 'LDAP domain with AD server',
        'id_provider': 'ldap',
        'ldap_id_use_start_tls': 'true',
        'ldap_default_bind_dn': "cn=Administrator,cn=Users,"+multihost.ad[0].domainname,
        'ldap_tls_cacert': '/etc/openldap/certs/ad_cert.pem',
        'ldap_default_authtok': $AD_SERVER1_BINDPASS,
        'ldap_search_base': multihost.ad[0].domainname,
        'ldap_force_upper_case_realm': 'True',
        'ldap_referrals': 'false',
    }
    client.sssd_conf(dom_section, sssd_params)
    # Clear cache and restart SSSD
    client.clear_sssd_cache()
    res,_ = call_sssd_getpwnam(aduser)
    assert res == NssReturnCode.SUCCESS
    password_login_res = client.auth_from_client(aduser, 'Secret123')
    assert password_login_res == 3 # this was used in sssd/src/tests/multihost/ad/test_adparameters_ported.py, need to check it's right

