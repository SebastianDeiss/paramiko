# Copyright (C) 2003-2007  Robey Pointer <robeypointer@gmail.com>
#
# This file is part of paramiko.
#
# Paramiko is free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.
#
# Paramiko is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Paramiko; if not, write to the Free Software Foundation, Inc.,
# 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.

'''
Created on 07.11.2013

@author: Sebastian Deiss <s.deiss@science-computing.de>
         science + computing ag
'''

import struct
from pyasn1.type.univ import ObjectIdentifier
from pyasn1.codec.der import encoder, decoder
import gssapi
from paramiko.common import *
from paramiko.ssh_exception import SSHException
# for server mode
from subprocess import call
import string
import random


class SSH_GSSAuth(object):
    '''
    Implementation of the GSSAPI Authentication for SSH2
    '''
    def __init__(self, auth_method,  gss_deleg_creds=True):
        self._auth_method = auth_method
        self._hostname = None
        self._username = None
        self._session_id = None
        self._service = "ssh-connection"
        self._gss_ctxt = None
        self._gss_ctxt_status = False
        '''
        We delegate credentials by defualt.
        '''
        if gss_deleg_creds:
            self._gss_flags = gssapi.C_PROT_READY_FLAG + gssapi.C_INTEG_FLAG + gssapi.C_MUTUAL_FLAG + gssapi.C_DELEG_FLAG
        else:
            self._gss_flags = gssapi.C_PROT_READY_FLAG + gssapi.C_INTEG_FLAG + gssapi.C_MUTUAL_FLAG
        '''
        OpenSSH supports Kerberos V5 mechanism only for GSSAPI authentication,
        so we also support krb5 mechanism only
        '''
        self._krb5_mech = "1.2.840.113554.1.2.2"
        # for server mode
        self._gss_srv_ctxt = None
        self._gss_srv_ctxt_status = False

    '''
    This is just a setter to use a non default service.
    I added this method, because RFC 4462 doesn't specify "ssh-connection" as
    the only service value.
    '''
    def set_service(self, service):
        if service.find("ssh-"):
            self._service = service

    '''
    Returns the supported OIDs as DER encoded bytes and use the OID length as
    prefix This will return only a single OID, because we only support the
    Kerberos V5 mechanism
    '''
    @property
    def ssh_gss_oids(self):
        # we support just one OID. It's the Kerveros V5 GSSAPI OID
        OIDs = self._make_uint32(1)
        krb5_OID = encoder.encode(ObjectIdentifier(self._krb5_mech))
        OID_len = self._make_uint32(len(krb5_OID))
        '''
        returns a byte sequence containing the number of OIDs we support, the
        length of the OID and the actual OID encoded with DER
        '''
        return OIDs + OID_len + krb5_OID

    '''
    Initialize a GSSAPI context
    '''
    def ssh_init_sec_context(self, username, target, desired_mech,
                             recv_token=None):
        self._username = username
        self._hostname = target
        targ_name = gssapi.Name("host@" + self._hostname,
                                gssapi.C_NT_HOSTBASED_SERVICE)
        ctx = gssapi.Context()
        ctx.flags = self._gss_flags
        mech, __ = decoder.decode(desired_mech)
        if mech.__str__() != self._krb5_mech:
            raise SSHException("Unsupported mechanism OID.")
        else:
            krb5_mech = gssapi.OID.mech_from_string(mech.__str__())
        token = None
        if recv_token is None:
            self._gss_ctxt = gssapi.InitContext(target_name=targ_name,
                                                mech_type=krb5_mech, req_flags=ctx.flags)
            token = self._gss_ctxt.step(token)
        else:
            token = self._gss_ctxt.step(recv_token)
        self._gss_ctxt_status = self._gss_ctxt.established
        return token

    '''
    Create the MIC token for a message
    '''
    def ssh_get_mic(self, session_id):
        self._session_id = session_id
        mic_field = self._ssh_build_mic(self._session_id, self._username,
                                        self._service, self._auth_method)
        mic_token = self._gss_ctxt.get_mic(mic_field)
        return mic_token

    '''
    Accept a GSSAPI context (server mode)
    '''
    def ssh_accept_sec_context(self, username, recv_token):
        self._username = username
        self._gss_srv_ctxt = gssapi.AcceptContext()
        token = self._gss_srv_ctxt.step(recv_token)
        return token

    '''
    Verify the MIC token for a message (server mode)
    '''
    def ssh_check_mic(self, mic_token, session_id, username):
        self._session_id = session_id
        self._username = username
        mic_field = self._ssh_build_mic(self._session_id, self._username,
                                        self._service, self._auth_method)
        mic_status = self._gss_ctxt.verify_mic(mic_field, mic_token)
        return mic_status

    '''
    Save the Client token in a file and set this file to the KRB5CCNAME environment variable
    This is used by the SSH server if credentials are delegated
    (server mode)
    '''
    def save_client_creds(self, client_token):
            cc_file = "/tmp/krb5cc_1773_" + self._random_string()
            file_handler = open(cc_file)
            file_handler.write(client_token)
            file_handler.close()
            call("export KRB5_CCNAME=" + cc_file)
            return cc_file

    # Internals
    #----------------------------------------------------------------------
    '''
    Create a 32 bit unsigned integer
    '''
    def _make_uint32(self, integer):
        b = ["", "", "", ""]
        b[0], b[1], b[2], b[3] = struct.pack("I", integer)
        b.reverse()
        return "" . join([str(string) for string in b])

    '''
    Create the SSH2 MIC filed. The contents of the MIC field are defined in
    RFC 4462 as follows:
    string    session_identifier
    byte      SSH_MSG_USERAUTH_REQUEST
    string    user-name
    string    service
    string    authentication-method (gssapi-with-mic or gss-keyex)
    '''
    def _ssh_build_mic(self, session_id, username, service, auth_method):
        mic = self._make_uint32(len(session_id))
        mic += session_id
        mic += chr(MSG_USERAUTH_REQUEST)
        mic += self._make_uint32(len(username))
        mic += str.encode(username)
        mic += self._make_uint32(len(service))
        mic += str.encode(service)
        mic += self._make_uint32(len(auth_method))
        mic += str.encode(auth_method)
        return mic

    def _random_string(self, chars=string.ascii_uppercase +
                       string.ascii_lowercase, length=10):
        return ''.join(random.choice(chars) for x in range(length))
