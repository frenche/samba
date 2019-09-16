/*
   Unix SMB/CIFS implementation.

   Samba KDB plugin for MIT Kerberos

   Copyright (c) 2010      Simo Sorce <idra@samba.org>.
   Copyright (c) 2014      Andreas Schneider <asn@samba.org>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"

#include "system/kerberos.h"

#include <profile.h>
#include <kdb.h>

#include "kdc/mit_samba.h"
#include "kdb_samba.h"

/* FIXME: This is a krb5 function which is exported, but in no header */
extern krb5_error_code decode_krb5_padata_sequence(const krb5_data *output,
						   krb5_pa_data ***rep);

static krb5_error_code ks_get_netbios_name(krb5_address **addrs, char **name)
{
	char *nb_name = NULL;
	int len, i;

	for (i = 0; addrs[i]; i++) {
		if (addrs[i]->addrtype != ADDRTYPE_NETBIOS) {
			continue;
		}
		len = MIN(addrs[i]->length, 15);
		nb_name = strndup((const char *)addrs[i]->contents, len);
		if (!nb_name) {
			return ENOMEM;
		}
		break;
	}

	if (nb_name) {
		/* Strip space padding */
		i = strlen(nb_name) - 1;
		for (i = strlen(nb_name) - 1;
		     i > 0 && nb_name[i] == ' ';
		     i--) {
			nb_name[i] = '\0';
		}
	}

	*name = nb_name;

	return 0;
}

krb5_error_code kdb_samba_db_check_policy_as(krb5_context context,
					     krb5_kdc_req *kdcreq,
					     krb5_db_entry *client,
					     krb5_db_entry *server,
					     krb5_timestamp kdc_time,
					     const char **status,
					     krb5_pa_data ***e_data_out)
{
	struct mit_samba_context *mit_ctx;
	krb5_error_code code;
	char *client_name = NULL;
	char *server_name = NULL;
	char *netbios_name = NULL;
	char *realm = NULL;
	bool password_change = false;
	krb5_const_principal client_princ;
	DATA_BLOB int_data = { NULL, 0 };
	krb5_data d;
	krb5_pa_data **e_data;

	mit_ctx = ks_get_context(context);
	if (mit_ctx == NULL) {
		return KRB5_KDB_DBNOTINITED;
	}

	/* Prefer canonicalised name from client entry */
	client_princ = client ? client->princ : kdcreq->client;

	if (client_princ == NULL || ks_is_kadmin(context, client_princ)) {
		return KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN;
	}

	if (krb5_princ_size(context, kdcreq->server) == 2 &&
	    ks_is_kadmin_changepw(context, kdcreq->server)) {
		code = krb5_get_default_realm(context, &realm);
		if (code) {
			goto done;
		}

		if (ks_data_eq_string(kdcreq->server->realm, realm)) {
			password_change = true;
		}
	}

	code = krb5_unparse_name(context, kdcreq->server, &server_name);
	if (code) {
		goto done;
	}

	code = krb5_unparse_name(context, client_princ, &client_name);
	if (code) {
		goto done;
	}

	if (kdcreq->addresses) {
		code = ks_get_netbios_name(kdcreq->addresses, &netbios_name);
		if (code) {
			goto done;
		}
	}

	code = mit_samba_check_client_access(mit_ctx,
					     client,
					     client_name,
					     server,
					     server_name,
					     netbios_name,
					     password_change,
					     &int_data);

	if (int_data.length && int_data.data) {

		/* make sure the mapped return code is returned - gd */
		int code_tmp;

		d = ks_make_data(int_data.data, int_data.length);

		code_tmp = decode_krb5_padata_sequence(&d, &e_data);
		if (code_tmp == 0) {
			*e_data_out = e_data;
		}
	}
done:
	free(realm);
	free(server_name);
	free(client_name);
	free(netbios_name);

	return code;
}

static krb5_error_code ks_get_pac(krb5_context context,
				  krb5_db_entry *client,
				  krb5_keyblock *client_key,
				  krb5_pac *pac)
{
	struct mit_samba_context *mit_ctx;
	krb5_error_code code;

	mit_ctx = ks_get_context(context);
	if (mit_ctx == NULL) {
		return KRB5_KDB_DBNOTINITED;
	}

	code = mit_samba_get_pac(mit_ctx,
				 context,
				 client,
				 client_key,
				 pac);
	if (code != 0) {
		return code;
	}

	return code;
}

static krb5_error_code ks_verify_pac(krb5_context context,
				     unsigned int flags,
				     krb5_const_principal client_princ,
				     krb5_const_principal server_princ,
				     krb5_db_entry *client,
				     krb5_db_entry *header_server,
				     krb5_keyblock *header_server_key,
				     krb5_keyblock *local_krbtgt_key,
				     krb5_timestamp authtime,
				     krb5_authdata **tgt_auth_data,
				     krb5_pac *pac)
{
	krb5_error_code code;
	struct mit_samba_context *mit_ctx;
	krb5_authdata **authdata = NULL;
	krb5_boolean check_realm;
	krb5_pac ipac;

	*pac = NULL;

	mit_ctx = ks_get_context(context);
	if (mit_ctx == NULL) {
		return KRB5_KDB_DBNOTINITED;
	}

	/* find the existing PAC, if present */
	code = krb5_find_authdata(context,
				  tgt_auth_data,
				  NULL,
				  KRB5_AUTHDATA_WIN2K_PAC,
				  &authdata);
	if (code != 0) {
		return code;
	}

	/* no pac data */
	if (authdata == NULL) {
		return 0;
	}

	SMB_ASSERT(authdata[0] != NULL);

	if (authdata[1] != NULL) {
		code = KRB5KDC_ERR_BADOPTION; /* XXX */
		goto done;
	}

	code = krb5_pac_parse(context,
			      authdata[0]->contents,
			      authdata[0]->length,
			      &ipac);
	if (code != 0) {
		goto done;
	}

	check_realm = ((flags & KRB5_KDB_FLAGS_S4U) &&
		       (flags & KRB5_KDB_FLAG_CROSS_REALM));

	code = krb5_pac_verify_ext(context, ipac, authtime, client_princ,
				   header_server_key, NULL, check_realm);
	if (code != 0) {
		goto done;
	}

	code = mit_samba_reget_pac(mit_ctx,
				   context,
				   flags,
				   server_princ,
				   client,
				   header_server,
				   local_krbtgt_key,
				   &ipac);
	if (code != 0) {
		goto done;
	}

	*pac = ipac;
	ipac = NULL;

done:
	krb5_free_authdata(context, authdata);
	krb5_pac_free(context, ipac);

	return code;
}

#if KRB5_KDB_API_VERSION >= 10
krb5_error_code kdb_samba_db_sign_auth_data(krb5_context context,
					    unsigned int flags,
					    krb5_const_principal client_princ,
					    krb5_const_principal server_princ,
					    krb5_db_entry *client,
					    krb5_db_entry *server,
					    krb5_db_entry *header_server,
					    krb5_db_entry *local_krbtgt,
					    krb5_keyblock *client_key,
					    krb5_keyblock *server_key,
					    krb5_keyblock *header_server_key,
					    krb5_keyblock *local_krbtgt_key,
					    krb5_keyblock *session_key,
					    krb5_timestamp authtime,
					    krb5_authdata **tgt_auth_data,
					    void *authdata_info,
					    krb5_data ***auth_indicators,
					    krb5_authdata ***signed_auth_data)
{
#else
krb5_error_code kdb_samba_db_sign_auth_data(krb5_context context,
					    unsigned int flags,
					    krb5_const_principal client_princ,
					    krb5_db_entry *client,
					    krb5_db_entry *server,
					    krb5_db_entry *krbtgt,
					    krb5_keyblock *client_key,
					    krb5_keyblock *server_key,
					    krb5_keyblock *krbtgt_key,
					    krb5_keyblock *session_key,
					    krb5_timestamp authtime,
					    krb5_authdata **tgt_auth_data,
					    krb5_authdata ***signed_auth_data)
{
	krb5_const_principal server_princ = server->princ;
	krb5_db_entry *header_server = krbtgt;
	krb5_db_entry *local_krbtgt = krbtgt;
	krb5_keyblock *header_server_key = krbtgt_key;
	krb5_keyblock *local_krbtgt_key = krbtgt_key;
#endif
	krb5_authdata **authdata = NULL;
	krb5_error_code code;
	krb5_pac pac = NULL;
	krb5_data pac_data;
	krb5_boolean sign_realm;

	if (client != NULL &&
	    ((flags & KRB5_KDB_FLAG_CLIENT_REFERRALS_ONLY) ||
	     (flags & KRB5_KDB_FLAG_PROTOCOL_TRANSITION))) {
		code = ks_get_pac(context, client, client_key, &pac);
		if (code != 0) {
			goto done;
		}
	} else {
		code = ks_verify_pac(context,
				     flags,
				     client_princ,
				     server_princ,
				     client,
				     local_krbtgt,
				     header_server_key,
				     local_krbtgt_key,
				     authtime,
				     tgt_auth_data,
				     &pac);
		if (code != 0) {
			goto done;
		}
	}

	/* TODO: only error when PAC is required, like in S4U ? */
	if (pac == NULL) {
		code = KRB5_KDB_DBTYPE_NOSUP;
		goto done;
	}

	sign_realm = ((flags & KRB5_KDB_FLAGS_S4U) &&
		      (flags & KRB5_KDB_FLAG_ISSUING_REFERRAL));

	code = krb5_pac_sign_ext(context, pac, authtime, client_princ,
				 server_key, local_krbtgt_key, sign_realm,
				 &pac_data);
	if (code != 0) {
		DBG_ERR("krb5_pac_sign_ext failed: %d\n", code);
		goto done;
	}

	authdata = calloc(2, sizeof(krb5_authdata *));
	if (authdata == NULL) {
		goto done;
	}

	authdata[0] = malloc(sizeof(krb5_authdata));
	if (authdata[0] == NULL) {
		goto done;
	}

	/* put in signed data */
	authdata[0]->magic = KV5M_AUTHDATA;
	authdata[0]->ad_type = KRB5_AUTHDATA_WIN2K_PAC;
	authdata[0]->contents = (krb5_octet *)pac_data.data;
	authdata[0]->length = pac_data.length;

	code = krb5_encode_authdata_container(context,
					      KRB5_AUTHDATA_IF_RELEVANT,
					      authdata,
					      signed_auth_data);

done:
	krb5_pac_free(context, pac);
	krb5_free_authdata(context, authdata);

	return code;
}

krb5_error_code kdb_samba_db_check_allowed_to_delegate(krb5_context context,
						       krb5_const_principal client,
						       const krb5_db_entry *server,
						       krb5_const_principal proxy)
{
	struct mit_samba_context *mit_ctx;

	/*
	 * Names are quite odd and confusing in the current implementation.
	 * The following mappings should help understanding what is what.
	 * client ->  client to impersonate
	 * server; -> delegating service
	 * proxy; -> target principal
	 */

	mit_ctx = ks_get_context(context);
	if (mit_ctx == NULL) {
		return KRB5_KDB_DBNOTINITED;
	}

	return mit_samba_check_s4u2proxy(mit_ctx, server, proxy);
}


static void samba_bad_password_count(krb5_db_entry *client,
				     krb5_error_code error_code)
{
	switch (error_code) {
	case 0:
		mit_samba_zero_bad_password_count(client);
		break;
	case KRB5KDC_ERR_PREAUTH_FAILED:
	case KRB5KRB_AP_ERR_BAD_INTEGRITY:
		mit_samba_update_bad_password_count(client);
		break;
	}
}

#if KRB5_KDB_API_VERSION >= 9
void kdb_samba_db_audit_as_req(krb5_context context,
			       krb5_kdc_req *request,
			       const krb5_address *local_addr,
			       const krb5_address *remote_addr,
			       krb5_db_entry *client,
			       krb5_db_entry *server,
			       krb5_timestamp authtime,
			       krb5_error_code error_code)
{
	/*
	 * FIXME: This segfaulted with a FAST test
	 * FIND_FAST: <unknown client> for <unknown server>, Unknown FAST armor type 0
	 */
	if (client == NULL) {
		return;
	}

	samba_bad_password_count(client, error_code);

	/* TODO: perform proper audit logging for addresses */
}
#else
void kdb_samba_db_audit_as_req(krb5_context context,
			       krb5_kdc_req *request,
			       krb5_db_entry *client,
			       krb5_db_entry *server,
			       krb5_timestamp authtime,
			       krb5_error_code error_code)
{
	/*
	 * FIXME: This segfaulted with a FAST test
	 * FIND_FAST: <unknown client> for <unknown server>, Unknown FAST armor type 0
	 */
	if (client == NULL) {
		return;
	}

	samba_bad_password_count(client, error_code);
}
#endif
