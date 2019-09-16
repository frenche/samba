#!/bin/sh
# Copyright (C) 2015 Stefan Metzmacher <metze@samba.org>

if [ $# -lt 11 ]; then
cat <<EOF
Usage: test_s4u_mit.sh SERVER USERNAME PASSWORD REALM DOMAIN TRUST_USERNAME TRUST_PASSWORD TRUST_REALM TRUST_DOMAIN PREFIX
EOF
exit 1;
fi

SERVER=$1
USERNAME=$2
PASSWORD=$3
REALM=$4
DOMAIN=$5
shift 5
TRUST_SERVER=$1
TRUST_USERNAME=$2
TRUST_PASSWORD=$3
TRUST_REALM=$4
TRUST_DOMAIN=$5
shift 5
PREFIX=$1
shift 1
failed=0

smbclient="$BINDIR/smbclient"
samba_tool="$BINDIR/samba-tool"

. `dirname $0`/subunit.sh
. `dirname $0`/common_test_fns.inc

unc="//$SERVER.$REALM/tmp"
spn="CIFS/$SERVER"
impersonator=test_impersonator

KRB5CCNAME_PATH="$PREFIX/tmpccache"
KRB5CCNAME="FILE:$KRB5CCNAME_PATH"
export KRB5CCNAME
rm -rf $KRB5CCNAME_PATH

echo $PASSWORD > $PREFIX/tmppassfile

testit "Add principal" $VALGRIND $PYTHON $samba_tool user add $impersonator $PASSWORD || failed=`expr $failed + 1`
testit "Become a service" $VALGRIND $PYTHON $samba_tool spn add HOST/me $impersonator || failed=`expr $failed + 1`

testit "kinit with password" kinit $impersonator < $PREFIX/tmppassfile || failed=`expr $failed + 1`

testit "Local realm S4U2Self" kvno -I $USERNAME $impersonator
testit "Cross realm S4U2Self" kvno -I ${TRUST_USERNAME}@$TRUST_REALM $impersonator

testit "TrustedToAuthForDelegation" $VALGRIND $PYTHON $samba_tool delegation for-any-protocol $impersonator on || failed=`expr $failed + 1`
testit "msDS-AllowedToDelegateTo"  $VALGRIND $PYTHON $samba_tool delegation add-service $impersonator $spn || failed=`expr $failed + 1`

testit "kinit forwardable" kinit -f $impersonator < $PREFIX/tmppassfile || failed=`expr $failed + 1`

testit "Local realm S4U2Self followed by S4U2Proxy" kvno -I $USERNAME -P $spn
testit "Cross realm S4U2Self followed by S4U2Proxy" kvno -I ${TRUST_USERNAME}@$TRUST_REALM -P $spn


rm -f $PREFIX/tmpccache $PREFIX/tmppassfile
exit $failed
