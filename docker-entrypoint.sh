#!/bin/sh
PARAM_OC_USERNAME=""
if [ "${ocusername}" ]
then
    PARAM_OC_USERNAME=${ocusername}
else
    PARAM_OC_USERNAME=yhiblog
fi
PARAM_OC_PASSWORD=""
if [ "${ocpassword}" ]
then
    PARAM_OC_PASSWORD="${ocpassword}"
else
    PARAM_OC_PASSWORD=yhiblog
fi
PARAM_DOMAIN=""
if [ "${domain}" ]
then
    PARAM_DOMAIN="${domain}"
else
    PARAM_DOMAIN="$(curl checkip.amazonaws.com 2>/dev/null)"
fi
if [ ! -f /etc/ocserv/certs/server-key.pem ] || [ ! -f /etc/ocserv/certs/server-cert.pem ]; then
	# Check environment variables
	if [ -z "$CA_CN" ]; then
		CA_CN="YHIBLOG"
	fi

	if [ -z "$CA_ORG" ]; then
		CA_ORG="YHIBLOG"
	fi

	if [ -z "$CA_DAYS" ]; then
		CA_DAYS=9999
	fi

	if [ -z "$SRV_CN" ]; then
		SRV_CN="shui.azurewebsites.net"
	fi

	if [ -z "$SRV_ORG" ]; then
		SRV_ORG="YHIBLOG"
	fi

	if [ -z "$SRV_DAYS" ]; then
		SRV_DAYS=9999
	fi

	# No certification found, generate one
	mkdir /etc/ocserv/certs
	cd /etc/ocserv/certs
	certtool --generate-privkey --outfile ca-key.pem
	cat > ca.tmpl <<-EOCA
	cn = "$CA_CN"
	organization = "$CA_ORG"
	serial = 1
	expiration_days = $CA_DAYS
	ca
	signing_key
	cert_signing_key
	crl_signing_key
	EOCA
	certtool --generate-self-signed --load-privkey ca-key.pem --template ca.tmpl --outfile ca.pem
	certtool --generate-privkey --outfile server-key.pem 
	cat > server.tmpl <<-EOSRV
	cn = "$SRV_CN"
	organization = "$SRV_ORG"
	expiration_days = $SRV_DAYS
	signing_key
	encryption_key
	tls_www_server
	EOSRV
	certtool --generate-certificate --load-privkey server-key.pem --load-ca-certificate ca.pem --load-ca-privkey ca-key.pem --template server.tmpl --outfile server-cert.pem

	# Create a test user
	if [ -z "$NO_TEST_USER" ] && [ ! -f /etc/ocserv/ocpasswd ]; then
		echo "Create test user '${PARAM_OC_USERNAME}' with password '${PARAM_OC_PASSWORD}'"
(
echo "${PARAM_OC_PASSWORD}"
sleep 1
echo "${PARAM_OC_PASSWORD}")|ocpasswd -c /etc/ocserv/ocpasswd -g "All,Route,NoRoute,Scholar" ${PARAM_OC_USERNAME}
	fi
fi

cat >/etc/ocserv/profile.xml<<EOF
<?xml version="1.0" encoding="UTF-8"?>
<AnyConnectProfile xmlns="http://schemas.xmlsoap.org/encoding/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://schemas.xmlsoap.org/encoding/ AnyConnectProfile.xsd">
 
 <ClientInitialization>
 <UseStartBeforeLogon UserControllable="false">false</UseStartBeforeLogon>
 <StrictCertificateTrust>false</StrictCertificateTrust>
 <RestrictPreferenceCaching>false</RestrictPreferenceCaching>
 <RestrictTunnelProtocols>false</RestrictTunnelProtocols>
 <BypassDownloader>true</BypassDownloader>
 <WindowsVPNEstablishment>AllowRemoteUsers</WindowsVPNEstablishment>
 <CertEnrollmentPin>pinAllowed</CertEnrollmentPin>
 <CertificateMatch>
 <KeyUsage>
 <MatchKey>Digital_Signature</MatchKey>
 </KeyUsage>
 <ExtendedKeyUsage>
 <ExtendedMatchKey>ClientAuth</ExtendedMatchKey>
 </ExtendedKeyUsage>
 </CertificateMatch>
 
 <BackupServerList>
             <HostAddress>${PARAM_DOMAIN}</HostAddress>
 </BackupServerList>
 </ClientInitialization>
</AnyConnectProfile>
EOF

    PARAM_IP="$(curl checkip.amazonaws.com 2>/dev/null)"
echo "no-route = ${PARAM_IP}/255.255.255.255" >> /etc/ocserv/config-per-group/All
echo "no-route = ${PARAM_IP}/255.255.255.255" >> /etc/ocserv/config-per-group/NoRoute
echo "no-route = ${PARAM_IP}/255.255.255.255" >> /etc/ocserv/config-per-group/Scholar

# Open ipv4 ip forward
sysctl -w net.ipv4.ip_forward=1

# Enable NAT forwarding
iptables -t nat -A POSTROUTING -j MASQUERADE
iptables -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

# Enable TUN device
mkdir -p /dev/net
mknod /dev/net/tun c 10 200
chmod 600 /dev/net/tun

# Run OpennConnect Server
exec "$@"
bash /etc/init.d/ocserv restart
