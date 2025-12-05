##! Extensions to the MatchyIntel::Where enum for various observation points.

@load ../main

module MatchyIntel;

export {
	redef enum Where += {
		## Connection originator IP
		Conn::IN_ORIG,
		## Connection responder IP
		Conn::IN_RESP,
		## File hash
		Files::IN_HASH,
		## File name
		Files::IN_NAME,
		## DNS request query
		DNS::IN_REQUEST,
		## DNS response answer
		DNS::IN_RESPONSE,
		## HTTP Host header
		HTTP::IN_HOST_HEADER,
		## HTTP Referrer header
		HTTP::IN_REFERRER_HEADER,
		## HTTP User-Agent header
		HTTP::IN_USER_AGENT_HEADER,
		## HTTP X-Forwarded-For header
		HTTP::IN_X_FORWARDED_FOR_HEADER,
		## HTTP URL
		HTTP::IN_URL,
		## SMTP MAIL FROM
		SMTP::IN_MAIL_FROM,
		## SMTP RCPT TO
		SMTP::IN_RCPT_TO,
		## SMTP From header
		SMTP::IN_FROM,
		## SMTP To header
		SMTP::IN_TO,
		## SMTP CC header
		SMTP::IN_CC,
		## SMTP Received header
		SMTP::IN_RECEIVED_HEADER,
		## SMTP Reply-To header
		SMTP::IN_REPLY_TO,
		## SMTP X-Originating-IP header
		SMTP::IN_X_ORIGINATING_IP_HEADER,
		## SMTP message body
		SMTP::IN_MESSAGE,
		## SSH server host key
		SSH::IN_SERVER_HOST_KEY,
		## SSL/TLS Server Name Indication
		SSL::IN_SERVER_NAME,
		## SMTP generic header
		SMTP::IN_HEADER,
		## X.509 certificate field
		X509::IN_CERT,
		## SMB file name
		SMB::IN_FILE_NAME,
	};
}
