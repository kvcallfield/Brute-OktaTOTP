# Brute-OktaTOTP

This is a proof of concept that will guess at 6-digit TOTP codes until a valid one is found.  The tool will then send the valid password for the target Okta account, completing the two factor auth process, and sending the attacker a copy of the 'idx' session cookie.  

The attacker will need to watch and account for IP address blocking by Okta, and may need to rotate IP addresses in a fashion similar to CredMaster, for example, using AWS API gateways.  

Valid Okta passwords should be obtainable via a tool like Okta-Password-Sprayer.

-----------------------------------------------------------------------------------------------

codeguess.py - a POC that guesses 3 incorrect TOTP codes, then the correct one.  It then sends the predetermined valid user password to complete 2fa, and gives you an 'idx' cookie to paste into your Okta session for initial access.  Update: includes a Slack webhook with the cookie.

codeguess_loop.py - the actual tool that guesses until a valid code is found.  Handles timeouts.  Includes the bells and whistles described above for codeguess.py.

codeguess_loop_slower.py - attempts to avoid lockouts and IP blocks by throttling the attempts.  Includes the bells and whistles described above for codeguess.py.
