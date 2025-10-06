# CardSecurity EF

The file `EF.CardSecurity`, contained in the Master File, is **REQUIRED** if:

- PACE with Chip Authentication Mapping (CAM) is supported by the eMRTD chip, or  
- Terminal Authentication in the Master File is supported by the eMRTD chip, or  
- Chip Authentication in the Master File is supported by the eMRTD  

It **SHALL** contain the following `SecurityInfos`:

- `ChipAuthenticationInfo` as required by Chip Authentication  
- `ChipAuthenticationPublicKeyInfo` as required for PACE-CAM / Chip Authentication  
- `TerminalAuthenticationInfo` as required by Terminal Authentication  
- `EFDIRInfo` if more than the eMRTD Application is present on the chip  
- The `SecurityInfos` contained in `EF.CardAccess`


## EF.DG14

The file `EF.DG14`, contained in the eMRTD Application, is **REQUIRED** if:

- PACE with Generic/Integrated Mapping is supported by the eMRTD chip, or  
- Terminal Authentication in the eMRTD Application is supported by the eMRTD chip, or  
- Chip Authentication in the eMRTD Application is supported by the eMRTD chip  

It **SHALL** contain the following `SecurityInfos`:

- `ChipAuthenticationInfo` as required for Chip Authentication  
- `ChipAuthenticationPublicKeyInfo` as required for Chip Authentication  
- `TerminalAuthenticationInfo` as required by Terminal Authentication  
- The `SecurityInfos` contained in `EF.CardAccess`


## EF.DG15

the file has info about active authentication

## Conditionals

If CardSecurity is missing, it should fallback to using BAC instead of PACE


# ECDH

## Variables
- Curve Domain Parameters, (a, b, G, n, h) can be found in different standarized curves.
- The private key is random integer in range of [1, n-1]
- Compute Public Key by multiplying the private key with generator G
- Shared Secret is computed by multiplying the other parts public key with their private,

## Specific to PACEv2
- First takes a nounce and uses that nounce to map to a new G by taking a point in the curve
- After that both parties chooses their own ephemeral private keys, multiply with new generator to produce ephemeral public key
- then shared secret is computed the standard way   

# How to get Nounce
-The nonce s SHALL be encrypted in CBC mode according to [ISO/IEC 10116] using the key Kπ =
KDFπ(π) derived from the password π and IV set to the all-0 string

# OTHER

They exchange and verify the authentication token TIFD = MAC(KSMAC,PKDH,IC) and
TIC = MAC(KSMAC,PKDH,IFD) as described in Section 4.4.3.4