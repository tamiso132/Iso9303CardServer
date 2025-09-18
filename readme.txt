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
