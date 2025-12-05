# EF Files Reference

All File IDs are defined by 3GPP/ETSI standards and are static across all compliant cards.

## Master File (MF)

| EF ID | Name | Description |
|-------|------|-------------|
| 0x2FE2 | EF_ICCID | ICC Identification |
| 0x2F05 | EF_PL | Preferred Languages |
| 0x2F00 | EF_DIR | Application Directory |

## USIM Application Files (3GPP TS 31.102)

| EF ID | Name | Description | Type |
|-------|------|-------------|------|
| **Identity** ||||
| 0x6F07 | EF_IMSI | International Mobile Subscriber Identity | Transparent |
| 0x6F40 | EF_MSISDN | Mobile Station ISDN Number | Linear Fixed |
| 0x6F46 | EF_SPN | Service Provider Name | Transparent |
| **Administrative** ||||
| 0x6FAD | EF_AD | Administrative Data (UE mode, MNC length) | Transparent |
| 0x6F78 | EF_ACC | Access Control Class | Transparent |
| 0x6F05 | EF_LI | Language Indication | Transparent |
| **Service Tables** ||||
| 0x6F38 | EF_UST | USIM Service Table | Transparent |
| 0x6F56 | EF_EST | Enabled Services Table | Transparent |
| **PLMN Selection** ||||
| 0x6F62 | EF_HPLMNwACT | Home PLMN with Access Technology | Transparent |
| 0x6F61 | EF_OPLMNwACT | Operator Controlled PLMN with ACT | Transparent |
| 0x6F60 | EF_PLMNwACT | User Controlled PLMN with ACT | Transparent |
| 0x6F7B | EF_FPLMN | Forbidden PLMNs | Transparent |
| 0x6F31 | EF_HPPLMN | Higher Priority PLMN Search Period | Transparent |
| **Location** ||||
| 0x6F7E | EF_LOCI | Location Information | Transparent |
| 0x6FAE | EF_PSLOCI | PS Location Information | Transparent |
| 0x6FE3 | EF_EPSLOCI | EPS Location Information | Transparent |
| 0x6F5C | EF_5GS3GPPLOCI | 5GS 3GPP Location Information | Transparent |
| 0x6F5D | EF_5GSN3GPPLOCI | 5GS Non-3GPP Location Information | Transparent |
| **Security** ||||
| 0x6F08 | EF_KEYS | Ciphering and Integrity Keys | Transparent |
| 0x6F09 | EF_KEYSPS | Ciphering and Integrity Keys for PS | Transparent |
| 0x6FE4 | EF_EPSNSC | EPS NAS Security Context | Transparent |
| **Phonebook & SMS** ||||
| 0x6F3A | EF_ADN | Abbreviated Dialling Numbers | Linear Fixed |
| 0x6F3B | EF_FDN | Fixed Dialling Numbers | Linear Fixed |
| 0x6F3C | EF_SMS | Short Messages | Linear Fixed |
| 0x6F42 | EF_SMSP | SMS Parameters | Linear Fixed |
| 0x6F43 | EF_SMSS | SMS Status | Transparent |
| **Other** ||||
| 0x6FC4 | EF_NETPAR | Network Parameters | Transparent |
| 0x6F17 | EF_RP | Roaming Preference | Transparent |

## ISIM Application Files (3GPP TS 31.103)

| EF ID | Name | Description | Type |
|-------|------|-------------|------|
| 0x6F02 | EF_IMPI | IMS Private User Identity | Transparent |
| 0x6F03 | EF_DOMAIN | Home Network Domain Name | Transparent |
| 0x6F04 | EF_IMPU | IMS Public User Identity | Linear Fixed |
| 0x6F07 | EF_IST | ISIM Service Table | Transparent |
| 0x6F09 | EF_PCSCF | P-CSCF Address | Linear Fixed |
| 0x6F22 | EF_UICCIARI | UICC IARI | Linear Fixed |
| 0x6FAD | EF_AD | Administrative Data | Transparent |

## Write Flags

| Flag | EF ID | Description |
|------|-------|-------------|
| `-write-hplmn` | 0x6F62 | Write Home PLMN |
| `-write-oplmn` | 0x6F61 | Write Operator PLMN |
| `-write-user-plmn` | 0x6F60 | Write User PLMN |
| `-clear-fplmn` | 0x6F7B | Clear Forbidden PLMNs |
| `-write-imsi` | 0x6F07 | Write IMSI |
| `-write-spn` | 0x6F46 | Write Service Provider Name |
| `-set-op-mode` | 0x6FAD | Set UE Operation Mode |

**Source:** 3GPP TS 31.102, 3GPP TS 31.103, ETSI TS 102 221

