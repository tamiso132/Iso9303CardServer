# eMRTD / ICAO 9303 Passport Reader (C#)

This project implements a C# library for reading and verifying **Electronic Machine Readable Travel Documents (eMRTD)**, such as electronic passports and ID cards. It adheres to **ICAO 9303** standards and supports advanced security protocols including **PACE**, **Passive Authentication**, **Active Authentication**, and **Chip Authentication**.

## Key Features

* **Secure Messaging**: Implementation of **PACE** (Password Authenticated Connection Establishment) using MRZ/CAN to encrypt communication channels.
* **Passive Authentication (PA)**: Full verification of the Document Security Object (`EF.SOD`), Chain of Trust (CSCA), and Data Group integrity.
* **Active Authentication (AA)**: Verifies the chip is not a clone using RSA/ECDSA signature challenges.
* **Chip Authentication (CA)**: Advanced clone detection using Elliptic Curves (ECDH).
* **Custom ASN.1/TLV Parsing**: Lightweight, recursive parsers for processing raw chip data without heavy framework dependencies.

---

## 📂 Project Structure

The codebase is organized into logical layers. Here is where to find specific functionality:

### 🔐 1. Authentication & Security Logic
*Core logic for verifying the passport's authenticity and calculating hashes.*

* **`Helper/helper.cs`** (Specifically `class SodHelper`)
    * **Role**: The "Brain" of Passive Authentication.
    * **Key Functions**:
        * `CheckSodIntegrity`: Verifies the SOD signature and checks that `eContent` hashes match the `SignedAttributes`.
        * `VerifyChipSignature`: Validates the Document Signer Certificate (DSC) against the local CSCA Master List (Chain of Trust).
        * `VerifyDataGroups`: Reads actual files (DG1, DG2, etc.) from the chip and compares their hashes against the SOD "Master List".
* **`Encryption/encryption.cs`**
    * **Role**: Handles **PACE** cryptographic primitives, Key Derivation, and OID mappings.
    * **Key Components**:
        * `PassHelper.DerivePaceKey`: Derives the initial Kπ from MRZ or CAN.
        * `PassHelper.DeriveSessionKeys`: Generates the Session Keys (Encryption + MAC) for Secure Messaging.
        * `EncryptionInfo`: Maps OIDs to specific algorithms (Brainpool, NIST, AES, etc.).
        * `ECDH`: Handling of Elliptic Curve Diffie-Hellman key agreement.

### 📡 2. Communication & Protocols
*Logic for talking to the NFC chip and wrapping commands in Secure Messaging.*

* **`Command/command.cs`**
    * **Role**: Handles the low-level APDU protocol.
    * **Key Features**:
        * **Secure Messaging**: Automatically encrypts/decrypts APDUs (`FormatEncryptedCommand`, `ParseCommand`) and verifies CMACs.
        * **Commands**: Methods for `ReadBinary`, `SelectApplication`, `GeneralAuthenticate`, and `MseSetAT`.
* **`App/application.cs`**
    * **Role**: The main workflow orchestrator.
    * **Key Flows**:
        * `ClientSession.Start()`: The entry point for the reading process.
        * `SetupSecureMessaging()`: Performs the PACE handshake to establish an encrypted channel.
        * `SetupPassiveAuthentication()`: Calls helpers to verify the SOD and Data Groups.
        * `SetupActiveAuthentication()` / `SetupChipAuthentication()`: Performs clone detection logic.
* **`Interfaces/interfaces.cs`**
    * Defines contracts for `ICommunicator` (NFC/USB abstraction) and `IServerFormat`.

### 📝 3. Parsing & Data Models
*Logic for decoding the raw byte streams from the chip.*

* **`Parser/sodparsertest.cs`** (`class EfSodParser`)
    * **Role**: Specific parser for the `EF.SOD` file.
    * **Key Features**: Extracts `SignerInfo`, `EncapsulatedContent` (DG Hashes), `Signature`, and the `DocumentSignerCertificate`.
* **`Parser/tagparser.cs`** (`class TagReader`)
    * **Role**: A robust, recursive **TLV (Tag-Length-Value)** parser.
    * **Usage**: Used heavily to navigate complex ASN.1 structures inside the SOD and Data Groups.
* **`Parser/efparser.cs`**
    * **Role**: Parsers for specific files like `EF.CardAccess` (to extract PACE security infos) and `EF.COM`.
* **`Asn1/asn1.cs`**
    * **Role**: Helper for **building** ASN.1 structures (used when sending commands to the chip) and a generic node parser.

### 🛠 4. Utilities & Error Handling
* **`Helper/helper.cs`** (General Utils):
    * `MrzUtils`: Calculates check digits for MRZ keys.
    * `HashCalculator`: Dynamically switches between SHA-1, SHA-256, SHA-384, etc., based on OIDs.
    * `Log`: Console logging utility with color coding.
* **`ErrorHandling/error.cs`**:
    * Defines the `Result<T>` pattern to handle errors functionally without excessive try-catch blocks.

---

## 🧩 Authentication Flow

If you are debugging the verification process, the logic flows through these files in this order:

1.  **PACE Handshake**
    * `application.cs` -> `SetupSecureMessaging` -> `encryption.cs` (Key Derivation) -> `command.cs` (General Authenticate).
2.  **Read SOD**
    * `application.cs` -> `EfSodParser.ParseFromHexString`.
3.  **Passive Auth Step 1 (Integrity)**     * `helper.cs` -> `SodHelper.CheckSodIntegrity`.
    * *Checks if SOD Hash == SignedAttribute Hash.*
4.  **Passive Auth Step 2 (Trust)**
    * `helper.cs` -> `SodHelper.VerifyChipSignature`.
    * *Checks if the Document Signer Certificate is signed by a trusted CSCA in the local Master List.*
5.  **Passive Auth Step 3 (Data)**
    * `helper.cs` -> `SodHelper.VerifyDataGroups`.
    * *Reads DG1/DG2 etc., hashes them, and checks against the SOD hash list.*
6.  **Clone Detection**     * `application.cs` -> `SetupActiveAuthentication` (RSA/ECDSA signature challenge) OR `SetupChipAuthentication`.

## 📦 Dependencies

* **BouncyCastle** (`Org.BouncyCastle`): Used heavily for X.509 certificates, ASN.1 parsing, and Cryptographic primitives (RSA, ECDSA, CMAC, ECDH).
* **System.IO.Ports / NFC Reader Library**: (Implementation specific to `ICommunicator`).
* **.NET 8.0**