# Motoko ASN.1

[![MOPS](https://img.shields.io/badge/MOPS-asn1-blue)](https://mops.one/asn1)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/yourusername/motoko_asn1/blob/main/LICENSE)

A Motoko implementation of ASN.1 (Abstract Syntax Notation One) encoding and decoding.

## ⚠️ Partial Implementation

This library implements the core ASN.1 DER encoding and decoding functionality, but is missing several ASN.1 types:

**Missing Types (by usage frequency):**

1. ENUMERATED - Used in protocols like SNMP, LDAP
2. BMPString - Common in certificates and internationalized applications
3. NumericString - Used in telephony and financial protocols
4. VisibleString/ISO646String - Legacy systems and restricted environments
5. TeletexString/T61String - Older X.509 certificates
6. REAL - Scientific and technical applications
7. DATE, DATE-TIME - Modern alternatives to UTCTime/GeneralizedTime
8. RELATIVE-OID - X.500 directory services
9. Other less common types (EXTERNAL, GraphicString, UniversalString, etc.)

## Package

### MOPS

```bash
mops add asn1
```

To set up MOPS package manager, follow the instructions from the [MOPS Site](https://mops.one)

## Quick Start

### Example 1: Encoding ASN.1 to DER

```motoko
import ASN1 "mo:asn1";
import Result "mo:base/Result";
import Debug "mo:base/Debug";
import Nat "mo:base/Nat";

// Create an ASN.1 SEQUENCE value
let sequence = #sequence([
    #integer(123),
    #utf8String("Hello ASN.1"),
    #boolean(true)
]);

// Encode to DER format
let bytes : [Nat8] = ASN1.encodeDER(sequence);
...
```

### Example 2: Decoding DER to ASN.1

```motoko
import ASN1 "mo:asn1";
import Result "mo:base/Result";
import Debug "mo:base/Debug";

// Assuming 'derBytes' contains DER-encoded data
let derBytes : [Nat8] = [...];

// Decode from DER
let value : ASN1.ASN1Value = switch (ASN1.decodeDER(derBytes.vals())) {
    case (#err(msg)) return #err(msg);
    case (#ok(value)) value;
};
```

### Example 3: Pretty-Printing ASN.1 Values

```motoko
import ASN1 "mo:asn1";
import Debug "mo:base/Debug";

// Create an ASN.1 structure
let certificate = #sequence([
    #objectIdentifier([1, 2, 840, 113549, 1, 1, 11]), // sha256WithRSAEncryption
    #utf8String("Example Certificate"),
    #contextSpecific({
        tagNumber = 0;
        constructed = true;
        value = ?#sequence([
            #utctime("220101000000Z"),
            #utctime("230101000000Z")
        ])
    })
]);

// Print a human-readable representation
let prettyText = ASN1.toText(certificate);
Debug.print(prettyText);
// Output:
// SEQUENCE {
//   OBJECT IDENTIFIER: 1.2.840.113549.1.1.11
//   UTF8String: Example Certificate
//   [0] CONSTRUCTED {
//     SEQUENCE {
//       UTCTime: 220101000000Z
//       UTCTime: 230101000000Z
//     }
//   }
// }
```

## API Reference

### Types

```motoko
public type TagClass = {
    #universal;
    #application;
    #contextSpecific;
    #private_;
};

public type ASN1Value = {
    #boolean : Bool;
    #integer : Int;
    #bitString : BitString;
    #octetString : [Nat8];
    #null_;
    #objectIdentifier : [Nat];
    #utf8String : Text;
    #printableString : Text;
    #ia5String : Text;
    #utctime : Text;
    #generalizedTime : Text;
    #sequence : [ASN1Value];
    #set : [ASN1Value];
    // Context-specific types
    #contextSpecific : ContextSpecificASN1Value;
    // Unknown types - store raw data
    #unknown : UnknownASN1Value;
};

public type BitString = {
    data : [Nat8];
    // Number of unused bits in the last byte (0-7)
    unusedBits : Nat8;
};

public type ContextSpecificASN1Value = {
    tagNumber : Nat;
    constructed : Bool;
    value : ?ASN1Value;
};

public type UnknownASN1Value = {
    tagClass : TagClass;
    tagNumber : Nat;
    constructed : Bool;
    data : [Nat8];
};
```

### Functions

```motoko
// Main encoding/decoding functions
public func decodeDER(bytes : [Nat8]) : Result.Result<ASN1Value, Text>;

public func encodeDER(value : ASN1Value) : [Nat8];

public func encodeDERToBuffer(buffer : Buffer.Buffer<Nat>, value : ASN1Value);

// Utility function for pretty-printing
public func toText(value : ASN1Value) : Text;
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
