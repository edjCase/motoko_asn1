import Text "mo:base/Text";
import Nat8 "mo:base/Nat8";
import Nat "mo:base/Nat";
import Nat32 "mo:base/Nat32";
import Iter "mo:base/Iter";
import Buffer "mo:base/Buffer";
import Array "mo:base/Array";
import Char "mo:base/Char";
import Result "mo:base/Result";

module {
    // ASN.1 Tag Classes
    public type TagClass = {
        #universal;
        #application;
        #contextSpecific;
        #private_;
    };

    // ASN.1 Value Types
    public type ASN1Value = {
        #boolean : Bool;
        #integer : [Nat8]; // Using Nat8 array to support arbitrary precision
        #bitString : {
            unusedBits : Nat8;
            data : [Nat8];
        };
        #octetString : [Nat8];
        #null_;
        #objectIdentifier : Text; // Dot-notation string (e.g. "1.2.840.113549.1.1.1")
        #utf8String : Text;
        #printableString : Text;
        #ia5String : Text;
        #utctime : Text;
        #generalizedTime : Text;
        #sequence : [ASN1Value];
        #set : [ASN1Value];
        // Context-specific types
        #contextSpecific : {
            tagNumber : Nat;
            constructed : Bool;
            value : ?ASN1Value;
        };
        // Unknown types - store raw data
        #unknown : {
            tagClass : TagClass;
            tagNumber : Nat;
            constructed : Bool;
            data : [Nat8];
        };
    };

    // Tag numbers for Universal types
    let TAG_BOOLEAN : Nat = 0x01;
    let TAG_INTEGER : Nat = 0x02;
    let TAG_BIT_STRING : Nat = 0x03;
    let TAG_OCTET_STRING : Nat = 0x04;
    let TAG_NULL : Nat = 0x05;
    let TAG_OBJECT_ID : Nat = 0x06;
    let TAG_UTF8_STRING : Nat = 0x0C;
    let TAG_PRINTABLESTRING : Nat = 0x13;
    let TAG_IA5_STRING : Nat = 0x16;
    let TAG_UTCTIME : Nat = 0x17;
    let TAG_GENERALIZEDTIME : Nat = 0x18;
    let TAG_SEQUENCE : Nat = 0x10; // 0x30 with constructed bit
    let TAG_SET : Nat = 0x11; // 0x31 with constructed bit

    type ParseResult<T> = Result.Result<{ value : T; rest : Iter.Iter<Nat8> }, Text>;

    // ===== DECODER FUNCTIONS =====

    // Main ASN.1 parser function
    public func decodeDER(bytes : [Nat8]) : Result.Result<ASN1Value, Text> {
        // Convert byte array to iterator
        let byteIter = Iter.fromArray(bytes);
        switch (decodeInternal(byteIter)) {
            case (#err(e)) return #err(e);
            case (#ok({ value; rest })) {
                // Check if there are remaining bytes
                if (Iter.size<Nat8>(rest) > 0) {
                    return #err("Extra data after ASN.1 value");
                };
                return #ok(value);
            };
        };
    };

    private func decodeInternal(bytes : Iter.Iter<Nat8>) : ParseResult<ASN1Value> {
        // Parse tag
        let tagResult = parseTag(bytes);
        switch (tagResult) {
            case (#err(e)) return #err(e);
            case (#ok({ value = { tagClass; tagNumber; constructed }; rest = bytes })) {

                // Parse length
                let lengthResult = parseLength(bytes);
                switch (lengthResult) {
                    case (#err(e)) return #err(e);
                    case (#ok({ value = length; rest = bytes })) {

                        // Parse value based on tag
                        if (tagClass == #universal) {
                            switch (tagNumber) {
                                case (0x01) {
                                    let valueResult = parseBoolean(bytes, length);
                                    switch (valueResult) {
                                        case (#err(e)) return #err(e);
                                        case (#ok({ value; rest })) {
                                            return #ok({
                                                value = #boolean(value);
                                                rest;
                                            });
                                        };
                                    };
                                };
                                case (0x02) {
                                    let valueResult = parseInteger(bytes, length);
                                    switch (valueResult) {
                                        case (#err(e)) return #err(e);
                                        case (#ok({ value; rest })) {
                                            return #ok({
                                                value = #integer(value);
                                                rest;
                                            });
                                        };
                                    };
                                };
                                case (0x03) {
                                    let valueResult = parseBitString(bytes, length);
                                    switch (valueResult) {
                                        case (#err(e)) return #err(e);
                                        case (#ok({ value; rest })) {
                                            return #ok({
                                                value = #bitString(value);
                                                rest;
                                            });
                                        };
                                    };
                                };
                                case (0x04) {
                                    let valueResult = parseOctetString(bytes, length);
                                    switch (valueResult) {
                                        case (#err(e)) return #err(e);
                                        case (#ok({ value; rest })) {
                                            return #ok({
                                                value = #octetString(value);
                                                rest;
                                            });
                                        };
                                    };
                                };
                                case (0x05) {
                                    let valueResult = parseNull(bytes, length);
                                    switch (valueResult) {
                                        case (#err(e)) return #err(e);
                                        case (#ok({ value = _; rest })) {
                                            return #ok({
                                                value = #null_;
                                                rest;
                                            });
                                        };
                                    };
                                };
                                case (0x06) {
                                    let valueResult = parseObjectIdentifier(bytes, length);
                                    switch (valueResult) {
                                        case (#err(e)) return #err(e);
                                        case (#ok({ value; rest })) {
                                            return #ok({
                                                value = #objectIdentifier(value);
                                                rest;
                                            });
                                        };
                                    };
                                };
                                case (0x0C) {
                                    let valueResult = parseString(bytes, length);
                                    switch (valueResult) {
                                        case (#err(e)) return #err(e);
                                        case (#ok({ value; rest })) {
                                            return #ok({
                                                value = #utf8String(value);
                                                rest;
                                            });
                                        };
                                    };
                                };
                                case (0x13) {
                                    let valueResult = parseString(bytes, length);
                                    switch (valueResult) {
                                        case (#err(e)) return #err(e);
                                        case (#ok({ value; rest })) {
                                            return #ok({
                                                value = #printableString(value);
                                                rest;
                                            });
                                        };
                                    };
                                };
                                case (0x16) {
                                    let valueResult = parseString(bytes, length);
                                    switch (valueResult) {
                                        case (#err(e)) return #err(e);
                                        case (#ok({ value; rest })) {
                                            return #ok({
                                                value = #ia5String(value);
                                                rest;
                                            });
                                        };
                                    };
                                };
                                case (0x17) {
                                    // UTCTime
                                    let valueResult = parseString(bytes, length); // UTCTime is encoded like a string
                                    switch (valueResult) {
                                        case (#err(e)) return #err(e);
                                        case (#ok({ value; rest })) {
                                            return #ok({
                                                value = #utctime(value);
                                                rest;
                                            });
                                        };
                                    };
                                };
                                case (0x18) {
                                    // GeneralizedTime
                                    let valueResult = parseString(bytes, length); // Also encoded like a string
                                    switch (valueResult) {
                                        case (#err(e)) return #err(e);
                                        case (#ok({ value; rest })) {
                                            return #ok({
                                                value = #generalizedTime(value);
                                                rest;
                                            });
                                        };
                                    };
                                };
                                case (0x10) {
                                    if (not constructed) {
                                        return #err("SEQUENCE must be constructed");
                                    };

                                    // Read sequence content
                                    let contentResult = readBytes(bytes, length);
                                    switch (contentResult) {
                                        case (#err(e)) return #err(e);
                                        case (#ok({ value = contentBytes; rest })) {
                                            // Parse sequence elements
                                            let elements = Buffer.Buffer<ASN1Value>(8);
                                            var contentIter = contentBytes.vals();

                                            while (Iter.size<Nat8>(contentIter) > 0) {
                                                let elementResult = decodeInternal(contentIter);
                                                switch (elementResult) {
                                                    case (#err(e)) return #err(e);
                                                    case (#ok({ value; rest = nextIter })) {
                                                        elements.add(value);
                                                        contentIter := nextIter;
                                                    };
                                                };
                                            };

                                            return #ok({
                                                value = #sequence(Buffer.toArray(elements));
                                                rest;
                                            });
                                        };
                                    };
                                };
                                case (0x11) {
                                    if (not constructed) {
                                        return #err("SET must be constructed");
                                    };

                                    // Read set content
                                    let contentResult = readBytes(bytes, length);
                                    switch (contentResult) {
                                        case (#err(e)) return #err(e);
                                        case (#ok({ value = contentBytes; rest })) {
                                            // Parse set elements
                                            let elements = Buffer.Buffer<ASN1Value>(8);
                                            var contentIter = contentBytes.vals();

                                            while (Iter.size<Nat8>(contentIter) > 0) {
                                                let elementResult = decodeInternal(contentIter);
                                                switch (elementResult) {
                                                    case (#err(e)) return #err(e);
                                                    case (#ok({ value; rest = nextIter })) {
                                                        elements.add(value);
                                                        contentIter := nextIter;
                                                    };
                                                };
                                            };

                                            return #ok({
                                                value = #set(Buffer.toArray(elements));
                                                rest;
                                            });
                                        };
                                    };
                                };
                                case (_) {
                                    // Unknown or unsupported universal type
                                    let contentResult = readBytes(bytes, length);
                                    switch (contentResult) {
                                        case (#err(e)) return #err(e);
                                        case (#ok({ value = data; rest })) {
                                            return #ok({
                                                value = #unknown({
                                                    tagClass;
                                                    tagNumber;
                                                    constructed;
                                                    data;
                                                });
                                                rest;
                                            });
                                        };
                                    };
                                };
                            };
                        } else if (tagClass == #contextSpecific) {
                            if (constructed) {
                                // Parse constructed context-specific value
                                let contentResult = readBytes(bytes, length);
                                switch (contentResult) {
                                    case (#err(e)) return #err(e);
                                    case (#ok({ value = contentBytes; rest })) {
                                        if (contentBytes.size() > 0) {
                                            let contentIter = contentBytes.vals();
                                            let innerResult = decodeInternal(contentIter);

                                            switch (innerResult) {
                                                case (#err(e)) return #err(e);
                                                case (#ok({ value; rest = _ })) {
                                                    return #ok({
                                                        value = #contextSpecific({
                                                            tagNumber;
                                                            constructed;
                                                            value = ?value;
                                                        });
                                                        rest;
                                                    });
                                                };
                                            };
                                        } else {
                                            // Empty constructed context-specific value
                                            return #ok({
                                                value = #contextSpecific({
                                                    tagNumber;
                                                    constructed;
                                                    value = null;
                                                });
                                                rest;
                                            });
                                        };
                                    };
                                };
                            } else {
                                // Primitive context-specific value
                                let contentResult = readBytes(bytes, length);
                                switch (contentResult) {
                                    case (#err(e)) return #err(e);
                                    case (#ok({ rest })) {
                                        return #ok({
                                            value = #contextSpecific({
                                                tagNumber;
                                                constructed;
                                                value = null;
                                            });
                                            rest;
                                        });
                                    };
                                };
                            };
                        } else {
                            // APPLICATION or PRIVATE class - store as raw data
                            let contentResult = readBytes(bytes, length);
                            switch (contentResult) {
                                case (#err(e)) return #err(e);
                                case (#ok({ value = data; rest })) {
                                    return #ok({
                                        value = #unknown({
                                            tagClass;
                                            tagNumber;
                                            constructed;
                                            data;
                                        });
                                        rest;
                                    });
                                };
                            };
                        };

                        // Default case if we somehow miss a type
                        return #err("Unsupported ASN.1 type");
                    };
                };
            };
        };
    };

    // Parse ASN.1 DER tag byte
    private func parseTag(bytes : Iter.Iter<Nat8>) : ParseResult<{ tagClass : TagClass; tagNumber : Nat; constructed : Bool }> {
        let ?tagByte = bytes.next() else return #err("Unexpected end of data while parsing tag");

        let tagClass = switch (tagByte >> 6) {
            case (0) #universal;
            case (1) #application;
            case (2) #contextSpecific;
            case (3) #private_;
            case (_) #universal; // Should never happen, but need a default
        };

        let constructed = (tagByte & 0x20) != 0;
        let tagNumber = Nat8.toNat(tagByte & 0x1F);

        // Handle long form tags if necessary
        if (tagNumber == 0x1F) {
            var result = 0;
            var cont = true;

            while (cont) {
                let ?byte = bytes.next() else return #err("Unexpected end of data while parsing long tag");

                result := result * 128 + Nat8.toNat(byte & 0x7F);
                cont := (byte & 0x80) != 0;
            };

            return #ok({
                value = {
                    tagClass;
                    tagNumber = result;
                    constructed;
                };
                rest = bytes;
            });
        };

        #ok({
            value = {
                tagClass;
                tagNumber;
                constructed;
            };
            rest = bytes;
        });
    };

    // Parse ASN.1 DER length
    private func parseLength(bytes : Iter.Iter<Nat8>) : ParseResult<Nat> {
        let ?firstByte = bytes.next() else return #err("Unexpected end of data while parsing length");

        if (firstByte < 0x80) {
            // Short form
            return #ok({
                value = Nat8.toNat(firstByte);
                rest = bytes;
            });
        };

        // Long form
        let numLengthBytes = Nat8.toNat(firstByte & 0x7F);
        if (numLengthBytes == 0) {
            return #err("Indefinite length encoding not supported");
        };

        var length : Nat = 0;
        var i = 0;
        while (i < numLengthBytes) {
            let ?byte = bytes.next() else return #err("Unexpected end of data while parsing length");
            length := length * 256 + Nat8.toNat(byte);
            i += 1;
        };

        #ok({
            value = length;
            rest = bytes;
        });
    };

    // Read a specific number of bytes from an iterator
    private func readBytes(bytes : Iter.Iter<Nat8>, count : Nat) : ParseResult<[Nat8]> {
        let buffer = Buffer.Buffer<Nat8>(count);
        var i = 0;
        while (i < count) {
            let ?byte = bytes.next() else return #err("Unexpected end of data while reading bytes");
            buffer.add(byte);
            i += 1;
        };

        #ok({
            value = Buffer.toArray(buffer);
            rest = bytes;
        });
    };

    // Parse a BOOLEAN value
    private func parseBoolean(bytes : Iter.Iter<Nat8>, length : Nat) : ParseResult<Bool> {
        if (length != 1) {
            return #err("Invalid length for BOOLEAN value");
        };

        let ?value = bytes.next() else return #err("Unexpected end of data while parsing BOOLEAN");

        #ok({
            value = value != 0;
            rest = bytes;
        });
    };

    // Parse an INTEGER value
    private func parseInteger(bytes : Iter.Iter<Nat8>, length : Nat) : ParseResult<[Nat8]> {
        if (length == 0) {
            return #err("Invalid length for INTEGER value");
        };

        readBytes(bytes, length);
    };

    // Parse a BIT_string value
    private func parseBitString(bytes : Iter.Iter<Nat8>, length : Nat) : ParseResult<{ unusedBits : Nat8; data : [Nat8] }> {
        if (length == 0) {
            return #err("Invalid length for BIT_string value");
        };

        let ?unusedBits = bytes.next() else return #err("Unexpected end of data while parsing BIT_string");
        if (unusedBits > 7) {
            return #err("Invalid number of unused bits in BIT_string");
        };

        let byteResult = readBytes(bytes, length - 1);
        switch (byteResult) {
            case (#err(e)) return #err(e);
            case (#ok({ value; rest })) {
                #ok({
                    value = {
                        unusedBits;
                        data = value;
                    };
                    rest;
                });
            };
        };
    };

    // Parse an OCTET_string value
    private func parseOctetString(bytes : Iter.Iter<Nat8>, length : Nat) : ParseResult<[Nat8]> {
        readBytes(bytes, length);
    };

    // Parse a NULL value
    private func parseNull(bytes : Iter.Iter<Nat8>, length : Nat) : ParseResult<()> {
        if (length != 0) {
            return #err("Invalid length for NULL value");
        };

        #ok({
            value = ();
            rest = bytes;
        });
    };

    // Parse an OBJECT_identifier value
    private func parseObjectIdentifier(bytes : Iter.Iter<Nat8>, length : Nat) : ParseResult<Text> {
        if (length == 0) {
            return #err("Invalid length for OBJECT_identifier value");
        };

        let byteResult = readBytes(bytes, length);
        switch (byteResult) {
            case (#err(e)) return #err(e);
            case (#ok({ value = oidBytes; rest })) {
                // Process OID bytes
                let components = Buffer.Buffer<Text>(8);

                // First byte encodes the first two components
                if (oidBytes.size() == 0) {
                    return #err("Empty OBJECT_identifier value");
                };

                let first = oidBytes[0];
                components.add(Nat.toText(Nat8.toNat(first) / 40));
                components.add(Nat.toText(Nat8.toNat(first) % 40));

                var value : Nat = 0;
                var i = 1;
                while (i < oidBytes.size()) {
                    let byte = oidBytes[i];
                    if (byte >= 0x80) {
                        // Continuation byte
                        value := value * 128 + Nat8.toNat(byte & 0x7F);
                    } else {
                        // Last byte of this component
                        value := value * 128 + Nat8.toNat(byte);
                        components.add(Nat.toText(value));
                        value := 0;
                    };
                    i += 1;
                };

                #ok({
                    value = Text.join(".", components.vals());
                    rest;
                });
            };
        };
    };

    // Parse string types (UTF8String, PrintableString, IA5String)
    private func parseString(bytes : Iter.Iter<Nat8>, length : Nat) : ParseResult<Text> {
        let byteResult = readBytes(bytes, length);
        switch (byteResult) {
            case (#err(e)) return #err(e);
            case (#ok({ value; rest })) {
                // Simple ASCII conversion for now
                // A full implementation would need proper UTF-8 decoding
                let chars = Array.map<Nat8, Char>(
                    value,
                    func(b) {
                        Char.fromNat32(Nat32.fromNat(Nat8.toNat(b)));
                    },
                );

                #ok({
                    value = Text.fromIter(chars.vals());
                    rest;
                });
            };
        };
    };

    // ===== ENCODER FUNCTIONS =====

    // Encode an ASN.1 value to DER
    private func encodeDER(value : ASN1Value) : Result.Result<[Nat8], Text> {
        let encoded = Buffer.Buffer<Nat8>(64); // Initial size estimate

        switch (value) {
            case (#boolean(boolValue)) {
                // Tag
                let tag = encodeTag(#universal, false, TAG_BOOLEAN);
                for (b in tag.vals()) encoded.add(b);

                // Length (always 1)
                encoded.add(0x01);

                // Value
                encoded.add(if (boolValue) 0xFF else 0x00);
            };
            case (#integer(intValue)) {
                // Tag
                let tag = encodeTag(#universal, false, TAG_INTEGER);
                for (b in tag.vals()) encoded.add(b);

                // Length
                let length = encodeLength(intValue.size());
                for (b in length.vals()) encoded.add(b);

                // Value
                for (b in intValue.vals()) encoded.add(b);
            };
            case (#bitString({ unusedBits; data })) {
                // Tag
                let tag = encodeTag(#universal, false, TAG_BIT_STRING);
                for (b in tag.vals()) encoded.add(b);

                // Length (data length + 1 for unused bits byte)
                let length = encodeLength(data.size() + 1);
                for (b in length.vals()) encoded.add(b);

                // Value
                encoded.add(unusedBits);
                for (b in data.vals()) encoded.add(b);
            };
            case (#octetString(data)) {
                // Tag
                let tag = encodeTag(#universal, false, TAG_OCTET_STRING);
                for (b in tag.vals()) encoded.add(b);

                // Length
                let length = encodeLength(data.size());
                for (b in length.vals()) encoded.add(b);

                // Value
                for (b in data.vals()) encoded.add(b);
            };
            case (#null_) {
                // Tag
                let tag = encodeTag(#universal, false, TAG_NULL);
                for (b in tag.vals()) encoded.add(b);

                // Length (always 0)
                encoded.add(0x00);

                // No value
            };
            case (#objectIdentifier(oid)) {
                // Tag
                let tag = encodeTag(#universal, false, TAG_OBJECT_ID);
                for (b in tag.vals()) encoded.add(b);

                // Encode OID
                let oidResult = encodeObjectIdentifier(oid);
                switch (oidResult) {
                    case (#err(e)) return #err(e);
                    case (#ok(oidBytes)) {
                        // Length
                        let length = encodeLength(oidBytes.size());
                        for (b in length.vals()) encoded.add(b);

                        // Value
                        for (b in oidBytes.vals()) encoded.add(b);
                    };
                };
            };
            case (#utf8String(str)) {
                // Simplified: we're just encoding as ASCII here
                // A real implementation would need proper UTF-8 encoding

                // Tag
                let tag = encodeTag(#universal, false, TAG_UTF8_STRING);
                for (b in tag.vals()) encoded.add(b);

                // Simple ASCII encoding
                let bytes = Array.map<Char, Nat8>(
                    Iter.toArray(Text.toIter(str)),
                    func(c) { Nat8.fromNat(Nat32.toNat(Char.toNat32(c))) },
                );

                // Length
                let length = encodeLength(bytes.size());
                for (b in length.vals()) encoded.add(b);

                // Value
                for (b in bytes.vals()) encoded.add(b);
            };
            case (#printableString(str)) {
                // Tag
                let tag = encodeTag(#universal, false, TAG_PRINTABLESTRING);
                for (b in tag.vals()) encoded.add(b);

                // Simple ASCII encoding
                let bytes = Array.map<Char, Nat8>(
                    Iter.toArray(Text.toIter(str)),
                    func(c) { Nat8.fromNat(Nat32.toNat(Char.toNat32(c))) },
                );

                // Length
                let length = encodeLength(bytes.size());
                for (b in length.vals()) encoded.add(b);

                // Value
                for (b in bytes.vals()) encoded.add(b);
            };
            case (#ia5String(str)) {
                // Tag
                let tag = encodeTag(#universal, false, TAG_IA5_STRING);
                for (b in tag.vals()) encoded.add(b);

                // Simple ASCII encoding
                let bytes = Array.map<Char, Nat8>(
                    Iter.toArray(Text.toIter(str)),
                    func(c) { Nat8.fromNat(Nat32.toNat(Char.toNat32(c))) },
                );

                // Length
                let length = encodeLength(bytes.size());
                for (b in length.vals()) encoded.add(b);

                // Value
                for (b in bytes.vals()) encoded.add(b);
            };
            case (#sequence(elements)) {
                // Encode each element first
                let contentsBuffer = Buffer.Buffer<Nat8>(64);

                for (element in elements.vals()) {
                    let elementResult = encodeDER(element);
                    switch (elementResult) {
                        case (#err(e)) return #err(e);
                        case (#ok(bytes)) {
                            for (b in bytes.vals()) contentsBuffer.add(b);
                        };
                    };
                };

                let contents = Buffer.toArray(contentsBuffer);

                // Tag
                let tag = encodeTag(#universal, true, TAG_SEQUENCE);
                for (b in tag.vals()) encoded.add(b);

                // Length
                let length = encodeLength(contents.size());
                for (b in length.vals()) encoded.add(b);

                // Value (encoded elements)
                for (b in contents.vals()) encoded.add(b);
            };
            case (#set(elements)) {
                // Encode each element first
                let contentsBuffer = Buffer.Buffer<Nat8>(64);

                for (element in elements.vals()) {
                    let elementResult = encodeDER(element);
                    switch (elementResult) {
                        case (#err(e)) return #err(e);
                        case (#ok(bytes)) {
                            for (b in bytes.vals()) contentsBuffer.add(b);
                        };
                    };
                };

                let contents = Buffer.toArray(contentsBuffer);

                // Tag
                let tag = encodeTag(#universal, true, TAG_SET);
                for (b in tag.vals()) encoded.add(b);

                // Length
                let length = encodeLength(contents.size());
                for (b in length.vals()) encoded.add(b);

                // Value (encoded elements)
                for (b in contents.vals()) encoded.add(b);
            };
            case (#contextSpecific({ tagNumber; constructed; value })) {
                // Tag
                let tag = encodeTag(#contextSpecific, constructed, tagNumber);
                for (b in tag.vals()) encoded.add(b);

                switch (value) {
                    case (null) {
                        // Empty value
                        encoded.add(0x00); // Length 0
                    };
                    case (?innerValue) {
                        // Encode inner value
                        let innerResult = encodeDER(innerValue);
                        switch (innerResult) {
                            case (#err(e)) return #err(e);
                            case (#ok(innerBytes)) {
                                // For constructed, we only need the value part, not the entire TLV
                                if (constructed) {
                                    // Skip the first byte (tag) and extract the inner value
                                    var i = 1; // Start after tag

                                    // Skip the length bytes
                                    if (i < innerBytes.size()) {
                                        let lengthByte = innerBytes[i];
                                        i += 1;

                                        if (lengthByte >= 0x80) {
                                            let numLengthBytes = Nat8.toNat(lengthByte & 0x7F);
                                            i += numLengthBytes;
                                        };
                                    };

                                    // Calculate content length
                                    let contentLength = if (i < innerBytes.size()) {
                                        innerBytes.size() - i : Nat;
                                    } else {
                                        0;
                                    };

                                    // Length
                                    let lengthBytes = encodeLength(contentLength);
                                    for (b in lengthBytes.vals()) encoded.add(b);

                                    // Value (just the content part)
                                    while (i < innerBytes.size()) {
                                        encoded.add(innerBytes[i]);
                                        i += 1;
                                    };
                                } else {
                                    // For primitive, use the entire encoding
                                    // Length
                                    let length = encodeLength(innerBytes.size());
                                    for (b in length.vals()) encoded.add(b);

                                    // Value
                                    for (b in innerBytes.vals()) encoded.add(b);
                                };
                            };
                        };
                    };
                };
            };
            case (#unknown({ tagClass; tagNumber; constructed; data })) {
                // Tag
                let tag = encodeTag(tagClass, constructed, tagNumber);
                for (b in tag.vals()) encoded.add(b);

                // Length
                let length = encodeLength(data.size());
                for (b in length.vals()) encoded.add(b);

                // Value
                for (b in data.vals()) encoded.add(b);
            };
            case (#utctime(time)) {
                // Tag
                let tag = encodeTag(#universal, false, TAG_UTCTIME);
                for (b in tag.vals()) encoded.add(b);

                // Simple ASCII encoding
                let bytes = Array.map<Char, Nat8>(
                    Iter.toArray(Text.toIter(time)),
                    func(c) { Nat8.fromNat(Nat32.toNat(Char.toNat32(c))) },
                );

                // Length
                let length = encodeLength(bytes.size());
                for (b in length.vals()) encoded.add(b);

                // Value
                for (b in bytes.vals()) encoded.add(b);
            };
            case (#generalizedTime(time)) {
                // Tag
                let tag = encodeTag(#universal, false, TAG_GENERALIZEDTIME);
                for (b in tag.vals()) encoded.add(b);

                // Simple ASCII encoding
                let bytes = Array.map<Char, Nat8>(
                    Iter.toArray(Text.toIter(time)),
                    func(c) { Nat8.fromNat(Nat32.toNat(Char.toNat32(c))) },
                );

                // Length
                let length = encodeLength(bytes.size());
                for (b in length.vals()) encoded.add(b);

                // Value
                for (b in bytes.vals()) encoded.add(b);
            };
        };

        #ok(Buffer.toArray(encoded));
    };

    // Encode a tag byte
    private func encodeTag(tagClass : TagClass, constructed : Bool, tagNumber : Nat) : [Nat8] {
        let classValue : Nat8 = switch (tagClass) {
            case (#universal) 0x00;
            case (#application) 0x40;
            case (#contextSpecific) 0x80;
            case (#private_) 0xC0;
        };

        let constructedBit : Nat8 = if (constructed) 0x20 else 0x00;

        if (tagNumber < 31) {
            // Short form
            let tagByte : Nat8 = classValue | constructedBit | Nat8.fromNat(tagNumber);
            return [tagByte];
        } else {
            // Long form
            let tagBytes = Buffer.Buffer<Nat8>(6); // Reasonable size for most tag numbers

            // Initial byte
            tagBytes.add(classValue | constructedBit | 0x1F);

            // Convert the tag number to base-128 encoding with continuation bits
            var value = tagNumber;
            let octets = Buffer.Buffer<Nat8>(5);

            // Add the octets in reverse order first
            while (value > 0) {
                octets.add(Nat8.fromNat(value % 128));
                value := value / 128;
            };

            // Reverse and set continuation bits
            let length = octets.size();
            let lastIndex : Nat = length - 1;
            for (i in Iter.range(0, lastIndex)) {
                let octet = octets.get(lastIndex - i);
                if (i < lastIndex) {
                    tagBytes.add(0x80 | octet);
                } else {
                    tagBytes.add(octet);
                };
            };

            Buffer.toArray(tagBytes);
        };
    };

    // Encode a length field
    private func encodeLength(length : Nat) : [Nat8] {
        if (length < 128) {
            // Short form
            return [Nat8.fromNat(length)];
        } else {
            // Long form
            let lengthBytes = Buffer.Buffer<Nat8>(5); // Can handle lengths up to 2^32-1
            var tempLength = length;
            let octets = Buffer.Buffer<Nat8>(4);

            // Convert to octets (big-endian)
            while (tempLength > 0) {
                octets.add(Nat8.fromNat(tempLength % 256));
                tempLength := tempLength / 256;
            };

            // Add length of length octets
            lengthBytes.add(0x80 | Nat8.fromNat(octets.size()));

            // Add length octets in big-endian order
            for (i in Iter.range(0, octets.size() - 1)) {
                lengthBytes.add(octets.get(octets.size() - 1 - i));
            };

            Buffer.toArray(lengthBytes);
        };
    };

    // Encode an OBJECT_identifier
    private func encodeObjectIdentifier(oid : Text) : Result.Result<[Nat8], Text> {
        let components = Iter.toArray(Text.split(oid, #char('.')));

        if (components.size() < 2) {
            return #err("OID must have at least 2 components");
        };

        // Parse first two components
        let ?first = Nat.fromText(components[0]) else return #err("Invalid OID component: " # components[0]);
        let ?second = Nat.fromText(components[1]) else return #err("Invalid OID component: " # components[1]);

        if (first > 2) {
            return #err("First OID component must be 0, 1, or 2");
        };

        if (first < 2 and second >= 40) {
            return #err("Second OID component must be < 40 when first component is 0 or 1");
        };

        let encoded = Buffer.Buffer<Nat8>(components.size() * 2); // Reasonable estimate

        // Encode first two components into a single byte
        encoded.add(Nat8.fromNat(first * 40 + second));

        // Encode remaining components
        for (i in Iter.range(2, components.size() - 1)) {
            let ?value = Nat.fromText(components[i]) else return #err("Invalid OID component: " # components[i]);

            if (value < 128) {
                // Single byte encoding
                encoded.add(Nat8.fromNat(value));
            } else {
                // Multi-byte encoding
                let octets = Buffer.Buffer<Nat8>(5); // Can handle values up to 2^35-1
                var tempValue = value;

                // Convert to base-128 with continuation bits
                while (tempValue > 0) {
                    octets.add(Nat8.fromNat(tempValue % 128));
                    tempValue := tempValue / 128;
                };

                // Add octets in reverse order with continuation bits
                let length = octets.size();
                let lastIndex : Nat = length - 1;
                for (j in Iter.range(0, lastIndex)) {
                    let octet = octets.get(lastIndex - j);
                    if (j < lastIndex) {
                        encoded.add(0x80 | octet);
                    } else {
                        encoded.add(octet);
                    };
                };
            };
        };

        #ok(Buffer.toArray(encoded));
    };

    // ===== UTILITY FUNCTIONS =====

    // Helper to convert bytes to hex string
    private func bytesToHex(bytes : [Nat8]) : Text {
        let hexChars = [
            '0',
            '1',
            '2',
            '3',
            '4',
            '5',
            '6',
            '7',
            '8',
            '9',
            'A',
            'B',
            'C',
            'D',
            'E',
            'F',
        ];

        let result = Buffer.Buffer<Char>(bytes.size() * 2);

        for (b in bytes.vals()) {
            let high = Nat8.toNat(b) / 16;
            let low = Nat8.toNat(b) % 16;

            result.add(hexChars[high]);
            result.add(hexChars[low]);
        };

        Text.fromIter(result.vals());
    };

    // Helper to pretty print ASN.1 structures
    public func toText(value : ASN1Value) : Text {
        toTextIndent(value, 0);
    };

    // Helper for pretty printing with indentation
    public func toTextIndent(value : ASN1Value, indent : Nat) : Text {
        let indentStr = Text.join("", Iter.fromArray(Array.tabulate<Text>(indent, func(_) { "  " })));

        switch (value) {
            case (#boolean(boolValue)) {
                indentStr # "BOOLEAN: " # (if (boolValue) "TRUE" else "FALSE");
            };
            case (#integer(intValue)) {
                indentStr # "INTEGER: " # bytesToHex(intValue);
            };
            case (#bitString({ unusedBits; data })) {
                indentStr # "BIT STRING: [" # Nat8.toText(unusedBits) # " unused bits] " # bytesToHex(data);
            };
            case (#octetString(data)) {
                indentStr # "OCTET STRING: " # bytesToHex(data);
            };
            case (#null_) {
                indentStr # "NULL";
            };
            case (#objectIdentifier(oid)) {
                indentStr # "OBJECT IDENTIFIER: " # oid;
            };
            case (#utf8String(str)) {
                indentStr # "UTF8String: " # str;
            };
            case (#printableString(str)) {
                indentStr # "PrintableString: " # str;
            };
            case (#ia5String(str)) {
                indentStr # "IA5String: " # str;
            };
            case (#utctime(time)) {
                indentStr # "UTCTime: " # time;
            };
            case (#generalizedTime(time)) {
                indentStr # "GeneralizedTime: " # time;
            };
            case (#sequence(elements)) {
                var result = indentStr # "SEQUENCE {\n";

                for (element in elements.vals()) {
                    result #= toTextIndent(element, indent + 1) # "\n";
                };

                result #= indentStr # "}";
                result;
            };
            case (#set(elements)) {
                var result = indentStr # "SET {\n";

                for (element in elements.vals()) {
                    result #= toTextIndent(element, indent + 1) # "\n";
                };

                result #= indentStr # "}";
                result;
            };
            case (#contextSpecific({ tagNumber; constructed; value })) {
                var result = indentStr # "[" # Nat.toText(tagNumber) # "] ";
                result #= if (constructed) "CONSTRUCTED " else "PRIMITIVE ";

                switch (value) {
                    case (null) {
                        result #= "EMPTY";
                    };
                    case (?innerValue) {
                        result #= "{\n" # toTextIndent(innerValue, indent + 1) # "\n" # indentStr # "}";
                    };
                };

                result;
            };
            case (#unknown({ tagClass; tagNumber; constructed; data })) {
                indentStr # "UNKNOWN TAG [" # (
                    switch (tagClass) {
                        case (#universal) "UNIVERSAL";
                        case (#application) "APPLICATION";
                        case (#contextSpecific) "CONTEXT_specific";
                        case (#private_) "PRIVATE";
                    }
                ) # " " # Nat.toText(tagNumber) # "] " #
                (if (constructed) "CONSTRUCTED" else "PRIMITIVE") # ": " #
                bytesToHex(data);
            };
        };
    };
};
