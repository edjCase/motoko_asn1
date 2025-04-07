import Text "mo:base/Text";
import Nat8 "mo:base/Nat8";
import Nat "mo:base/Nat";
import Nat32 "mo:base/Nat32";
import Iter "mo:base/Iter";
import Buffer "mo:base/Buffer";
import Array "mo:base/Array";
import Char "mo:base/Char";
import Result "mo:base/Result";
import IterTools "mo:itertools/Iter";
import PeekableIter "mo:itertools/PeekableIter";
import Int "mo:new-base/Int";
import Blob "mo:new-base/Blob";
import IntX "mo:xtended-numbers/IntX";

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
        #integer : Int;
        #bitString : [Bool];
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

    // ===== DECODER FUNCTIONS =====

    // Main ASN.1 parser function
    public func decodeDER(bytes : [Nat8]) : Result.Result<ASN1Value, Text> {
        // Convert byte array to iterator
        let byteIter = IterTools.peekable<Nat8>(bytes.vals());
        switch (decodeInternal(byteIter)) {
            case (#err(e)) return #err(e);
            case (#ok(value)) {
                // Check if there are remaining bytes
                if (PeekableIter.hasNext(byteIter)) {
                    return #err("Extra data after ASN.1 value");
                };
                return #ok(value);
            };
        };
    };

    private func decodeInternal(bytes : PeekableIter.PeekableIter<Nat8>) : Result.Result<ASN1Value, Text> {
        // Parse tag
        let tagResult = parseTag(bytes);
        switch (tagResult) {
            case (#err(e)) return #err(e);
            case (#ok({ tagClass; tagNumber; constructed })) {

                // Parse length
                let lengthResult = parseLength(bytes);
                switch (lengthResult) {
                    case (#err(e)) return #err(e);
                    case (#ok(length)) {

                        // Parse value based on tag
                        if (tagClass == #universal) {
                            switch (tagNumber) {
                                case (0x01) {
                                    let valueResult = parseBoolean(bytes, length);
                                    switch (valueResult) {
                                        case (#err(e)) return #err(e);
                                        case (#ok(value)) return #ok(#boolean(value));
                                    };
                                };
                                case (0x02) {
                                    let valueResult = parseInteger(bytes, length);
                                    switch (valueResult) {
                                        case (#err(e)) return #err(e);
                                        case (#ok(value)) return #ok(#integer(value));
                                    };
                                };
                                case (0x03) {
                                    let valueResult = parseBitString(bytes, length);
                                    switch (valueResult) {
                                        case (#err(e)) return #err(e);
                                        case (#ok(value)) return #ok(#bitString(value));
                                    };
                                };
                                case (0x04) {
                                    let valueResult = parseOctetString(bytes, length);
                                    switch (valueResult) {
                                        case (#err(e)) return #err(e);
                                        case (#ok(value)) return #ok(#octetString(value));
                                    };
                                };
                                case (0x05) {
                                    if (length != 0) {
                                        return #err("Invalid length for NULL value");
                                    };
                                    return #ok(#null_);
                                };
                                case (0x06) {
                                    let valueResult = parseObjectIdentifier(bytes, length);
                                    switch (valueResult) {
                                        case (#err(e)) return #err(e);
                                        case (#ok(value)) return #ok(#objectIdentifier(value));
                                    };
                                };
                                case (0x0C) {
                                    let valueResult = parseString(bytes, length);
                                    switch (valueResult) {
                                        case (#err(e)) return #err(e);
                                        case (#ok(value)) {
                                            return #ok(#utf8String(value));
                                        };
                                    };
                                };
                                case (0x13) {
                                    let valueResult = parseString(bytes, length);
                                    switch (valueResult) {
                                        case (#err(e)) return #err(e);
                                        case (#ok(value)) {
                                            return #ok(#printableString(value));
                                        };
                                    };
                                };
                                case (0x16) {
                                    let valueResult = parseString(bytes, length);
                                    switch (valueResult) {
                                        case (#err(e)) return #err(e);
                                        case (#ok(value)) {
                                            return #ok(#ia5String(value));
                                        };
                                    };
                                };
                                case (0x17) {
                                    // UTCTime
                                    let valueResult = parseString(bytes, length); // UTCTime is encoded like a string
                                    switch (valueResult) {
                                        case (#err(e)) return #err(e);
                                        case (#ok(value)) {
                                            return #ok(#utctime(value));
                                        };
                                    };
                                };
                                case (0x18) {
                                    // GeneralizedTime
                                    let valueResult = parseString(bytes, length); // Also encoded like a string
                                    switch (valueResult) {
                                        case (#err(e)) return #err(e);
                                        case (#ok(value)) {
                                            return #ok(#generalizedTime(value));
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
                                        case (#ok(contentBytes)) {
                                            // Parse sequence elements
                                            let elements = Buffer.Buffer<ASN1Value>(8);
                                            var contentIter = PeekableIter.fromIter(contentBytes.vals());
                                            while (PeekableIter.hasNext(contentIter)) {
                                                let elementResult = decodeInternal(contentIter);
                                                switch (elementResult) {
                                                    case (#err(e)) return #err(e);
                                                    case (#ok(value)) {
                                                        elements.add(value);
                                                    };
                                                };
                                            };

                                            return #ok(#sequence(Buffer.toArray(elements)));
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
                                        case (#ok(contentBytes)) {
                                            // Parse set elements
                                            let elements = Buffer.Buffer<ASN1Value>(8);
                                            var contentIter = PeekableIter.fromIter(contentBytes.vals());

                                            while (PeekableIter.hasNext(contentIter)) {
                                                let elementResult = decodeInternal(contentIter);
                                                switch (elementResult) {
                                                    case (#err(e)) return #err(e);
                                                    case (#ok(value)) {
                                                        elements.add(value);
                                                    };
                                                };
                                            };

                                            return #ok(#set(Buffer.toArray(elements)));
                                        };
                                    };
                                };
                                case (_) {
                                    // Unknown or unsupported universal type
                                    let contentResult = readBytes(bytes, length);
                                    switch (contentResult) {
                                        case (#err(e)) return #err(e);
                                        case (#ok(data)) {
                                            return #ok(#unknown({ tagClass; tagNumber; constructed; data }));
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
                                    case (#ok(contentBytes)) {
                                        if (contentBytes.size() > 0) {
                                            let contentIter = PeekableIter.fromIter(contentBytes.vals());
                                            let innerResult = decodeInternal(contentIter);

                                            switch (innerResult) {
                                                case (#err(e)) return #err(e);
                                                case (#ok(value)) {
                                                    return #ok(#contextSpecific({ tagNumber; constructed; value = ?value }));
                                                };
                                            };
                                        } else {
                                            // Empty constructed context-specific value
                                            return #ok(#contextSpecific({ tagNumber; constructed; value = null }));
                                        };
                                    };
                                };
                            } else {
                                // Primitive context-specific value
                                let contentResult = readBytes(bytes, length);
                                switch (contentResult) {
                                    case (#err(e)) return #err(e);
                                    case (#ok(bytes)) {
                                        return #ok(#unknown({ tagClass = #contextSpecific; tagNumber = tagNumber; constructed = false; data = bytes }));
                                    };
                                };
                            };
                        } else {
                            // APPLICATION or PRIVATE class - store as raw data
                            let contentResult = readBytes(bytes, length);
                            switch (contentResult) {
                                case (#err(e)) return #err(e);
                                case (#ok(data)) {
                                    return #ok(#unknown({ tagClass; tagNumber; constructed; data }));
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
    private func parseTag(bytes : Iter.Iter<Nat8>) : Result.Result<{ tagClass : TagClass; tagNumber : Nat; constructed : Bool }, Text> {
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
                tagClass;
                tagNumber = result;
                constructed;
            });
        };

        #ok({
            tagClass;
            tagNumber;
            constructed;
        });
    };

    // Parse ASN.1 DER length
    private func parseLength(bytes : Iter.Iter<Nat8>) : Result.Result<Nat, Text> {
        let ?firstByte = bytes.next() else return #err("Unexpected end of data while parsing length");

        if (firstByte < 0x80) {
            // Short form
            return #ok(Nat8.toNat(firstByte));
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

        #ok(length);
    };

    // Read a specific number of bytes from an iterator
    private func readBytes(bytes : Iter.Iter<Nat8>, count : Nat) : Result.Result<[Nat8], Text> {
        let buffer = Buffer.Buffer<Nat8>(count);
        var i = 0;
        while (i < count) {
            let ?byte = bytes.next() else return #err("Unexpected end of data while reading bytes");
            buffer.add(byte);
            i += 1;
        };

        #ok(Buffer.toArray(buffer));
    };

    // Parse a BOOLEAN value
    private func parseBoolean(bytes : Iter.Iter<Nat8>, length : Nat) : Result.Result<Bool, Text> {
        if (length != 1) {
            return #err("Invalid length for BOOLEAN value");
        };

        let ?value = bytes.next() else return #err("Unexpected end of data while parsing BOOLEAN");

        #ok(value != 0);
    };

    // Parse an INTEGER value
    private func parseInteger(bytes : Iter.Iter<Nat8>, length : Nat) : Result.Result<Int, Text> {
        if (length == 0) {
            return #err("Invalid length for INTEGER value");
        };

        let byteResult = readBytes(bytes, length);
        switch (byteResult) {
            case (#err(e)) return #err(e);
            case (#ok(b)) switch (IntX.decodeInt(b.vals(), #msb)) {
                case (null) return #err("Invalid INTEGER value");
                case (?intValue) return #ok(intValue);
            };
        };
    };

    // Parse a BIT_string value
    private func parseBitString(bytes : Iter.Iter<Nat8>, length : Nat) : Result.Result<[Bool], Text> {
        if (length == 0) {
            return #err("Invalid length for BIT_string value");
        };

        // First byte tells how many bits to ignore in the last byte
        let ?unusedBits = bytes.next() else return #err("Unexpected end of data while parsing BIT_string");
        if (unusedBits > 7) {
            return #err("Invalid number of unused bits in BIT_string");
        };

        // Read the data bytes
        let byteResult = readBytes(bytes, length - 1);
        let data = switch (byteResult) {
            case (#err(e)) return #err(e);
            case (#ok(data)) data;
        };
        // Create a buffer to hold the bits
        let bits = Buffer.Buffer<Bool>(data.size() * 8);

        // Process each byte
        var i = 0;
        while (i < data.size()) {
            let byte = data[i];
            let isLastByte = i == (data.size() - 1 : Nat);

            // Process each bit in the byte
            var j = 0;
            label w while (j < 8) {
                // Skip unused bits in the last byte
                if (isLastByte and j >= (8 - Nat8.toNat(unusedBits) : Nat)) {
                    break w;
                };

                // Test if bit is set (from most significant to least significant)
                let bitSet = (byte & (1 << Nat8.fromNat(7 - j))) != 0;
                bits.add(bitSet);

                j += 1;
            };

            i += 1;
        };

        #ok(Buffer.toArray(bits));
    };

    // Parse an OCTET_string value
    private func parseOctetString(bytes : Iter.Iter<Nat8>, length : Nat) : Result.Result<[Nat8], Text> {
        readBytes(bytes, length);
    };

    // Parse an OBJECT_identifier value
    private func parseObjectIdentifier(bytes : Iter.Iter<Nat8>, length : Nat) : Result.Result<[Nat], Text> {
        if (length == 0) {
            return #err("Invalid length for OBJECT_identifier value");
        };

        let byteResult = readBytes(bytes, length);
        switch (byteResult) {
            case (#err(e)) return #err(e);
            case (#ok(oidBytes)) {
                // Process OID bytes
                let components = Buffer.Buffer<Nat>(8);

                // First byte encodes the first two components
                if (oidBytes.size() == 0) {
                    return #err("Empty OBJECT_identifier value");
                };

                let first = oidBytes[0];
                components.add(Nat8.toNat(first) / 40);
                components.add(Nat8.toNat(first) % 40);

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
                        components.add(value);
                        value := 0;
                    };
                    i += 1;
                };

                #ok(Buffer.toArray(components));
            };
        };
    };

    // Parse string types (UTF8String, PrintableString, IA5String)
    private func parseString(bytes : Iter.Iter<Nat8>, length : Nat) : Result.Result<Text, Text> {
        let byteResult = readBytes(bytes, length);
        switch (byteResult) {
            case (#err(e)) return #err(e);
            case (#ok(value)) {
                let ?text = Text.decodeUtf8(Blob.fromArray(value)) else return #err("Invalid UTF-8 string");
                #ok(text);
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

                let valueBuffer = Buffer.Buffer<Nat8>(64);
                IntX.encodeInt(valueBuffer, intValue, #msb);

                // Length
                let length = encodeLength(valueBuffer.size());
                for (b in length.vals()) encoded.add(b);

                // Value
                encoded.append(valueBuffer);
            };
            case (#bitString(bits)) {
                // Tag
                let tag = encodeTag(#universal, false, TAG_BIT_STRING);
                for (b in tag.vals()) encoded.add(b);

                // Calculate bytes needed and unused bits
                let totalBits = bits.size();
                let completeBytes = totalBits / 8;
                let remainingBits = totalBits % 8;
                let totalBytes = if (remainingBits == 0) completeBytes else completeBytes + 1;
                let unusedBits : Nat8 = if (remainingBits == 0) 0 else Nat8.fromNat(8 - remainingBits);

                // Length (data bytes + 1 for unused bits byte)
                let length = encodeLength(totalBytes + 1);
                for (b in length.vals()) encoded.add(b);

                // Add unused bits byte
                encoded.add(unusedBits);

                // Pack bits into bytes
                var byteValue : Nat8 = 0;
                var bitIndex : Nat8 = 0;

                for (bit in bits.vals()) {
                    if (bit) {
                        byteValue := byteValue | (1 << (7 - (bitIndex % 8)));
                    };

                    bitIndex += 1;

                    // When we've filled a byte, add it to the output
                    if (bitIndex % 8 == 0) {
                        encoded.add(byteValue);
                        byteValue := 0;
                    };
                };

                // Add final partial byte if needed
                if (remainingBits > 0) {
                    encoded.add(byteValue);
                };
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

                let bytes = Text.encodeUtf8(time);

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

                let bytes = Text.encodeUtf8(time);

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
    private func encodeObjectIdentifier(oid : [Nat]) : Result.Result<[Nat8], Text> {
        if (oid.size() < 2) {
            return #err("OID must have at least 2 components");
        };

        // Validate first two components
        let first = oid[0];
        let second = oid[1];

        if (first > 2) {
            return #err("First OID component must be 0, 1, or 2");
        };

        if (first < 2 and second >= 40) {
            return #err("Second OID component must be < 40 when first component is 0 or 1");
        };

        let encoded = Buffer.Buffer<Nat8>(oid.size() * 2); // Reasonable estimate

        // Encode first two components into a single byte
        encoded.add(Nat8.fromNat(first * 40 + second));

        // Encode remaining components
        for (i in Iter.range(2, oid.size() - 1)) {
            let value = oid[i];

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
                indentStr # "INTEGER: " # Int.toText(intValue);
            };
            case (#bitString(bits)) {
                let bitText = bits.vals()
                |> Iter.map(
                    _,
                    func(b : Bool) : Text = if (b) "1" else "0",
                )
                |> Text.join("", _);
                indentStr # "BIT STRING: " # bitText;
            };
            case (#octetString(data)) {
                indentStr # "OCTET STRING: " # bytesToHex(data);
            };
            case (#null_) {
                indentStr # "NULL";
            };
            case (#objectIdentifier(oid)) {
                let oidText = oid.vals()
                |> Iter.map(_, func(n : Nat) : Text = Nat.toText(n))
                |> Text.join(".", _);
                indentStr # "OBJECT IDENTIFIER: " # oidText;
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
                        case (#contextSpecific) "CONTEXT_SPECIFIC";
                        case (#private_) "PRIVATE";
                    }
                ) # " " # Nat.toText(tagNumber) # "] " #
                (if (constructed) "CONSTRUCTED" else "PRIMITIVE") # ": " #
                bytesToHex(data);
            };
        };
    };
};
