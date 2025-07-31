import Text "mo:core/Text";
import Nat8 "mo:core/Nat8";
import Nat "mo:core/Nat";
import Iter "mo:core/Iter";
import Array "mo:core/Array";
import Char "mo:core/Char";
import Result "mo:core/Result";
import IterX "mo:xtended-iter/IterX";
import PeekableIter "mo:xtended-iter/PeekableIter";
import Int "mo:core/Int";
import Blob "mo:core/Blob";
import Buffer "mo:buffer";
import IntX "mo:xtended-numbers/IntX";
import List "mo:core/List";

module {

  public type Encoding = {
    #der; // Distinguished Encoding Rules
  };

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
  public func fromBytes(bytes : Iter.Iter<Nat8>, encoding : Encoding) : Result.Result<ASN1Value, Text> {
    // Convert byte array to iterator
    let byteIter = IterX.toPeekable<Nat8>(bytes);
    switch (decodeInternal(byteIter, encoding)) {
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

  private func decodeInternal(bytes : PeekableIter.PeekableIter<Nat8>, encoding : Encoding) : Result.Result<ASN1Value, Text> {
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
                      let elements = List.empty<ASN1Value>();
                      var contentIter = PeekableIter.fromIter(contentBytes.vals());
                      while (PeekableIter.hasNext(contentIter)) {
                        let elementResult = decodeInternal(contentIter, encoding);
                        switch (elementResult) {
                          case (#err(e)) return #err(e);
                          case (#ok(value)) {
                            List.add(elements, value);
                          };
                        };
                      };

                      return #ok(#sequence(List.toArray(elements)));
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
                      let elements = List.empty<ASN1Value>();
                      var contentIter = PeekableIter.fromIter(contentBytes.vals());

                      while (PeekableIter.hasNext(contentIter)) {
                        let elementResult = decodeInternal(contentIter, encoding);
                        switch (elementResult) {
                          case (#err(e)) return #err(e);
                          case (#ok(value)) {
                            List.add(elements, value);
                          };
                        };
                      };

                      return #ok(#set(List.toArray(elements)));
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
                      let innerResult = decodeInternal(contentIter, encoding);

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
    let elements = List.empty<Nat8>();
    var i = 0;
    while (i < count) {
      let ?byte = bytes.next() else return #err("Unexpected end of data while reading bytes");
      List.add(elements, byte);
      i += 1;
    };

    #ok(List.toArray(elements));
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
      case (#ok(b)) switch (IntX.fromIntBytes(b.vals(), #msb)) {
        case (null) return #err("Invalid INTEGER value");
        case (?intValue) return #ok(intValue);
      };
    };
  };

  // Parse a BIT_STRING value
  private func parseBitString(bytes : Iter.Iter<Nat8>, length : Nat) : Result.Result<BitString, Text> {
    if (length == 0) {
      return #err("Invalid length for BIT_STRING value");
    };

    // First byte tells how many bits to ignore in the last byte
    let ?unusedBits = bytes.next() else return #err("Unexpected end of data while parsing BIT_STRING");
    if (unusedBits > 7) {
      return #err("Invalid number of unused bits in BIT_STRING");
    };

    // Read the data bytes
    let byteResult = readBytes(bytes, length - 1);
    switch (byteResult) {
      case (#err(e)) return #err(e);
      case (#ok(data)) #ok({
        unusedBits;
        data = data;
      });
    };
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
        let components = List.empty<Nat>();

        // First byte encodes the first two components
        if (oidBytes.size() == 0) {
          return #err("Empty OBJECT_identifier value");
        };

        let first = oidBytes[0];
        List.add(components, Nat8.toNat(first) / 40);
        List.add(components, Nat8.toNat(first) % 40);

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
            List.add(components, value);
            value := 0;
          };
          i += 1;
        };

        #ok(List.toArray(components));
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
  public func toBytes(value : ASN1Value, encoding : Encoding) : [Nat8] {
    let bufferList = List.empty<Nat8>();
    toBytesBuffer(Buffer.fromList(bufferList), value, encoding);
    List.toArray(bufferList);
  };

  public func toBytesBuffer(buffer : Buffer.Buffer<Nat8>, value : ASN1Value, encoding : Encoding) {
    switch (value) {
      case (#boolean(boolValue)) {
        // Tag
        encodeTag(buffer, #universal, false, TAG_BOOLEAN);

        // Length (always 1)
        buffer.write(0x01);

        // Value
        buffer.write(if (boolValue) 0xFF else 0x00);
      };
      case (#integer(intValue)) {
        // Tag
        encodeTag(buffer, #universal, false, TAG_INTEGER);

        // Encode the integer value
        let tmpBufferList = List.empty<Nat8>();
        IntX.toIntBytesBuffer(Buffer.fromList(tmpBufferList), intValue, #msb);

        // Length
        encodeLength(buffer, List.size(tmpBufferList));

        // Value
        Buffer.writeMany(buffer, List.values(tmpBufferList));
      };
      case (#bitString({ unusedBits; data })) {
        // Tag
        encodeTag(buffer, #universal, false, TAG_BIT_STRING);

        // Length (data length + 1 for unused bits byte)
        encodeLength(buffer, data.size() + 1);

        // Add unused bits byte
        buffer.write(unusedBits);

        Buffer.writeMany(buffer, data.vals());
      };
      case (#octetString(data)) {
        // Tag
        encodeTag(buffer, #universal, false, TAG_OCTET_STRING);

        // Length
        encodeLength(buffer, data.size());

        // Value
        Buffer.writeMany(buffer, data.vals());
      };
      case (#null_) {
        // Tag
        encodeTag(buffer, #universal, false, TAG_NULL);

        // Length (always 0)
        buffer.write(0x00);

        // No value
      };
      case (#objectIdentifier(oid)) {
        // Tag
        encodeTag(buffer, #universal, false, TAG_OBJECT_ID);

        // Create a temporary list for the OID
        let tmpBufferList = List.empty<Nat8>();
        encodeObjectIdentifier(Buffer.fromList(tmpBufferList), oid);

        // Length
        encodeLength(buffer, List.size(tmpBufferList));

        // Value
        Buffer.writeMany(buffer, List.values(tmpBufferList));
      };
      case (#utf8String(str)) {
        // Tag
        encodeTag(buffer, #universal, false, TAG_UTF8_STRING);

        let bytes = Text.encodeUtf8(str);

        // Length
        encodeLength(buffer, bytes.size());

        // Value
        Buffer.writeMany(buffer, bytes.vals());
      };
      case (#printableString(str)) {
        // Tag
        encodeTag(buffer, #universal, false, TAG_PRINTABLESTRING);

        let bytes = Text.encodeUtf8(str);

        // Length
        encodeLength(buffer, bytes.size());

        // Value
        Buffer.writeMany(buffer, bytes.vals());
      };
      case (#ia5String(str)) {
        // Tag
        encodeTag(buffer, #universal, false, TAG_IA5_STRING);

        let bytes = Text.encodeUtf8(str);

        // Length
        encodeLength(buffer, bytes.size());

        // Value
        Buffer.writeMany(buffer, bytes.vals());
      };
      case (#sequence(elements)) {
        // Encode each element first to a temporary list
        let tmpBufferList = List.empty<Nat8>();
        let tmpBuffer = Buffer.fromList(tmpBufferList);

        for (element in elements.vals()) {
          toBytesBuffer(tmpBuffer, element, encoding);
        };

        // Tag
        encodeTag(buffer, #universal, true, TAG_SEQUENCE);

        // Length
        encodeLength(buffer, List.size(tmpBufferList));

        // Value (encoded elements)
        Buffer.writeMany(buffer, List.values(tmpBufferList));
      };
      case (#set(elements)) {
        // Encode each element first to a temporary list
        let tmpBufferList = List.empty<Nat8>();
        let tmpBuffer = Buffer.fromList(tmpBufferList);

        for (element in elements.vals()) {
          toBytesBuffer(tmpBuffer, element, encoding);
        };

        // Tag
        encodeTag(buffer, #universal, true, TAG_SET);

        // Length
        encodeLength(buffer, List.size(tmpBufferList));

        // Value (encoded elements)
        Buffer.writeMany(buffer, List.values(tmpBufferList));
      };
      case (#contextSpecific({ tagNumber; constructed; value })) {
        // Tag
        encodeTag(buffer, #contextSpecific, constructed, tagNumber);

        switch (value) {
          case (null) {
            // Empty value
            buffer.write(0x00); // Length 0
          };
          case (?innerValue) {
            // Create a temporary list for the inner value
            let innerBufferList = List.empty<Nat8>();
            let innerBuffer = Buffer.fromList(innerBufferList);
            toBytesBuffer(innerBuffer, innerValue, encoding);

            // For constructed, we only need the value part, not the entire TLV
            if (constructed) {
              // Length
              encodeLength(buffer, List.size(innerBufferList));

              // Value (include the entire inner encoding)
              Buffer.writeMany(buffer, List.values(innerBufferList));
            } else {
              // For primitive, use the entire encoding
              // Length
              encodeLength(buffer, List.size(innerBufferList));

              // Value
              Buffer.writeMany(buffer, List.values(innerBufferList));
            };
          };
        };
      };
      case (#unknown({ tagClass; tagNumber; constructed; data })) {
        // Tag
        encodeTag(buffer, tagClass, constructed, tagNumber);

        // Length
        encodeLength(buffer, data.size());

        // Value
        Buffer.writeMany(buffer, data.vals());
      };
      case (#utctime(time)) {
        // Tag
        encodeTag(buffer, #universal, false, TAG_UTCTIME);

        let bytes = Text.encodeUtf8(time);

        // Length
        encodeLength(buffer, bytes.size());

        // Value
        Buffer.writeMany(buffer, bytes.vals());
      };
      case (#generalizedTime(time)) {
        // Tag
        encodeTag(buffer, #universal, false, TAG_GENERALIZEDTIME);

        let bytes = Text.encodeUtf8(time);

        // Length
        encodeLength(buffer, bytes.size());

        // Value
        Buffer.writeMany(buffer, bytes.vals());
      };
    };
  };

  // Encode a tag byte
  private func encodeTag(buffer : Buffer.Buffer<Nat8>, tagClass : TagClass, constructed : Bool, tagNumber : Nat) {
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
      buffer.write(tagByte);
    } else {
      // Long form
      // Initial byte
      buffer.write(classValue | constructedBit | 0x1F);

      // Convert the tag number to base-128 encoding with continuation bits
      var value = tagNumber;

      // Create temporary array for octets in reverse order
      let octets = List.empty<Nat8>();

      // Add the octets in reverse order first
      while (value > 0) {
        List.add(octets, Nat8.fromNat(value % 128));
        value := value / 128;
      };

      // Reverse and set continuation bits
      let octetArray = List.toArray(octets);
      let length = octetArray.size();
      let lastIndex : Nat = length - 1;
      for (i in octetArray.keys()) {
        let octet = octetArray[lastIndex - i];
        if (i < lastIndex) {
          buffer.write(0x80 | octet);
        } else {
          buffer.write(octet);
        };
      };
    };
  };

  // Encode a length field
  private func encodeLength(buffer : Buffer.Buffer<Nat8>, length : Nat) {
    if (length < 128) {
      // Short form
      buffer.write(Nat8.fromNat(length));
    } else {
      // Long form
      var tempLength = length;
      let octets = List.empty<Nat8>();

      // Convert to octets (big-endian)
      while (tempLength > 0) {
        List.add(octets, Nat8.fromNat(tempLength % 256));
        tempLength := tempLength / 256;
      };

      // Add length of length octets
      buffer.write(0x80 | Nat8.fromNat(List.size(octets)));

      // Add length octets in big-endian order
      let octetArray = List.toArray(octets);
      for (i in octetArray.keys()) {
        buffer.write(octetArray[octetArray.size() - 1 - i]);
      };
    };
  };

  // Encode an OBJECT_identifier
  private func encodeObjectIdentifier(buffer : Buffer.Buffer<Nat8>, oid : [Nat]) {
    // Validate first two components
    let first = oid[0];
    let second = oid[1];

    // Encode first two components into a single byte
    buffer.write(Nat8.fromNat(first * 40 + second));

    // Encode remaining components
    for (i in Nat.range(2, oid.size())) {
      let value = oid[i];

      if (value < 128) {
        // Single byte encoding
        buffer.write(Nat8.fromNat(value));
      } else {
        // Multi-byte encoding
        let octets = List.empty<Nat8>(); // Can handle values up to 2^35-1
        var tempValue = value;

        // Convert to base-128 with continuation bits
        while (tempValue > 0) {
          List.add(octets, Nat8.fromNat(tempValue % 128));
          tempValue := tempValue / 128;
        };

        // Add octets in reverse order with continuation bits
        let length = List.size(octets);
        let octetArray = List.toArray(octets);
        let lastIndex : Nat = length - 1;
        for (j in octetArray.keys()) {
          let octet = octetArray[lastIndex - j];
          if (j < lastIndex) {
            buffer.write(0x80 | octet);
          } else {
            buffer.write(octet);
          };
        };
      };
    };
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

    let result = List.empty<Char>();

    for (b in bytes.vals()) {
      let high = Nat8.toNat(b) / 16;
      let low = Nat8.toNat(b) % 16;

      List.add(result, hexChars[high]);
      List.add(result, hexChars[low]);
    };

    Text.fromIter(List.toArray(result).vals());
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
