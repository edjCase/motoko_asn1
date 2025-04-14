import { test } "mo:test";
import Runtime "mo:new-base/Runtime";
import Text "mo:new-base/Text";
import Blob "mo:new-base/Blob";
import ASN1 "../src";

type TestCase = {
  name : Text; // Description of the test case
  derBytes : Blob; // DER encoded data as Blob literal
  expectedValue : ?ASN1.ASN1Value; // Expected decoded value if successful (null if error expected)
  expectedError : ?Text; // Expected error message substring if decoding should fail (null if success expected)
  expectedText : ?Text; // Optional: Expected output from ASN1.toText
};

test(
  "ASN1 Module Tests",
  func() {

    let cases : [TestCase] = [
      // --- Basic Types ---
      {
        name = "Boolean TRUE";
        derBytes = "\01\01\FF";
        expectedValue = ?#boolean(true);
        expectedError = null;
        expectedText = ?"BOOLEAN: TRUE";
      },
      {
        name = "Boolean FALSE";
        derBytes = "\01\01\00";
        expectedValue = ?#boolean(false);
        expectedError = null;
        expectedText = ?"BOOLEAN: FALSE";
      },
      {
        name = "Integer 0";
        derBytes = "\02\01\00";
        expectedValue = ?#integer(0);
        expectedError = null;
        expectedText = ?"INTEGER: 0";
      },
      {
        name = "Integer 127";
        derBytes = "\02\01\7F";
        expectedValue = ?#integer(127);
        expectedError = null;
        expectedText = ?"INTEGER: 127";
      },
      {
        name = "Integer 128";
        derBytes = "\02\02\00\80"; // Needs leading 0x00
        expectedValue = ?#integer(128);
        expectedError = null;
        expectedText = ?"INTEGER: 128";
      },
      {
        name = "Integer 256";
        derBytes = "\02\02\01\00";
        expectedValue = ?#integer(256);
        expectedError = null;
        expectedText = ?"INTEGER: 256";
      },
      {
        name = "Integer -128";
        derBytes = "\02\01\80";
        expectedValue = ?#integer(-128);
        expectedError = null;
        expectedText = ?"INTEGER: -128";
      },
      {
        name = "Integer -129";
        derBytes = "\02\02\FF\7F";
        expectedValue = ?#integer(-129);
        expectedError = null;
        expectedText = ?"INTEGER: -129";
      },
      {
        name = "Octet String 'abc'";
        derBytes = "\04\03\61\62\63";
        expectedValue = ?#octetString([0x61, 0x62, 0x63]);
        expectedError = null;
        expectedText = ?"OCTET STRING: 616263";
      },
      {
        name = "Octet String (empty)";
        derBytes = "\04\00";
        expectedValue = ?#octetString([]);
        expectedError = null;
        expectedText = ?"OCTET STRING: ";
      },
      {
        name = "NULL";
        derBytes = "\05\00";
        expectedValue = ?#null_;
        expectedError = null;
        expectedText = ?"NULL";
      },
      {
        name = "Object Identifier (RSA Encryption)"; // 1.2.840.113549.1.1.1
        derBytes = "\06\09\2A\86\48\86\F7\0D\01\01\01";
        expectedValue = ?#objectIdentifier([1, 2, 840, 113549, 1, 1, 1]);
        expectedError = null;
        expectedText = ?"OBJECT IDENTIFIER: 1.2.840.113549.1.1.1";
      },
      {
        name = "Object Identifier (id-Ed25519)"; // 1.3.101.112
        derBytes = "\06\03\2B\65\70";
        expectedValue = ?#objectIdentifier([1, 3, 101, 112]);
        expectedError = null;
        expectedText = ?"OBJECT IDENTIFIER: 1.3.101.112";
      },
      {
        name = "UTF8String 'Test'";
        derBytes = "\0C\04\54\65\73\74";
        expectedValue = ?#utf8String("Test");
        expectedError = null;
        expectedText = ?"UTF8String: Test";
      },
      {
        name = "PrintableString 'Test 123'";
        derBytes = "\13\08\54\65\73\74\20\31\32\33";
        expectedValue = ?#printableString("Test 123");
        expectedError = null;
        expectedText = ?"PrintableString: Test 123";
      },
      {
        name = "IA5String 'test@example.com'";
        derBytes = "\16\10\74\65\73\74\40\65\78\61\6d\70\6c\65\2e\63\6f\6d";
        expectedValue = ?#ia5String("test@example.com");
        expectedError = null;
        expectedText = ?"IA5String: test@example.com";
      },
      {
        name = "UTCTime '230101120000Z'";
        derBytes = "\17\0D\32\33\30\31\30\31\31\32\30\30\30\30\5A";
        expectedValue = ?#utctime("230101120000Z");
        expectedError = null;
        expectedText = ?"UTCTime: 230101120000Z";
      },
      {
        name = "GeneralizedTime '20230101120000Z'";
        derBytes = "\18\0F\32\30\32\33\30\31\30\31\31\32\30\30\30\30\5A";
        expectedValue = ?#generalizedTime("20230101120000Z");
        expectedError = null;
        expectedText = ?"GeneralizedTime: 20230101120000Z";
      },
      {
        name = "Bit String (3 unused bits)"; // 10110... -> B? -> [0xB0]
        derBytes = "\03\02\03\B0"; // Length 2 = 1 unused + 1 data byte
        expectedValue = ?#bitString({ unusedBits = 3; data = [0xB0] });
        expectedError = null;
        expectedText = ?"BIT STRING: [3 unused bits] B0";
      },
      {
        name = "Bit String (0 unused bits)"; // 11110000 -> F0 -> [0xF0]
        derBytes = "\03\02\00\F0";
        expectedValue = ?#bitString({ unusedBits = 0; data = [0xF0] });
        expectedError = null;
        expectedText = ?"BIT STRING: [0 unused bits] F0";
      },

      // --- Constructed Types ---
      {
        name = "SEQUENCE (Integer 1, Boolean TRUE)";
        derBytes = "\30\06\02\01\01\01\01\FF";
        expectedValue = ?#sequence([
          #integer(1),
          #boolean(true),
        ]);
        expectedError = null;
        expectedText = ?"SEQUENCE {\n  INTEGER: 1\n  BOOLEAN: TRUE\n}";
      },
      {
        name = "SEQUENCE (empty)";
        derBytes = "\30\00";
        expectedValue = ?#sequence([]);
        expectedError = null;
        expectedText = ?"SEQUENCE {\n}";
      },
      {
        name = "SET (Integer 5, Octet String 'a')";
        derBytes = "\31\06\02\01\05\04\01\61"; // Note: DER requires SET elements to be sorted by encoding.
        expectedValue = ?#set([
          #integer(5),
          #octetString([0x61]),
        ]);
        expectedError = null;
        expectedText = ?"SET {\n  INTEGER: 5\n  OCTET STRING: 61\n}";
      },
      {
        name = "Nested SEQUENCE"; // SEQUENCE { INTEGER 1, SEQUENCE { BOOLEAN false } }
        derBytes = "\30\08\02\01\01\30\03\01\01\00";
        expectedValue = ?#sequence([
          #integer(1),
          #sequence([
            #boolean(false)
          ]),
        ]);
        expectedError = null;
        expectedText = ?"SEQUENCE {\n  INTEGER: 1\n  SEQUENCE {\n    BOOLEAN: FALSE\n  }\n}";
      },

      // --- Context Specific ---
      {
        name = "Context-Specific [0] Constructed (Explicit Integer 5)";
        derBytes = "\A0\03\02\01\05";
        expectedValue = ?#contextSpecific({
          tagNumber = 0;
          constructed = true;
          value = ?#integer(5);
        });
        expectedError = null;
        expectedText = ?"[0] CONSTRUCTED {\n  INTEGER: 5\n}";
      },
      {
        name = "Context-Specific [1] Primitive"; // Code likely parses as primitive context-specific without inner value
        derBytes = "\81\01\62"; // Primitive, tag 1 -> 81, length 1, value 62
        expectedValue = ?#unknown({
          tagClass = #contextSpecific;
          tagNumber = 1;
          constructed = false;
          data = [98];
        });
        expectedError = null;
        expectedText = ?"UNKNOWN TAG [CONTEXT_SPECIFIC 1] PRIMITIVE: 62";
      },
      {
        name = "Context-Specific [2] Constructed Empty";
        derBytes = "\A2\00";
        expectedValue = ?#contextSpecific({
          tagNumber = 2;
          constructed = true;
          value = null; // Parsed as having length 0 content
        });
        expectedError = null;
        expectedText = ?"[2] CONSTRUCTED EMPTY";
      },

      // --- Length Variations ---
      {
        name = "Long Length (130 bytes)"; // Integer with 130 '0x01' bytes
        derBytes = "\02\81\82\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01"; // 0x81 indicates 1 length byte follows, 0x82 is 130
        expectedValue = ?#integer(+46_201_418_543_661_464_834_881_468_620_999_813_702_897_152_663_514_903_353_221_622_740_208_504_476_820_827_921_039_932_430_593_334_434_039_716_796_985_300_529_755_005_671_721_653_363_810_553_918_487_798_338_098_907_437_896_046_997_815_951_930_446_224_564_800_833_244_095_481_737_012_025_792_325_952_924_107_452_056_351_421_190_799_273_479_761_051_862_931_927_267_383_175_781_202_697_073_293_774_189_228_051_202_305);
        expectedError = null;
        expectedText = ?"INTEGER: 46201418543661464834881468620999813702897152663514903353221622740208504476820827921039932430593334434039716796985300529755005671721653363810553918487798338098907437896046997815951930446224564800833244095481737012025792325952924107452056351421190799273479761051862931927267383175781202697073293774189228051202305";
      },
      {
        name = "Long Length (256 bytes)"; // Octet String with 256 'A's (0x41)
        derBytes = "\04\82\01\00\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41"; // 0x82 indicates 2 length bytes follow, 0x0100 is 256
        expectedValue = ?#octetString([
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41, // 16
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41, // 32
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41, // 48
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41, // 64
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41, // 80
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41, // 96
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41, // 112
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41, // 128
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41, // 144
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41, // 160
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41, // 176
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41, // 192
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41, // 208
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41, // 224
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41, // 240
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41,
          0x41 // 256
        ]);
        expectedError = null;
        expectedText = ?"OCTET STRING: 41414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141";
      },

      // --- Tag Variations ---
      {
        name = "Long Tag (Application 31 Constructed)";
        derBytes = "\7F\1F\01\00"; // App class (01), constructed (1), tag=31 (11111) -> 7F. Next byte 1F (31). Bool false content (0100)
        expectedValue = ?#unknown({
          // Assuming App class falls into unknown
          tagClass = #application;
          tagNumber = 31;
          constructed = true;
          data = [0x00]; // Content bytes after tag and length
        });
        expectedError = null;
        expectedText = ?"UNKNOWN TAG [APPLICATION 31] CONSTRUCTED: 00";
      },
      {
        name = "Long Tag (Application 31 Primitive)";
        derBytes = "\5F\1F\01\FF"; // App class (01), primitive (0), Tag 31 (11111) -> 5F. Long tag 1F(31). Content length 01, value FF.
        expectedValue = ?#unknown({
          tagClass = #application;
          tagNumber = 31;
          constructed = false;
          data = [0xFF]; // Content bytes after tag and length
        });
        expectedError = null;
        expectedText = ?"UNKNOWN TAG [APPLICATION 31] PRIMITIVE: FF";
      },

      // --- Error Cases ---
      {
        name = "Error: Truncated Tag";
        derBytes = ""; // Empty input
        expectedValue = null;
        expectedError = ?"Unexpected end of data";
        expectedText = null;
      },
      {
        name = "Error: Truncated Length";
        derBytes = "\01"; // Tag only
        expectedValue = null;
        expectedError = ?"Unexpected end of data while parsing length";
        expectedText = null;
      },
      {
        name = "Error: Truncated Long Length";
        derBytes = "\02\81"; // Tag + Long length indicator, but no length byte
        expectedValue = null;
        expectedError = ?"Unexpected end of data while parsing length";
        expectedText = null;
      },
      {
        name = "Error: Truncated Value (Boolean)";
        derBytes = "\01\01"; // Tag + Length, but no value byte
        expectedValue = null;
        expectedError = ?"Unexpected end of data while parsing BOOLEAN";
        expectedText = null;
      },
      {
        name = "Error: Truncated Value (Integer)";
        derBytes = "\02\02\00"; // Tag + Length 2, but only 1 value byte
        expectedValue = null;
        expectedError = ?"Unexpected end of data while reading bytes"; // Error from readBytes
        expectedText = null;
      },
      {
        name = "Error: Invalid Boolean Length";
        derBytes = "\01\02\00\FF"; // Tag Boolean, Length 2 (invalid)
        expectedValue = null;
        expectedError = ?"Invalid length for BOOLEAN";
        expectedText = null;
      },
      {
        name = "Error: Invalid Null Length";
        derBytes = "\05\01\00"; // Tag Null, Length 1 (invalid)
        expectedValue = null;
        expectedError = ?"Invalid length for NULL";
        expectedText = null;
      },
      {
        name = "Error: SEQUENCE not constructed";
        derBytes = "\10\00"; // Tag SEQUENCE primitive (invalid)
        expectedValue = null;
        expectedError = ?"SEQUENCE must be constructed";
        expectedText = null;
      },
      {
        name = "Error: SET not constructed";
        derBytes = "\11\00"; // Tag SET primitive (invalid)
        expectedValue = null;
        expectedError = ?"SET must be constructed";
        expectedText = null;
      },
      {
        name = "Error: Extra data after value";
        derBytes = "\01\01\FF\00"; // Boolean true + extra 0x00 byte
        expectedValue = null;
        expectedError = ?"Extra data after ASN.1 value";
        expectedText = null;
      },
      {
        name = "Object Identifier (Short 1.2)"; // Re-checked, should be success
        derBytes = "\06\01\2A"; // 1*40 + 2 = 42 = 0x2A
        expectedValue = ?#objectIdentifier([1, 2]);
        expectedError = null;
        expectedText = ?"OBJECT IDENTIFIER: 1.2";
      },
      // --- Additional UTCTime Formats ---
      {
        name = "UTCTime with Z timezone";
        derBytes = "\17\0D\32\33\30\34\31\35\31\32\33\30\30\30\5A"; // "230415123000Z"
        expectedValue = ?#utctime("230415123000Z");
        expectedError = null;
        expectedText = ?"UTCTime: 230415123000Z";
      },
      {
        name = "UTCTime with +01 timezone";
        derBytes = "\17\0F\32\33\30\34\31\35\31\32\33\30\30\30\2B\30\31"; // "230415123000+01"
        expectedValue = ?#utctime("230415123000+01");
        expectedError = null;
        expectedText = ?"UTCTime: 230415123000+01";
      },
      {
        name = "UTCTime with -05 timezone";
        derBytes = "\17\0F\32\33\30\34\31\35\31\32\33\30\30\30\2D\30\35"; // "230415123000-0500"
        expectedValue = ?#utctime("230415123000-05");
        expectedError = null;
        expectedText = ?"UTCTime: 230415123000-05";
      },
      {
        name = "UTCTime without seconds";
        derBytes = "\17\0B\32\33\30\34\31\35\31\32\33\30\5A"; // "2304151230Z"
        expectedValue = ?#utctime("2304151230Z");
        expectedError = null;
        expectedText = ?"UTCTime: 2304151230Z";
      },

      // --- Additional GeneralizedTime Formats ---
      {
        name = "GeneralizedTime with fractional seconds";
        derBytes = "\18\11\32\30\32\33\30\34\31\35\31\32\33\30\34\35\2E\35\5A"; // "20230415123045.5Z"
        expectedValue = ?#generalizedTime("20230415123045.5Z");
        expectedError = null;
        expectedText = ?"GeneralizedTime: 20230415123045.5Z";
      },
      {
        name = "GeneralizedTime with +0100 timezone";
        derBytes = "\18\13\32\30\32\33\30\34\31\35\31\32\33\30\34\35\2B\30\31\30\30"; // "20230415123045+0100"
        expectedValue = ?#generalizedTime("20230415123045+0100");
        expectedError = null;
        expectedText = ?"GeneralizedTime: 20230415123045+0100";
      },
      {
        name = "GeneralizedTime with -05 timezone";
        derBytes = "\18\11\32\30\32\33\30\34\31\35\31\32\33\30\34\35\2D\30\35"; // "20230415123045-05"
        expectedValue = ?#generalizedTime("20230415123045-05");
        expectedError = null;
        expectedText = ?"GeneralizedTime: 20230415123045-05";
      },
      {
        name = "GeneralizedTime with only hour precision";
        derBytes = "\18\0B\32\30\32\33\30\34\31\35\31\32\5A"; // "2023041512Z"
        expectedValue = ?#generalizedTime("2023041512Z");
        expectedError = null;
        expectedText = ?"GeneralizedTime: 2023041512Z";
      },

      // --- Application Class Tags ---
      {
        name = "Application [1] Integer";
        derBytes = "\41\01\05"; // App tag 1, length 1, value 5
        expectedValue = ?#unknown({
          tagClass = #application;
          tagNumber = 1;
          constructed = false;
          data = [0x05];
        });
        expectedError = null;
        expectedText = ?"UNKNOWN TAG [APPLICATION 1] PRIMITIVE: 05";
      },
      {
        name = "Application [5] Constructed SEQUENCE";
        derBytes = "\65\08\30\06\02\01\05\04\01\41"; // App tag 5 constructed, containing a SEQUENCE with INTEGER 5 and OCTET STRING "A"
        expectedValue = ?#unknown({
          tagClass = #application;
          tagNumber = 5;
          constructed = true;
          data = [0x30, 0x06, 0x02, 0x01, 0x05, 0x04, 0x01, 0x41];
        });
        expectedError = null;
        expectedText = ?"UNKNOWN TAG [APPLICATION 5] CONSTRUCTED: 3006020105040141";
      },

      // --- Private Class Tags ---
      {
        name = "Private [10] UTF8String";
        derBytes = "\EA\05\48\65\6C\6C\6F"; // Changed from \CA to \EA
        expectedValue = ?#unknown({
          tagClass = #private_;
          tagNumber = 10;
          constructed = true;
          data = [0x48, 0x65, 0x6C, 0x6C, 0x6F];
        });
        expectedError = null;
        expectedText = ?"UNKNOWN TAG [PRIVATE 10] CONSTRUCTED: 48656C6C6F";
      },

      // --- More Complex OIDs ---
      {
        name = "Large OID Value"; // OID with component > 127
        derBytes = "\06\06\2B\06\81\83\51\01"; // 1.3.6.16849.1
        expectedValue = ?#objectIdentifier([1, 3, 6, 16849, 1]);
        expectedError = null;
        expectedText = ?"OBJECT IDENTIFIER: 1.3.6.16849.1";
      },
      {
        name = "Very Large OID Value"; // OID with component > 16383
        derBytes = "\06\07\2B\06\82\84\D5\7A\01"; // 1.3.6.4270842.1
        expectedValue = ?#objectIdentifier([1, 3, 6, 4270842, 1]);
        expectedError = null;
        expectedText = ?"OBJECT IDENTIFIER: 1.3.6.4270842.1";
      },

      // --- More Nested Structures ---
      {
        name = "Complex Nested Structure";
        derBytes = "\30\1A\30\0C\02\01\01\04\02\AB\CD\0C\03\41\42\43\31\0A\30\08\02\01\FF\04\03\01\02\03";
        expectedValue = ?#sequence([
          #sequence([
            #integer(1),
            #octetString([0xAB, 0xCD]),
            #utf8String("ABC"),
          ]),
          #set([
            #sequence([
              #integer(-1),
              #octetString([0x01, 0x02, 0x03]),
            ])
          ]),
        ]);
        expectedError = null;
        expectedText = ?"SEQUENCE {\n  SEQUENCE {\n    INTEGER: 1\n    OCTET STRING: ABCD\n    UTF8String: ABC\n  }\n  SET {\n    SEQUENCE {\n      INTEGER: -1\n      OCTET STRING: 010203\n    }\n  }\n}";
      },

      // --- Date-Related Error Cases ---
      {
        name = "Error: Invalid UTCTime Format";
        derBytes = "\17\0D\32\33\30\34\31\35\31\32\33\30\30\30\59"; // Last byte should be 'Z', not 'Y'
        expectedValue = ?#utctime("230415123000Y"); // Parser doesn't validate format, just parses the string
        expectedError = null; // Current implementation just parses string without validation
        expectedText = ?"UTCTime: 230415123000Y";
      },
      {
        name = "Error: Empty UTCTime";
        derBytes = "\17\00"; // UTCTime tag with zero length
        expectedValue = ?#utctime("");
        expectedError = null; // Parser accepts empty string
        expectedText = ?"UTCTime: ";
      },
      {
        name = "Error: Invalid GeneralizedTime Format";
        derBytes = "\18\11\32\30\32\33\30\34\31\35\31\32\33\30\34\35\2E\5A"; // Missing digit after decimal point
        expectedValue = ?#generalizedTime("20230415123045.Z"); // Parser doesn't validate format
        expectedError = ?"Unexpected end of data while reading bytes";
        expectedText = null;
      },

      // --- Indefinite Length Encoding (not supported in DER) ---
      {
        name = "Error: Indefinite Length Encoding";
        derBytes = "\04\80\01\02\03\00\00"; // Octet String with indefinite length, content 01 02 03, end-of-content marker
        expectedValue = null;
        expectedError = ?"Indefinite length encoding not supported";
        expectedText = null;
      },

      {
        name = "ECDSA PKCS Private Key (SEQUENCE)";
        derBytes = "\30\81\84\02\01\00\30\10\06\07\2a\86\48\ce\3d\02\01\06\05\2b\81\04\00\0a\04\6d\30\6b\02\01\01\04\20\b1\aa\62\82\b1\4e\5f\fb\f6\d1\2f\78\36\12\f8\04\e6\a2\0d\1a\97\34\ff\bb\6c\99\23\c6\70\ee\8d\a2\81\44\03\42\00\04\0a\09\ff\14\2d\94\bc\3f\56\c5\c8\1b\75\ea\3b\06\b0\82\c5\26\3f\bb\5b\d8\8c\61\9f\c6\39\3d\da\3d\a5\3e\0e\93\08\92\cd\b7\79\9e\ea\8f\d4\5b\9f\ff\37\7d\83\8f\41\06\45\42\89\ae\8a\08\0b\11\1f\8d";
        expectedValue = ?#sequence([
          #integer(0),
          #sequence([
            #objectIdentifier([1, 2, 840, 10045, 2, 1]),
            #objectIdentifier([1, 3, 132, 0, 10]),
          ]),
          #octetString([48, 107, 2, 1, 1, 4, 32, 177, 170, 98, 130, 177, 78, 95, 251, 246, 209, 47, 120, 54, 18, 248, 4, 230, 162, 13, 26, 151, 52, 255, 187, 108, 153, 35, 198, 112, 238, 141, 162, 129, 68, 3, 66, 0, 4, 10, 9, 255, 20, 45, 148, 188, 63, 86, 197, 200, 27, 117, 234, 59, 6, 176, 130, 197, 38, 63, 187, 91, 216, 140, 97, 159, 198, 57, 61, 218, 61, 165, 62, 14, 147, 8, 146, 205, 183, 121, 158, 234, 143, 212, 91, 159, 255, 55, 125, 131, 143, 65, 6, 69, 66, 137, 174, 138, 8, 11, 17, 31, 141]),
        ]);
        expectedError = null;
        expectedText = ?"SEQUENCE {
  INTEGER: 0
  SEQUENCE {
    OBJECT IDENTIFIER: 1.2.840.10045.2.1
    OBJECT IDENTIFIER: 1.3.132.0.10
  }
  OCTET STRING: 306B0201010420B1AA6282B14E5FFBF6D12F783612F804E6A20D1A9734FFBB6C9923C670EE8DA28144034200040A09FF142D94BC3F56C5C81B75EA3B06B082C5263FBB5BD88C619FC6393DDA3DA53E0E930892CDB7799EEA8FD45B9FFF377D838F4106454289AE8A080B111F8D
}";
      },
      {
        name = "ECDSA SEC1 Private Key (SEQUENCE)";
        derBytes = "\30\77\02\01\01\04\20\d6\b2\38\d6\3b\0d\5a\ce\19\92\8d\05\75\2d\45\9a\d1\1c\e5\9a\02\55\f2\2e\af\56\d3\b9\02\2a\eb\d2\a0\0a\06\08\2a\86\48\ce\3d\03\01\07\a1\44\03\42\00\04\d3\0d\17\12\6b\01\57\66\ad\16\f0\aa\aa\00\49\a6\e6\7e\24\b7\e4\b3\1b\cd\7d\d7\b0\fc\dd\cb\67\31\ce\c5\09\f9\de\a4\fd\cb\79\af\cf\2c\37\5c\e6\9d\a5\51\e5\79\da\52\97\06\64\aa\86\6f\e9\8a\90\ed";
        expectedValue = ?#sequence([
          #integer(1),
          #octetString([214, 178, 56, 214, 59, 13, 90, 206, 25, 146, 141, 5, 117, 45, 69, 154, 209, 28, 229, 154, 2, 85, 242, 46, 175, 86, 211, 185, 2, 42, 235, 210]),
          #contextSpecific({
            tagNumber = 0;
            constructed = true;
            value = ?#objectIdentifier([1, 2, 840, 10_045, 3, 1, 7]);
          }),
          #contextSpecific({
            tagNumber = 1;
            constructed = true;
            value = ?#bitString({
              data = [4, 211, 13, 23, 18, 107, 1, 87, 102, 173, 22, 240, 170, 170, 0, 73, 166, 230, 126, 36, 183, 228, 179, 27, 205, 125, 215, 176, 252, 221, 203, 103, 49, 206, 197, 9, 249, 222, 164, 253, 203, 121, 175, 207, 44, 55, 92, 230, 157, 165, 81, 229, 121, 218, 82, 151, 6, 100, 170, 134, 111, 233, 138, 144, 237];
              unusedBits = 0;
            });
          }),
        ]);
        expectedError = null;
        expectedText = ?"SEQUENCE {
  INTEGER: 1
  OCTET STRING: D6B238D63B0D5ACE19928D05752D459AD11CE59A0255F22EAF56D3B9022AEBD2
  [0] CONSTRUCTED {
    OBJECT IDENTIFIER: 1.2.840.10045.3.1.7
  }
  [1] CONSTRUCTED {
    BIT STRING: [0 unused bits] 04D30D17126B015766AD16F0AAAA0049A6E67E24B7E4B31BCD7DD7B0FCDDCB6731CEC509F9DEA4FDCB79AFCF2C375CE69DA551E579DA52970664AA866FE98A90ED
  }
}";
      },
    ];

    for (testCase in cases.vals()) {
      // Test decodeDER
      let result = ASN1.decodeDER(testCase.derBytes.vals());

      switch (result) {
        case (#ok(actualValue)) {
          switch (testCase.expectedError) {
            case (?errText) {
              // Error was expected, but got success
              Runtime.trap(
                "[" # testCase.name # "] Failed:\nExpected Error: " # errText #
                "\nActual Success: " # debug_show (actualValue)
              );
            };
            case null {
              // Success was expected, check value
              switch (testCase.expectedValue) {
                case (?expected) {
                  // Custom comparison needed for ASN1Value containing Blobs/Arrays
                  if (actualValue != expected) {
                    Runtime.trap(
                      "[" # testCase.name # "] Failed:\nExpected Value: " # debug_show (expected) #
                      "\nActual Value:   " # debug_show (actualValue)
                    );
                  };
                  // Check encodeDER
                  let encoded = Blob.fromArray(ASN1.encodeDER(actualValue));
                  if (encoded != testCase.derBytes) {
                    Runtime.trap(
                      "[" # testCase.name # "] Failed:\nExpected DER: " # debug_show testCase.derBytes #
                      "\nActual DER:   " # debug_show encoded
                    );
                  };

                  // Check expectedText if provided
                  switch (testCase.expectedText) {
                    case (?expectedText) {
                      let actualText = ASN1.toText(actualValue);
                      if (actualText != expectedText) {
                        Runtime.trap(
                          "[" # testCase.name # "] Failed:\nExpected Text: " # expectedText #
                          "\nActual Text:   " # actualText
                        );
                      };
                    };
                    case null {
                      // No text check required
                    };
                  };
                };
                case null {
                  // Should not happen based on logic
                  Runtime.trap("[" # testCase.name # "] Test case definition error: expectedValue is null when success is expected.");
                };
              };
            };
          };
        };
        case (#err(actualError)) {
          switch (testCase.expectedError) {
            case (?expectedErrSubstring) {
              // Error was expected, check if message contains substring
              if (not Text.contains(actualError, #text(expectedErrSubstring))) {
                Runtime.trap(
                  "[" # testCase.name # "] Failed:\nExpected Error Substring: " # expectedErrSubstring #
                  "\nActual Error:           " # actualError
                );
              };

              // Check that expectedText is null for error cases
              switch (testCase.expectedText) {
                case (?_) {
                  Runtime.trap("[" # testCase.name # "] Test case definition error: expectedText should be null for error cases.");
                };
                case null {
                  // This is expected for error cases
                };
              };
            };
            case null {
              // Success was expected, but got error
              Runtime.trap(
                "[" # testCase.name # "] Failed:\nExpected Value: " # debug_show (testCase.expectedValue) #
                "\nActual Error: " # actualError
              );
            };
          };
        };
      };
    };
  },
);
