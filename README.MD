# DNS Server

## Build

### Windows

`gradlew.bat build`

### Linux

`./gradlew build`

## Start

`java -jar DNS_server-1.0-SNAPSHOT.jar`

## Protocol:

### Packet format:

    +---------------------+
    |        Header       |
    +---------------------+
    |       Question      | the question for the name server
    +---------------------+
    |        Answer       | RRs answering the question
    +---------------------+
    |      Authority      | RRs pointing toward an authority
    +---------------------+
    |      Additional     | RRs holding additional information
    +---------------------+

#### Header

                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      ID                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QDCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ANCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    NSCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ARCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

- **ID** - A 16 bit identifier assigned by the program that generates any kind of query. This identifier is copied the
  corresponding reply and can be used by the requester to match up replies to outstanding queries.

- **QR** - A one bit field that specifies whether this message is a query (0), or a response (1).

- **OPCODE** - A four bit field that specifies kind of query in this message. This value is set by the originator of a
  query and copied into the response. The values are:<br>
  **0**               a standard query (QUERY)<br>
  **1**               an inverse query (IQUERY)<br>
  **2**               a server status request (STATUS)<br>
  **3-15**            reserved for future use

- **AA** - Authoritative Answer - this bit is valid in responses, and specifies that the responding name server is an
  authority for the domain name in question section.
- **TC** - TrunCation - specifies that this message was truncated due to length greater than that permitted on the
  transmission channel.
- **RD** (Recursion Desired) - this bit may be set in a query and is copied into the response. If RD is set, it directs
  the name server to pursue the query recursively. Recursive query support is optional.

- **RA** (Recursion Available) - this be is set or cleared in a response, and denotes whether recursive query support is
  available in the name server.

- **Z**  - Reserved for future use. Must be zero in all queries and responses.

- **RCODE** (Response code) - this 4 bit field is set as part of responses. The values have the following
  interpretation:
  **0** No error condition<br>
  **1** Format error - The name server was unable to interpret the query.<br>
  **2** Server failure - The name server was unable to process this query due to a problem with the name server.<br>
  **3** Name Error - Meaningful only for responses from an authoritative name server, this code signifies that the
  domain name referenced in the query does not exist.<br>
  **4** Not Implemented - The name server does not support the requested kind of query.<br>
  **5** Refused - The name server refuses to perform the specified operation for policy reasons. For example, a name
  server may not wish to provide the information to the particular requester, or a name server may not wish to perform a
  particular operation (e.g., zone transfer) for particular data.<br>
  **6-15** Reserved for future use.
- **QDCOUNT** - an unsigned 16 bit integer specifying the number of entries in the question section.
- **ANCOUNT** - an unsigned 16 bit integer specifying the number of resource records in the answer section.
- **NSCOUNT** - an unsigned 16 bit integer specifying the number of name server resource records in the authority
  records section.
- **ARCOUNT** an unsigned 16 bit integer specifying the number of resource records in the additional records section.

#### Question

                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                     QNAME                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QTYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QCLASS                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

- **QNAME** - a domain name represented as a sequence of labels, where each label consists of a length octet followed by
  that number of octets. The domain name terminates with the zero length octet for the null label of the root. Note that
  this field may be an odd number of octets; no padding is used.

- **QTYPE** - a two octet code which specifies the type of the query. The values for this field include all codes valid
  for a TYPE field, together with some more general codes which can match more than one type of RR.

- **QCLASS** - a two octet code that specifies the class of the query. For example, the QCLASS field is IN for the
  Internet.

#### Answer

                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                                               /
    /                      NAME                     /
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     CLASS                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TTL                      |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                   RDLENGTH                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
    /                     RDATA                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

- **NAME** - a domain name to which this resource record pertains.

- **TYPE** - two octets containing one of the RR type codes. This field specifies the meaning of the data in the RDATA
  field.

- **CLASS** - two octets which specify the class of the data in the RDATA field.

- **TTL** a 32 bit unsigned integer that specifies the time interval (in seconds) that the resource record may be cached
  before it should be discarded.

- **RDLENGTH** - an unsigned 16 bit integer that specifies the length in octets of the RDATA field.

- **RDATA** - a variable length string of octets that describes the resource. The format of this information varies
  according to the TYPE and CLASS of the resource record.