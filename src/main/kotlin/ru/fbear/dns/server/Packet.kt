package ru.fbear.dns.server

import java.net.InetAddress

enum class QR(val code: Int) {
    Query(0),
    Response(1)
}

enum class Opcode(val code: Int) {
    Query(0),
    IQuery(1),
    Status(2)
}

enum class RCode(val code: Int) {
    Null(0),
    FormatError(1),
    ServerFailure(2),
    NameError(3),
    NotImplemented(4),
    Refused(5)
}

enum class Type(val code: Int) {
    A(1),
    MX(15),
    TXT(16),
    AAAA(28)
}

enum class QClass(val code: Int) {
    ALL(255)
}

data class Header(
    val id: Int,
    val qr: QR,
    val opcode: Opcode,
    val aa: Boolean,
    val tc: Boolean,
    val rd: Boolean,
    val ra: Boolean,
    val rCode: RCode,
    val qdCount: Int,
    val anCount: Int,
    val nsCount: Int,
    val arCount: Int
)

data class Query(
    val qName: String,
    val qType: Type,
    val qClass: QClass
)

open class RData

class A(
    val inetAddress: InetAddress
) : RData()

class MX(
    val preference: Int,
    val exchange: String
) : RData()

class TXT(
    val string: String
) : RData()

class AAAA(
    val inetAddress: InetAddress
) : RData()

class Answer(
    val name: String,
    val type: Type,
    val `class`: Int = 1,
    val ttl: Int = 0,
    val rdLength: Int,
    val rdata: RData
)

class Packet(
    val header: Header,
    val query: Query,
    val rawQuery: ByteArray,
    var answer: Answer?
)
