package ru.fbear.dns.server

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import kotlin.system.exitProcess


fun main(args: Array<String>) {
    if (args.size != 1) {
        println("Usage java -jar dns_server.jar port")
        exitProcess(0)
    }
    if (args[0].toIntOrNull() == null) {
        println("Usage java -jar dns_server.jar port")
        exitProcess(0)
    }

    Server(args[0].toInt()).launch()
}

class Server(port: Int) {

    private val serverSocket = DatagramSocket(port)

    fun launch() {
        Thread(ConsoleReader()).start()

        while (true) {
            val receivingDataBuffer = ByteArray(1024)
            val inputPacket = DatagramPacket(receivingDataBuffer, receivingDataBuffer.size)
            serverSocket.receive(inputPacket)
            val packet = parsePacket(inputPacket)
            val answer =
                if (packet.query.qName == "fbear.ru" && packet.header.qr == QR.Query && packet.header.opcode == Opcode.Query)
                    when (packet.query.qType) {
                        Type.A -> Answer(
                            packet.query.qName,
                            packet.query.qType,
                            1,
                            0,
                            4,
                            A(InetAddress.getByName("10.0.0.100"))
                        )
                        Type.TXT -> Answer(
                            packet.query.qName,
                            packet.query.qType,
                            1,
                            0,
                            "fbear domain".toByteArray(Charsets.US_ASCII).size,
                            TXT("fbear domain")
                        )
                        Type.MX -> Answer(
                            packet.query.qName,
                            packet.query.qType,
                            1,
                            0,
                            "mail.fbear.ru".toByteArray(Charsets.US_ASCII).size + 2,
                            MX(30, "mail.fbear.ru")
                        )
                        Type.AAAA -> Answer(
                            packet.query.qName,
                            packet.query.qType,
                            1,
                            0,
                            128,
                            AAAA(InetAddress.getByName("2001:0db8:85a3:0000:0000:8a2e:0370:7334"))
                        )
                    }
                else continue
            packet.answer = answer
            sendPacket(packet, inputPacket.address, inputPacket.port)
        }

    }

    private fun sendPacket(packet: Packet, inetAddress: InetAddress, port: Int) {
//        val nameBytes = packet.rawDomain!!
        val nameBytes = byteArrayOf(0b11000000.toByte(), 0b00001100.toByte()) // 11000000 00001100
        val typeBytes = ByteArray(1) + packet.answer!!.type.code.toByte()
        val classBytes = ByteArray(1) + packet.answer!!.`class`.toByte()
        val ttlBytes = ByteArray(3) + byteArrayOf(100.toByte())
        val rDataBytes = when (packet.answer!!.type) {
            Type.A -> {
                val a = packet.answer!!.rdata as A
                a.inetAddress.address
            }
            Type.TXT -> {
                val txt = packet.answer!!.rdata as TXT
                val bytes = txt.string.toByteArray(Charsets.US_ASCII)
                byteArrayOf(bytes.size.toByte()) + bytes
            }
            Type.MX -> {
                val mx = packet.answer!!.rdata as MX
                val exchangeBytes = mutableListOf<Byte>()
                for (sub in mx.exchange.split('.')) {
                    exchangeBytes.add(sub.length.toByte())
                    exchangeBytes.addAll(sub.toByteArray(Charsets.US_ASCII).toList())
                }
                exchangeBytes.add(0.toByte())
                ByteArray(1) + mx.preference.toByte() + exchangeBytes
            }
            Type.AAAA -> {
                val aaaa = packet.answer!!.rdata as AAAA
                aaaa.inetAddress.address
            }
        }
        val rdLengthBytes = ByteArray(1) + rDataBytes.size.toByte()

        val header = ByteArray(2 - packet.header.id.toByteArray().size) + packet.header.id.toByteArray() +
                ((1 shl 7) + (packet.header.opcode.code shl 3) + ((if (packet.header.aa) 1 else 0) shl 2) + ((if (packet.header.tc) 1 else 0) shl 1) + (if (packet.header.rd) 1 else 0)).toByteArray() +
                ByteArray(1 - (if (packet.header.ra) 1 else 0 shl 7).toByteArray().size) + (if (packet.header.ra) 1 else 0 shl 7).toByteArray() +
                ByteArray(2 - packet.header.qdCount.toByteArray().size) + packet.header.qdCount.toByteArray() +
                byteArrayOf(0.toByte(), 1.toByte()) +
                ByteArray(2 - packet.header.nsCount.toByteArray().size) + packet.header.nsCount.toByteArray() +
                ByteArray(2 - packet.header.arCount.toByteArray().size) + packet.header.arCount.toByteArray()

        val buffer =
            header + packet.rawQuery + nameBytes + typeBytes + classBytes + ttlBytes + rdLengthBytes + rDataBytes

        val datagramPacket = DatagramPacket(buffer, buffer.size, inetAddress, port)
        serverSocket.send(datagramPacket)
    }

    private fun parsePacket(inputPacket: DatagramPacket): Packet {
        val buffer = inputPacket.data

//      ======================= Id Section ===========================

        val id = buffer.slice(0..1).toInt()

//      ===================== Flags section ==========================

        val qr = when (buffer[2].toInt() ushr 7) {
            0 -> QR.Query
            1 -> QR.Response
            else -> throw IllegalStateException("Wrong QR")
        }
        val opcode = when ((buffer[2].toInt() ushr 3) and 0b00001111) {
            0 -> Opcode.Query
            1 -> Opcode.IQuery
            2 -> Opcode.Status
            else -> throw IllegalStateException("Wrong opcode")
        }
        val aa = (buffer[2].toInt() ushr 2) and 1 == 1
        val tc = (buffer[2].toInt() ushr 1) and 1 == 1
        val rd = (buffer[2].toInt()) and 1 == 1
        val ra = (buffer[3].toInt() ushr 7) and 1 == 1
        val rCode = when ((buffer[3].toInt()) and 0b00001111) {
            0 -> RCode.Null
            1 -> RCode.FormatError
            2 -> RCode.ServerFailure
            3 -> RCode.NameError
            4 -> RCode.NotImplemented
            5 -> RCode.Refused
            else -> throw IllegalStateException("Wrong RCODE")
        }

//      ===================== Count Section ===========================

        val qdCount = buffer.slice(4..5).toInt()
        val anCount = buffer.slice(6..7).toInt()
        val nsCount = buffer.slice(8..9).toInt()
        val arCount = buffer.slice(10..11).toInt()

//      ===================== Query Section ===========================

        var byte = 12

        val sb = StringBuilder()

        while (true) {
            val num = buffer[byte].toInt()
            if (num == 0) {
                sb.deleteAt(sb.length - 1)
                break
            }
            val string = buffer.slice(byte + 1..byte + num).toByteArray().toString(Charsets.US_ASCII)
            sb.append(string)
            sb.append(".")
            byte += num + 1
        }

        byte++

        val qname = sb.toString()

        val qtype = when (buffer.slice(byte..byte + 1).toInt()) {
            1 -> Type.A
            15 -> Type.MX
            16 -> Type.TXT
            28 -> Type.AAAA
            else -> throw IllegalStateException("Wrong QTYPE")
        }

        val qclass = QClass.ALL

        val header = Header(id, qr, opcode, aa, tc, rd, ra, rCode, qdCount, anCount, nsCount, arCount)

        val query = Query(qname, qtype, qclass)

        return Packet(
            header,
            query,
            buffer.sliceArray(12 until inputPacket.length),
            null
        )
    }

}

class ConsoleReader : Runnable {

    override fun run() {
        while (true) {
            when (readLine()) {
                "quit" -> exitProcess(0)
                null -> exitProcess(0)
                else -> println("Unknown command")
            }
        }
    }
}

fun List<Byte>.toInt(): Int {
    var result = 0
    var shift = 0
    this.reversed().forEach {
        result += it.toUByte().toInt() shl shift
        shift += 8
    }
    return result
}

fun Int.toByteArray(): ByteArray {
    val bytes = mutableListOf<Byte>()

    var shift = 0

    var limit = this.countBits() / 8

    if (this.countBits() % 8 != 0) limit++

    for (i in 0 until limit) {
        bytes.add((this shr shift).toByte())
        shift += 8
    }

    return bytes.reversed().toByteArray()
}

fun Int.countBits(): Int {
    var n = this
    var count = 0
    while (n != 0) {
        count++
        n = n shr 1
    }
    return count
}
