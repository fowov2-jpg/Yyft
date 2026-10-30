package com.secureconnect.app.vpn

import android.app.ActivityManager
import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.os.PowerManager
import android.os.SystemClock
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/**
 * Single attempt for a user-authorized proxy gateway.
 * Requires HTTP CONNECT 200 AND a certificate-verified HTTPS reply from
 * example.com THROUGH that exact socket. A bare HTTP 200 is never success.
 * Does not change Xray, VPN state, proxy pool or service lifecycle.
 */
internal object AutoPayloadGatewayProbe {
    data class Proof(val success: Boolean, val stage: String, val detail: String) {
        override fun toString(): String = "$stage: $detail"
    }

    fun stopReason(context: Context): String? {
        val power = context.getSystemService(PowerManager::class.java)
        if (power?.isPowerSaveMode == true) return "режим энергосбережения"
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q &&
            (power?.currentThermalStatus ?: PowerManager.THERMAL_STATUS_NONE) >=
                PowerManager.THERMAL_STATUS_LIGHT) return "нагрев устройства"
        val manager = context.getSystemService(ActivityManager::class.java)
        val info = ActivityManager.MemoryInfo()
        manager?.getMemoryInfo(info)
        if (info.lowMemory) return "системная нехватка оперативной памяти"
        return null
    }

    fun attempt(
        context: Context,
        gatewayHost: String,
        gatewayPort: Int,
        cellular: Boolean,
        tlsToGateway: Boolean,
        candidate: AutoPayloadGenerator.Candidate
    ): Proof {
        val host = gatewayHost.trim()
        if (!AutoPayloadGenerator.isValidHost(host) ||
            gatewayPort !in 1..65535) return Proof(false, "INPUT", "Неверный шлюз или порт")
        if (host.equals("vk.com", true) || host.equals("www.vk.com", true))
            return Proof(false, "INPUT", "vk.com — сайт, а не указанный вами прокси-шлюз")
        val cm = context.getSystemService(ConnectivityManager::class.java)
            ?: return Proof(false, "NETWORK", "Сеть Android недоступна")
        val network = cm.allNetworks.firstOrNull { net ->
            val caps = cm.getNetworkCapabilities(net) ?: return@firstOrNull false
            caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) &&
                caps.hasTransport(if (cellular) NetworkCapabilities.TRANSPORT_CELLULAR
                    else NetworkCapabilities.TRANSPORT_WIFI)
        } ?: return Proof(false, "NETWORK", "Выбранная физическая сеть недоступна")

        val sslFactory = SSLSocketFactory.getDefault() as SSLSocketFactory
        var stage = "DNS"
        val start = SystemClock.elapsedRealtime()
        return try {
            val addr = network.getAllByName(host).firstOrNull()
                ?: return Proof(false, stage, "DNS не разрешил имя")
            stage = "TCP"
            network.socketFactory.createSocket().use { raw ->
                raw.soTimeout = 3_000
                raw.connect(InetSocketAddress(addr, gatewayPort), 3_000)
                fun checkOverGateway(gatewaySocket: Socket): Proof {
                    gatewaySocket.soTimeout = 3_000
                    stage = "CONNECT"
                    gatewaySocket.getOutputStream().apply {
                        write(candidate.encoded.bytes)
                        flush()
                    }
                    val input = gatewaySocket.getInputStream()
                    val first = readLine(input)
                    if (!AutoPayloadGenerator.isConnectEstablished(first)) {
                        val code = first?.take(52) ?: "нет ответа"
                        return Proof(false, "CONNECT", "шлюз отверг запрос: $code")
                    }
                    // Read exactly through the end of proxy's HTTP headers,
                    // without buffered over-read that would consume tunneled TLS.
                    var headers = 0
                    while (true) {
                        if (++headers > 32) return Proof(false, "CONNECT", "Слишком много заголовков")
                        val line = readLine(input) ?: return Proof(false, "CONNECT", "Заголовки оборваны")
                        if (line.isEmpty()) break
                    }
                    stage = "TUNNELED_TLS"
                    val nested = sslFactory.createSocket(
                        gatewaySocket, AutoPayloadGenerator.TARGET_HOST,
                        AutoPayloadGenerator.TARGET_PORT, false
                    ) as SSLSocket
                    nested.use { tunnel ->
                        tunnel.soTimeout = 3_000
                        tunnel.sslParameters = tunnel.sslParameters.apply {
                            endpointIdentificationAlgorithm = "HTTPS"
                        }
                        tunnel.startHandshake() // validates certificate for example.com
                        stage = "TUNNELED_HTTP"
                        val http = "GET / HTTP/1.1\r\n" +
                            "Host: ${AutoPayloadGenerator.TARGET_HOST}\r\n" +
                            "Connection: close\r\n\r\n"
                        tunnel.getOutputStream().apply {
                            write(http.toByteArray(Charsets.US_ASCII))
                            flush()
                        }
                        val response = readLine(tunnel.getInputStream())
                        return if (AutoPayloadGenerator.isHttpPayloadDelivered(response))
                            Proof(true, "VERIFIED_CONNECT",
                                "через HTTP CONNECT получен HTTPS-ответ example.com; это не Xray и не IP Германии")
                        else Proof(false, "TUNNELED_HTTP",
                            "не подтверждён HTTPS-ответ: ${response?.take(45) ?: "нет ответа"}")
                    }
                }
                if (tlsToGateway) {
                    stage = "GATEWAY_TLS"
                    val gateway = sslFactory.createSocket(raw, host, gatewayPort, false) as SSLSocket
                    gateway.use { socket ->
                        socket.soTimeout = 3_000
                        socket.sslParameters = socket.sslParameters.apply {
                            endpointIdentificationAlgorithm = "HTTPS"
                        }
                        socket.startHandshake()
                        checkOverGateway(socket)
                    }
                } else {
                    checkOverGateway(raw)
                }
            }
        } catch (e: Exception) {
            Proof(false, stage,
                "${e.javaClass.simpleName}, ${SystemClock.elapsedRealtime() - start}мс")
        }
    }

    private fun readLine(stream: InputStream): String? {
        val bytes = ByteArray(512)
        var index = 0
        while (index < bytes.size) {
            val b = stream.read()
            if (b == -1) return if (index == 0) null else String(bytes, 0, index, Charsets.US_ASCII)
            if (b == 10) return String(bytes, 0, index, Charsets.US_ASCII)
            if (b != 13) bytes[index++] = b.toByte()
        }
        return null
    }
}
