package com.secureconnect.app.vpn

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.SystemClock
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.net.InetSocketAddress
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/**
 * One user-triggered request to a named gateway over the selected physical
 * network. No background worker, no retries, no Xray restart, no speed loop.
 * Results DO NOT prove a working VPN or a whitelist pass.
 */
internal object ManualPayloadGatewayProbe {
    fun run(
        context: Context,
        gatewayHost: String,
        gatewayPort: String,
        cellular: Boolean,
        tls: Boolean,
        payload: ManualPayloadCodec.Encoding
    ): String {
        if (!payload.valid) return payload.error ?: "Недопустимый запрос."
        val host = gatewayHost.trim()
        if (!Regex("^[A-Za-z0-9][A-Za-z0-9.:-]{0,252}$").matches(host) ||
            host.contains("..") || host.contains("://") || host.contains('@'))
            return "Укажи адрес своего или разрешённого шлюза без https://."
        val port = gatewayPort.trim().toIntOrNull()
        if (port == null || port !in 1..65535) return "Неверный порт: от 1 до 65535."
        val manager = context.getSystemService(ConnectivityManager::class.java)
            ?: return "Служба сети Android недоступна."
        val network = manager.allNetworks.firstOrNull { candidate ->
            val caps = manager.getNetworkCapabilities(candidate) ?: return@firstOrNull false
            caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) &&
                caps.hasTransport(if (cellular) NetworkCapabilities.TRANSPORT_CELLULAR
                    else NetworkCapabilities.TRANSPORT_WIFI)
        } ?: return if (cellular) "Мобильная сеть недоступна." else "Wi-Fi недоступен."
        val start = SystemClock.elapsedRealtime()
        val type = if (cellular) "SIM" else "Wi-Fi"
        var stage = "DNS"
        return try {
            val addr = network.getAllByName(host).firstOrNull()
                ?: return "DNS выбранной сети не разрешил адрес шлюза."
            stage = "TCP"
            network.socketFactory.createSocket().use { raw ->
                raw.soTimeout = 4_000
                raw.connect(InetSocketAddress(addr, port), 4_000)
                if (tls) {
                    stage = "TLS"
                    val ssl = (SSLSocketFactory.getDefault() as SSLSocketFactory)
                        .createSocket(raw, host, port, false) as SSLSocket
                    ssl.use { socket ->
                        socket.soTimeout = 4_000
                        val params = socket.sslParameters
                        params.endpointIdentificationAlgorithm = "HTTPS"
                        socket.sslParameters = params
                        socket.startHandshake()
                        stage = "HTTP"
                        exchange(socket.getInputStream(), socket.getOutputStream(), payload,
                            type, start)
                    }
                } else {
                    stage = "HTTP"
                    exchange(raw.getInputStream(), raw.getOutputStream(), payload,
                        type, start)
                }
            }
        } catch (e: Exception) {
            ManualPayloadCodec.failureSummary(type, stage, e.javaClass.simpleName, tls, port)
        }
    }

    private fun exchange(
        inputStream: java.io.InputStream,
        outputStream: java.io.OutputStream,
        payload: ManualPayloadCodec.Encoding,
        type: String,
        startMs: Long
    ): String {
        BufferedOutputStream(outputStream).apply {
            write(payload.bytes)
            flush()
        }
        val input = BufferedInputStream(inputStream)
        val result = ByteArray(256)
        var length = 0
        while (length < result.size) {
            val b = input.read()
            if (b == -1 || b == 10) break
            if (b == 13) continue
            result[length++] = b.toByte()
        }
        val first = if (length == 0) null else
            String(result, 0, length, Charsets.ISO_8859_1)
                .filter { it.code in 32..126 }.take(120)
        val duration = SystemClock.elapsedRealtime() - startMs
        return "$type · HTTP-ответ за ${duration}мс · " +
            ManualPayloadCodec.responseCategory(first)
    }
}
