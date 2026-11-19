package com.example.silentwifiwatcher

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat

class WifiWatcherService : Service() {

    private var lastSSID: String? = null
    private lateinit var connectivityManager: ConnectivityManager

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        startForeground(1, getNotification("Monitoring WiFi..."))

        connectivityManager = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

        val request = NetworkRequest.Builder()
            .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
            .build()

        connectivityManager.registerNetworkCallback(request, object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                super.onAvailable(network)
                checkCurrentSSID("Wi-Fi connected")
            }

            override fun onLost(network: Network) {
                super.onLost(network)
                sendNotification("Wi-Fi disconnected")
                lastSSID = null
            }
        })
    }

    private fun checkCurrentSSID(event: String) {
        val wifiManager = applicationContext.getSystemService(Context.WIFI_SERVICE) as android.net.wifi.WifiManager
        val wifiInfo = wifiManager.connectionInfo
        val currentSSID = wifiInfo.ssid?.replace("\"", "") ?: "Unknown"

        if (lastSSID != currentSSID) {
            sendNotification("$event: $currentSSID")
        }

        lastSSID = currentSSID
    }

    private fun getNotification(content: String): Notification {
        return NotificationCompat.Builder(this, "wifi_channel")
            .setContentTitle("SilentWifiWatcher")
            .setContentText(content)
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setOngoing(true)
            .build()
    }

    private fun sendNotification(content: String) {
        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        manager.notify(2, NotificationCompat.Builder(this, "wifi_channel")
            .setContentTitle("SilentWifiWatcher Alert")
            .setContentText(content)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .build())
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                "wifi_channel",
                "WiFi Watcher",
                NotificationManager.IMPORTANCE_DEFAULT
            )
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(channel)
        }
    }

    override fun onBind(intent: Intent?): IBinder? = null
}
