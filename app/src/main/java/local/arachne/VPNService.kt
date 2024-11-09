package local.arachne

import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.app.NotificationManager
import android.app.NotificationChannel
import android.app.PendingIntent
import android.content.pm.ServiceInfo
import android.os.ParcelFileDescriptor
import android_interface.Android_interface as aegis
import org.json.JSONTokener
import org.json.JSONObject
import java.lang.Exception
import android.util.Log
import androidx.core.app.NotificationCompat
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.NetworkInterface

enum class Status {
    OFF,
    ON
}

var VPNStatus = Status.OFF

class VPNService : VpnService() {
    companion object {
        private const val NOTIFICATION_CHANNEL_ID = "vpn_test"
        const val BROADCAST_TO_UI = "656084"
        const val START_ACTION = "START"
        const val STOP_ACTION = "STOP"
        const val SERVICE_ID = 1
        val testAddr6: InetAddress = InetAddress.getByName("2001:500:8d::53")
        val testAddr4: InetAddress = InetAddress.getByName("199.43.133.53")
    }

    override fun onCreate() {
        super.onCreate()
        if (Build.VERSION.SDK_INT > Build.VERSION_CODES.O) {
            val mChannel = NotificationChannel(
                NOTIFICATION_CHANNEL_ID,
                applicationContext.packageName,
                NotificationManager.IMPORTANCE_LOW
            )
            mChannel.enableVibration(false)
            mChannel.enableLights(false)
            val manager = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
            manager.createNotificationChannel(mChannel)
        }
    }

    var tunPFd: ParcelFileDescriptor? = null

    //TODO
    private fun start(conf: String) {
        val j = JSONTokener(conf).nextValue() as JSONObject
        var mtu = j.getInt("mtu")
        if (mtu == 0) {//auto
            //let's cheat
            val t=Thread{
                mtu=pickMTU()
            }
            t.start()
            t.join()
            j.put("mtu", mtu)
        }

        val mBuilder = Builder()
        mBuilder.addAddress("10.0.2.100", 24)
            .addRoute("0.0.0.0", 0)
            .addAddress("fd00::100", 64)
            .addRoute("::", 0)
            .addDnsServer("10.0.2.3")
            .setMtu(mtu)
        mBuilder.addDisallowedApplication(applicationContext.packageName)
        tunPFd = mBuilder.establish() ?: throw IllegalStateException("fd == null")
        val result = aegis.start(tunPFd?.fd!!, j.toString()).toLong()
        if (result == aegis.StatusStop)
            throw IllegalStateException("fail at go")
    }

    //TODO
    private fun stop() {
        aegis.stop()
        tunPFd?.close()
        updateStatus(Status.OFF)
        stopSelf()
    }

    private fun updateStatus(s: Status) {
        VPNStatus = s
        val mIntent = Intent(BROADCAST_TO_UI)
        sendBroadcast(mIntent)
    }

    private fun startForegroundCompat() {
        val notification = NotificationCompat.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setSmallIcon(R.drawable.baseline_air_24).setSilent(true)
            .setContentTitle(this.getString(R.string.app_name))
            .setContentText(this.getString(R.string.notification_content))
            .setContentIntent(
                PendingIntent.getActivity(
                    this,
                    0,
                    Intent(this, MainActivity::class.java),
                    PendingIntent.FLAG_IMMUTABLE
                )
            )
            .addAction(
                0, "STOP",
                PendingIntent.getService(
                    this,
                    0,
                    Intent(this, VPNService::class.java).setAction(STOP_ACTION),
                    PendingIntent.FLAG_IMMUTABLE
                )
            )
            .build()
        if (Build.VERSION.SDK_INT > Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
            startForeground(SERVICE_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
        else
            startForeground(SERVICE_ID, notification)
    }

    fun pickMTU():Int {
        val s = DatagramSocket()
        var mtu1: Int
        var mtu2: Int
        s.use {
            try {
                s.connect(testAddr6, 1)
                mtu1 = NetworkInterface.getByInetAddress(s.localAddress).mtu
                s.disconnect()
            } catch (e: Exception) {
                mtu1 = 65536
            }
            try {
                s.connect(testAddr4, 1)
                mtu2 = NetworkInterface.getByInetAddress(s.localAddress).mtu
                s.disconnect()
            } catch (e: Exception) {
                mtu2 = 65536
            }
        }
        if (mtu1 != 65536 || mtu2 != 65536)
            return minOf(mtu1, mtu2)
        return 1500
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        super.onStartCommand(intent, flags, startId)
        when (intent?.action) {
            START_ACTION -> {
                val conf = intent.getStringExtra("conf")!!
                try {
                    start(conf)
                    startForegroundCompat()
                    updateStatus(Status.ON)
                } catch (e: Exception) {
                    updateStatus(Status.OFF)
                    Log.e("VPNService", "Fail", e)
                }
                return START_STICKY
            }

            STOP_ACTION -> {
                stop()
                return START_NOT_STICKY
            }
        }
        return START_NOT_STICKY
    }

    override fun onRevoke() {
        stop()
    }
}