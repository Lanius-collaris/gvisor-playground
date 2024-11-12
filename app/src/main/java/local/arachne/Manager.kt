package local.arachne

import android.content.Context
import android.content.Intent
import androidx.core.content.ContextCompat
import android.system.Os
import java.lang.Exception

object Manager {
    const val DEFAULT_CONF="""{
  "mtu":1500,
  "strategy":"tlsfrag",
  "tlsFrag":{
    "size":1
  },
  "overwrite":{
    "payload":"UE9TVCAvIEhUVFAvMS4xDQpIb3N0OiBhDQpDb250ZW50LUxlbmd0aDogOTk5OTk5DQoNCg==",
    "maxTTL":20
  },
  "DoHURL":"https://[2620:fe::9]/dns-query",
  "DoHIP":"2620:fe::9"
}"""
    val CONF_PRESET= arrayListOf("",
        """{
  "mtu":0,
  "strategy":"tlsfrag",
  "tlsFrag":{
    "size":1
  },
  "overwrite":{
    "payload":"UE9TVCAvIEhUVFAvMS4xDQpIb3N0OiBhDQpDb250ZW50LUxlbmd0aDogOTk5OTk5DQoNCg==",
    "maxTTL":20
  },
  "DoHURL":"https://9.9.9.12/dns-query",
  "DoHIP":"9.9.9.12"
}""",
        """{
  "mtu":0,
  "strategy":"overwrite",
  "tlsFrag":{
    "size":1
  },
  "overwrite":{
    "payload":"UE9TVCAvIEhUVFAvMS4xDQpIb3N0OiBhDQpDb250ZW50LUxlbmd0aDogOTk5OTk5DQoNCg==",
    "maxTTL":20
  },
  "DoHURL":"https://9.9.9.12/dns-query",
  "DoHIP":"9.9.9.12"
}""")
    fun startVPN(context: Context, conf:String){
        val mIntent=Intent(context, VPNService::class.java)
        mIntent.action = VPNService.START_ACTION
        mIntent.putExtra("conf",conf)
        ContextCompat.startForegroundService(context, mIntent)
    }
    fun stopVPN(context: Context){
        val mIntent=Intent(context, VPNService::class.java)
        mIntent.action = VPNService.STOP_ACTION
        ContextCompat.startForegroundService(context, mIntent)
    }
    fun dontUseZeroCopy():Boolean{
        try{
            val rel = Os.uname().release
            val list = rel.split(".", limit = 3)
            val part1=list[0].toInt()
            if (part1 < 4)
                return true
            if (part1 == 4 && list[1].toInt() < 14)
                return true
            return false
        }catch (e:Exception){
            return true
        }
    }
}