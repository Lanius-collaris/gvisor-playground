package local.arachne

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import androidx.core.content.ContextCompat
import android.content.SharedPreferences
import android.net.VpnService
import android.os.Build
import com.google.android.material.textfield.TextInputLayout
import com.google.android.material.button.MaterialButton
import android.widget.EditText
import androidx.activity.result.contract.ActivityResultContracts
import com.google.android.material.materialswitch.MaterialSwitch
import android_interface.Android_interface as aegis
import androidx.core.widget.doOnTextChanged
import android.Manifest
import android.content.pm.PackageManager
import android.graphics.Rect
import android.view.MotionEvent
import android.view.inputmethod.InputMethodManager
import android.widget.TextView
import androidx.core.view.isVisible

class MainActivity : AppCompatActivity() {
    private var mPref: SharedPreferences? = null
    private var mInput: TextInputLayout? = null
    private var mEditText: EditText? = null
    private var mSwitch: MaterialSwitch? = null
    private var debugButton: MaterialButton? = null
    private val receiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            mSwitch?.isChecked = VPNStatus == Status.ON
            debugButton?.isVisible = VPNStatus == Status.ON
        }
    }
    private val vpnLauncher =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {
            if (it.resultCode == RESULT_OK) {
                Manager.startVPN(this, mEditText?.text.toString())
            }
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        //Model(findViewById(R.id.input), findViewById(R.id.btn_save), findViewById(R.id.vpn_switch))
        mPref = getPreferences(Context.MODE_PRIVATE)
        mInput = findViewById(R.id.input)
        mEditText = mInput?.editText
        mEditText?.setText(getConf())
        mEditText?.doOnTextChanged { text, _, _, _ ->
            val r = aegis.dryRun(text.toString())
            if (r.isNotEmpty())
                mInput?.error = r
            else
                mInput?.error = null
        }
        mSwitch = findViewById(R.id.vpn_switch)
        val intentFilter = IntentFilter().apply {
            addAction(VPNService.BROADCAST_TO_UI)
        }
        ContextCompat.registerReceiver(
            this,
            receiver,
            intentFilter,
            ContextCompat.RECEIVER_NOT_EXPORTED
        )
        val btn: MaterialButton = findViewById(R.id.btn_save)
        btn.setOnClickListener {
            if (mInput?.error == null) {
                saveConf(mInput?.editText?.text.toString())
            }
        }
        mSwitch?.setOnCheckedChangeListener { _, b ->
            if (b && mInput?.error == null && VPNStatus == Status.OFF) {
                start()
            } else if (!b && VPNStatus == Status.ON) {
                Manager.stopVPN(this)
            }
        }
        findViewById<TextView>(R.id.warning).isVisible=Manager.dontUseZeroCopy()
        debugButton=findViewById(R.id.btn_log)
        debugButton?.setOnClickListener { aegis.dontLog(false) }
    }

    private fun start() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU
            && ContextCompat.checkSelfPermission(
                this,
                Manifest.permission.POST_NOTIFICATIONS
            ) != PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1)
            mSwitch?.isChecked = false
            return
        }
        val p = VpnService.prepare(this)
        if (p == null)
            Manager.startVPN(this, mEditText?.text.toString())
        else
            vpnLauncher.launch(p)
    }

    private fun getConf(): String? {
        return mPref!!.getString("conf", Manager.DEFAULT_CONF)
    }

    private fun saveConf(c: String) {
        with(mPref!!.edit()) {
            putString("conf", c)
            apply()
        }
    }

    override fun onResume() {
        super.onResume()
        mSwitch?.isChecked = VPNStatus == Status.ON
    }

    override fun onDestroy() {
        super.onDestroy()
        unregisterReceiver(receiver)
    }

    override fun dispatchTouchEvent(ev: MotionEvent?): Boolean {
        if(ev?.action == MotionEvent.ACTION_DOWN){
            val v=currentFocus
            if(v is EditText){
                val outRect= Rect()
                v.getGlobalVisibleRect(outRect)
                if(!outRect.contains(ev.rawX.toInt(), ev.rawY.toInt())){
                    v.clearFocus()
                    val imm=getSystemService(Context.INPUT_METHOD_SERVICE) as InputMethodManager
                    imm.hideSoftInputFromWindow(v.windowToken,0)
                }
            }
        }
        return super.dispatchTouchEvent(ev)
    }
}