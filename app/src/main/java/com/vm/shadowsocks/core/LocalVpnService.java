package com.vm.shadowsocks.core;

import android.app.PendingIntent;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.SharedPreferences.Editor;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.net.VpnService;
import android.os.Build;
import android.os.Handler;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import com.vm.shadowsocks.R;
import com.vm.shadowsocks.core.ProxyConfig.IPAddress;
import com.vm.shadowsocks.dns.DnsPacket;
import com.vm.shadowsocks.tcpip.CommonMethods;
import com.vm.shadowsocks.tcpip.IPHeader;
import com.vm.shadowsocks.tcpip.TCPHeader;
import com.vm.shadowsocks.tcpip.UDPHeader;
import com.vm.shadowsocks.ui.MainActivity;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.zip.GZIPInputStream;

/**
 * 本地vpn服务
 */
public class LocalVpnService extends VpnService implements Runnable {

    public static LocalVpnService Instance;
    public static String ProxyUrl;
    public static boolean IsRunning = false;

    private static int ID;
    private static int LOCAL_IP;
    private static ConcurrentHashMap<onStatusChangedListener, Object> m_OnStatusChangedListeners = new ConcurrentHashMap<onStatusChangedListener, Object>();

    private Thread m_VPNThread;
    private ParcelFileDescriptor m_VPNInterface;
    private TcpProxyServer m_TcpProxyServer;
    private DnsProxy m_DnsProxy;
    private FileOutputStream m_VPNOutputStream;

    private byte[] m_Packet;//接收数据缓存
    private IPHeader m_IPHeader;
    private TCPHeader m_TCPHeader;
    private UDPHeader m_UDPHeader;
    private ByteBuffer m_DNSBuffer;
    private Handler m_Handler;
    private long m_SentBytes;
    private long m_ReceivedBytes;

    public LocalVpnService() {
        ID++;
        m_Handler = new Handler();
        m_Packet = new byte[20000];
        m_IPHeader = new IPHeader(m_Packet, 0);
        m_TCPHeader = new TCPHeader(m_Packet, 20);
        m_UDPHeader = new UDPHeader(m_Packet, 20);
        m_DNSBuffer = ((ByteBuffer) ByteBuffer.wrap(m_Packet).position(28)).slice();
        Instance = this;

        System.out.printf("New VPNService(%d)\n", ID);
    }

    @Override
    public void onCreate() {
        System.out.printf("VPNService(%s) created.\n", ID);
        // Start a new session by creating a new thread.
        //开个线程执行自己，具体抓包逻辑见：run()
        m_VPNThread = new Thread(this, "VPNServiceThread");
        m_VPNThread.start();
        super.onCreate();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        IsRunning = true;
        return super.onStartCommand(intent, flags, startId);
    }

    public interface onStatusChangedListener {
        public void onStatusChanged(String status, Boolean isRunning);

        public void onLogReceived(String logString);
    }

    public static void addOnStatusChangedListener(onStatusChangedListener listener) {
        if (!m_OnStatusChangedListeners.containsKey(listener)) {
            m_OnStatusChangedListeners.put(listener, 1);
        }
    }

    public static void removeOnStatusChangedListener(onStatusChangedListener listener) {
        if (m_OnStatusChangedListeners.containsKey(listener)) {
            m_OnStatusChangedListeners.remove(listener);
        }
    }

    private void onStatusChanged(final String status, final boolean isRunning) {
        m_Handler.post(new Runnable() {
            @Override
            public void run() {
                for (Map.Entry<onStatusChangedListener, Object> entry : m_OnStatusChangedListeners.entrySet()) {
                    entry.getKey().onStatusChanged(status, isRunning);
                }
            }
        });
    }

    public void writeLog(final String format, Object... args) {
        final String logString = String.format(format, args);
        m_Handler.post(new Runnable() {
            @Override
            public void run() {
                for (Map.Entry<onStatusChangedListener, Object> entry : m_OnStatusChangedListeners.entrySet()) {
                    entry.getKey().onLogReceived(logString);
                }
            }
        });
    }

    public void sendUDPPacket(IPHeader ipHeader, UDPHeader udpHeader) {
        try {
            CommonMethods.ComputeUDPChecksum(ipHeader, udpHeader);
            this.m_VPNOutputStream.write(ipHeader.m_Data, ipHeader.m_Offset, ipHeader.getTotalLength());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    String getAppInstallID() {
        SharedPreferences preferences = getSharedPreferences("SmartProxy", MODE_PRIVATE);
        String appInstallID = preferences.getString("AppInstallID", null);
        if (appInstallID == null || appInstallID.isEmpty()) {
            appInstallID = UUID.randomUUID().toString();
            Editor editor = preferences.edit();
            editor.putString("AppInstallID", appInstallID);
            editor.apply();
        }
        return appInstallID;
    }

    String getVersionName() {
        try {
            PackageManager packageManager = getPackageManager();
            // getPackageName()是你当前类的包名，0代表是获取版本信息
            PackageInfo packInfo = packageManager.getPackageInfo(getPackageName(), 0);
            String version = packInfo.versionName;
            return version;
        } catch (Exception e) {
            return "0.0";
        }
    }

    @Override
    public synchronized void run() {
        try {
            System.out.printf("VPNService(%s) work thread is runing...\n", ID);

            ProxyConfig.AppInstallID = getAppInstallID();//获取安装ID
            ProxyConfig.AppVersion = getVersionName();//获取版本号
            System.out.printf("AppInstallID: %s\n", ProxyConfig.AppInstallID);
            writeLog("Android version: %s", Build.VERSION.RELEASE);
            writeLog("App version: %s", ProxyConfig.AppVersion);


            ChinaIpMaskManager.loadFromFile(getResources().openRawResource(R.raw.ipmask));//加载中国的IP段，用于IP分流。
            waitUntilPreapred();//检查是否准备完毕。

            writeLog("Load config from file ...");
            try {
                //初始化一些代理配置
                ProxyConfig.Instance.loadFromFile(getResources().openRawResource(R.raw.config));
                writeLog("Load done");
            } catch (Exception e) {
                String errString = e.getMessage();
                if (errString == null || errString.isEmpty()) {
                    errString = e.toString();
                }
                writeLog("Load failed with error: %s", errString);
            }

            //启动tcp代理服务
            m_TcpProxyServer = new TcpProxyServer(0);
            m_TcpProxyServer.start();
            writeLog("LocalTcpServer started.");

            //启动dns代理服务
            m_DnsProxy = new DnsProxy();
            m_DnsProxy.start();
            writeLog("LocalDnsProxy started.");

            while (true) {
                //当前线程一直监听服务是否运行
                if (IsRunning) {
                    //加载配置文件
                    writeLog("set shadowsocks/(http proxy)");
                    try {
                        ProxyConfig.Instance.m_ProxyList.clear();
                        //设置代理url
                        ProxyConfig.Instance.addProxyToList(ProxyUrl);
                        writeLog("Proxy is: %s", ProxyConfig.Instance.getDefaultProxy());
                    } catch (Exception e) {
                        String errString = e.getMessage();
                        if (errString == null || errString.isEmpty()) {
                            errString = e.toString();
                        }
                        IsRunning = false;
                        onStatusChanged(errString, false);
                        continue;
                    }
                    String welcomeInfoString = ProxyConfig.Instance.getWelcomeInfo();
                    if (welcomeInfoString != null && !welcomeInfoString.isEmpty()) {
                        writeLog("%s", ProxyConfig.Instance.getWelcomeInfo());
                    }
                    writeLog("Global mode is " + (ProxyConfig.Instance.globalMode ? "on" : "off"));

                    //直到这里才是真正去执行抓包
                    runVPN();
                } else {
                    Thread.sleep(100);
                }
            }
        } catch (InterruptedException e) {
            System.out.println(e);
        } catch (Exception e) {
            e.printStackTrace();
            writeLog("Fatal error: %s", e.toString());
        } finally {
            writeLog("App terminated.");
            dispose();
        }
    }

    /**
     * 关键函数：执行抓包
     */
    private void runVPN() throws Exception {
        //初始化一些连接配置
        this.m_VPNInterface = establishVPN();
        this.m_VPNOutputStream = new FileOutputStream(m_VPNInterface.getFileDescriptor());
        FileInputStream in = new FileInputStream(m_VPNInterface.getFileDescriptor());
        int size = 0;
        while (size != -1 && IsRunning) {
            //不断去读数据
            while ((size = in.read(m_Packet)) > 0 && IsRunning) {
                if (m_DnsProxy.Stopped || m_TcpProxyServer.Stopped) {
                    in.close();
                    throw new Exception("LocalServer stopped.");
                }
                //todo 这里是数据相关的关键方法：数据的请求与接收
                onIPPacketReceived(m_IPHeader, size);
            }
            Thread.sleep(20);
        }
        in.close();
        disconnectVPN();
    }

    /**
     * 解析ip数据包
     */
    void onIPPacketReceived(IPHeader ipHeader, int size) throws IOException {
        switch (ipHeader.getProtocol()) {
            //发现ip包里有传输层协议头，解析一下
            case IPHeader.TCP:
                TCPHeader tcpHeader = m_TCPHeader;
                tcpHeader.m_Offset = ipHeader.getHeaderLength();
                if (ipHeader.getSourceIP() == LOCAL_IP) {
                    // TODO: 收到的数据 http response begin
                    if (tcpHeader.getSourcePort() == m_TcpProxyServer.Port) {
                        // 收到本地TCP服务器数据
                        NatSession session = NatSessionManager.getSession(tcpHeader.getDestinationPort());
                        if (session != null) {
                            // TODO: 2018/6/8 尝试修改思路：尝试去掉ip 和tcp header，解析http协议
                            ipHeader.setSourceIP(ipHeader.getDestinationIP());
                            tcpHeader.setSourcePort(session.RemotePort);
                            ipHeader.setDestinationIP(LOCAL_IP);

                            CommonMethods.ComputeTCPChecksum(ipHeader, tcpHeader);
                            m_VPNOutputStream.write(ipHeader.m_Data, ipHeader.m_Offset, size);
                            m_ReceivedBytes += size;

                            // TODO:本地添加的获取数据，并打印log的测试方法  begin
                            int dataOffset = tcpHeader.m_Offset + tcpHeader.getHeaderLength();
                            int tcpDataSize = ipHeader.getDataLength() - tcpHeader.getHeaderLength();
                            switch (tcpHeader.m_Data[dataOffset]) {
                                case 'H'://HEAD
//                                    Log.e(">>>>>data", "响应的数据(http层)(byte版) begin:\n");
//                                    StringBuilder sb = new StringBuilder();
//                                    for(int i = dataOffset;i<tcpDataSize;i++){
//                                        sb.append(tcpHeader.m_Data[i]);
//                                    }
//                                    Log.e(">>>>>data",sb.toString()+"\n响应的数据(http层)(byte版) end");

                                    String httpResponse = new String(tcpHeader.m_Data, dataOffset, tcpDataSize);
                                    int index = getIndexAfterEmptyLine(httpResponse);

                                    //目前index + 5貌似只支持gzip
                                    byte[] bytes = Arrays.copyOfRange(tcpHeader.m_Data, dataOffset + index + 5, size);
                                    bytes = uncompress(bytes);
                                    String httpBody = new String(bytes, "UTF-8");
                                    httpResponse = httpResponse.substring(0, index) + httpBody;
                                    Log.e(">>>>>data", "\n响应的数据："+httpResponse);

//                                    String s1=new String(httpResponse.getBytes("ISO-8859-1"), "utf-8");
//                                    Log.e(">>>>>data", "\n响应的数据(http层)(ISO-8859-1):\n" + s1);
//                                    s1=new String(httpResponse.getBytes("gbk"), "utf-8");
//                                    Log.e(">>>>>data", "\n响应的数据(http层)(gbk):\n" + s1);
                            }
                            // TODO: 2018/6/8 本地添加的获取数据，并打印log的测试方法  end
                        } else {
                            System.out.printf("NoSession: %s %s\n", ipHeader.toString(), tcpHeader.toString());
                        }
                    } else {
                        // TODO: 2018/6/8 发请求
                        // 添加端口映射
                        int portKey = tcpHeader.getSourcePort();
                        NatSession session = NatSessionManager.getSession(portKey);
                        if (session == null || session.RemoteIP != ipHeader.getDestinationIP() || session.RemotePort != tcpHeader.getDestinationPort()) {
                            session = NatSessionManager.createSession(portKey, ipHeader.getDestinationIP(), tcpHeader.getDestinationPort());
                        }

                        session.LastNanoTime = System.nanoTime();
                        session.PacketSent++;//注意顺序

                        int tcpDataSize = ipHeader.getDataLength() - tcpHeader.getHeaderLength();
                        if (session.PacketSent == 2 && tcpDataSize == 0) {
                            return;//丢弃tcp握手的第二个ACK报文。因为客户端发数据的时候也会带上ACK，这样可以在服务器Accept之前分析出HOST信息。
                        }

                        // todo test begin：找到http数据的位置，打印一下
                        int dataOffset = tcpHeader.m_Offset + tcpHeader.getHeaderLength();

                        switch (tcpHeader.m_Data[dataOffset]) {
                            case 'G'://GET
                            case 'H'://HEAD
                            case 'P'://POST,PUT
                            case 'D'://DELETE
                            case 'O'://OPTIONS
                            case 'T'://TRACE
                            case 'C'://CONNECT
                                //从dataOffset到tcp数据的结尾，就是http的数据
                                String httpRequest = new String(tcpHeader.m_Data, dataOffset, tcpDataSize);
                                Log.e(">>>>>data", "请求的数据(http层):\n" + httpRequest);
                                break;
                            case 0x16://SSL
                                break;
                        }
                        // todo end

                        //分析数据，找到host
                        if (session.BytesSent == 0 && tcpDataSize > 10) {
//                            int dataOffset = tcpHeader.m_Offset + tcpHeader.getHeaderLength();
                            // TODO:  这里拿到app请求的host
                            String host = HttpHostHeaderParser.parseHost(tcpHeader.m_Data, dataOffset, tcpDataSize);
                            if (host != null) {
                                session.RemoteHost = host;
                            } else {
                                System.out.printf("No host name found: %s", session.RemoteHost);
                            }
                        }

                        // 转发给本地TCP服务器
                        ipHeader.setSourceIP(ipHeader.getDestinationIP());
                        ipHeader.setDestinationIP(LOCAL_IP);
                        tcpHeader.setDestinationPort(m_TcpProxyServer.Port);

                        CommonMethods.ComputeTCPChecksum(ipHeader, tcpHeader);
                        m_VPNOutputStream.write(ipHeader.m_Data, ipHeader.m_Offset, size);
                        session.BytesSent += tcpDataSize;//注意顺序
                        m_SentBytes += size;
                    }
                }
                break;
            case IPHeader.UDP:
                // 转发DNS数据包：
                UDPHeader udpHeader = m_UDPHeader;
                udpHeader.m_Offset = ipHeader.getHeaderLength();
                if (ipHeader.getSourceIP() == LOCAL_IP && udpHeader.getDestinationPort() == 53) {
                    m_DNSBuffer.clear();
                    m_DNSBuffer.limit(ipHeader.getDataLength() - 8);
                    DnsPacket dnsPacket = DnsPacket.FromBytes(m_DNSBuffer);
                    if (dnsPacket != null && dnsPacket.Header.QuestionCount > 0) {
                        m_DnsProxy.onDnsRequestReceived(ipHeader, udpHeader, dnsPacket);
                    }
                }
                break;
        }
    }

    public static byte[] uncompress(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return new byte[256];
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayInputStream in = new ByteArrayInputStream(bytes);
        try {
            GZIPInputStream ungzip = new GZIPInputStream(in);
            byte[] buffer = new byte[256];
            int n;
            while ((n = ungzip.read(buffer)) >= 0) {
                out.write(buffer, 0, n);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        return out.toByteArray();
    }

    public static int getIndexAfterEmptyLine(String str) {
        if (str.contains("\n\n")) {
            return str.indexOf("\n\n") + 2;
        }
        if (str.contains("\r\n\r\n")) {
            return str.indexOf("\r\n\r\n") + 4;
        }
        if (str.contains("\r\n\r")) {
            return str.indexOf("\r\n\r") + 3;
        }
        if (str.contains("\n\r\n")) {
            return str.indexOf("\n\r\n") + 3;
        }
        if (str.contains("\n\r")) {
            return str.indexOf("\n\r") + 2;
        }
        return -1;
    }

    private void waitUntilPreapred() {
        while (prepare(this) != null) {
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
    }

    /**
     * 建立vpn连接
     */
    private ParcelFileDescriptor establishVPN() throws Exception {
        Builder builder = new Builder();
        //设置VPN接口的最大传输单元（MTU）。 如果未设置，则将使用操作系统中的默认值。
        builder.setMtu(ProxyConfig.Instance.getMTU());
        if (ProxyConfig.IS_DEBUG)
            System.out.printf("setMtu: %d\n", ProxyConfig.Instance.getMTU());

        //初始化ip，这个ip是干嘛的?
        IPAddress ipAddress = ProxyConfig.Instance.getDefaultLocalIP();
        LOCAL_IP = CommonMethods.ipStringToInt(ipAddress.Address);
        builder.addAddress(ipAddress.Address, ipAddress.PrefixLength);
        if (ProxyConfig.IS_DEBUG)
            System.out.printf("addAddress: %s/%d\n", ipAddress.Address, ipAddress.PrefixLength);

        //初始化dns
        for (ProxyConfig.IPAddress dns : ProxyConfig.Instance.getDnsList()) {
            builder.addDnsServer(dns.Address);
            if (ProxyConfig.IS_DEBUG)
                System.out.printf("addDnsServer: %s\n", dns.Address);
        }

        //设置路由
        if (ProxyConfig.Instance.getRouteList().size() > 0) {
            for (ProxyConfig.IPAddress routeAddress : ProxyConfig.Instance.getRouteList()) {
                builder.addRoute(routeAddress.Address, routeAddress.PrefixLength);
                if (ProxyConfig.IS_DEBUG)
                    System.out.printf("addRoute: %s/%d\n", routeAddress.Address, routeAddress.PrefixLength);
            }
            builder.addRoute(CommonMethods.ipIntToString(ProxyConfig.FAKE_NETWORK_IP), 16);

            if (ProxyConfig.IS_DEBUG)
                System.out.printf("addRoute for FAKE_NETWORK: %s/%d\n", CommonMethods.ipIntToString(ProxyConfig.FAKE_NETWORK_IP), 16);
        } else {
            builder.addRoute("0.0.0.0", 0);
            if (ProxyConfig.IS_DEBUG)
                System.out.printf("addDefaultRoute: 0.0.0.0/0\n");
        }


        Class<?> SystemProperties = Class.forName("android.os.SystemProperties");
        Method method = SystemProperties.getMethod("get", new Class[]{String.class});
        ArrayList<String> servers = new ArrayList<String>();
        for (String name : new String[]{"net.dns1", "net.dns2", "net.dns3", "net.dns4",}) {
            String value = (String) method.invoke(null, name);
            if (value != null && !"".equals(value) && !servers.contains(value)) {
                servers.add(value);
                if (value.replaceAll("\\d", "").length() == 3) {//防止IPv6地址导致问题
                    builder.addRoute(value, 32);
                } else {
                    builder.addRoute(value, 128);
                }
                if (ProxyConfig.IS_DEBUG)
                    System.out.printf("%s=%s\n", name, value);
            }
        }

        if (AppProxyManager.isLollipopOrAbove) {
            if (AppProxyManager.Instance.proxyAppInfo.size() == 0) {
                writeLog("Proxy All Apps");
            }
            for (AppInfo app : AppProxyManager.Instance.proxyAppInfo) {
                builder.addAllowedApplication("com.vm.shadowsocks");//需要把自己加入代理，不然会无法进行网络连接
                try {
                    builder.addAllowedApplication(app.getPkgName());
                    writeLog("Proxy App: " + app.getAppLabel());
                } catch (Exception e) {
                    e.printStackTrace();
                    writeLog("Proxy App Fail: " + app.getAppLabel());
                }
            }
        } else {
            writeLog("No Pre-App proxy, due to low Android version.");
        }

        Intent intent = new Intent(this, MainActivity.class);
        PendingIntent pendingIntent = PendingIntent.getActivity(this, 0, intent, 0);
        builder.setConfigureIntent(pendingIntent);

        builder.setSession(ProxyConfig.Instance.getSessionName());
        ParcelFileDescriptor pfdDescriptor = builder.establish();
        onStatusChanged(ProxyConfig.Instance.getSessionName() + getString(R.string.vpn_connected_status), true);
        return pfdDescriptor;
    }

    public void disconnectVPN() {
        try {
            if (m_VPNInterface != null) {
                m_VPNInterface.close();
                m_VPNInterface = null;
            }
        } catch (Exception e) {
            // ignore
        }
        onStatusChanged(ProxyConfig.Instance.getSessionName() + getString(R.string.vpn_disconnected_status), false);
        this.m_VPNOutputStream = null;
    }

    private synchronized void dispose() {
        // 断开VPN
        disconnectVPN();

        // 停止TcpServer
        if (m_TcpProxyServer != null) {
            m_TcpProxyServer.stop();
            m_TcpProxyServer = null;
            writeLog("LocalTcpServer stopped.");
        }

        // 停止DNS解析器
        if (m_DnsProxy != null) {
            m_DnsProxy.stop();
            m_DnsProxy = null;
            writeLog("LocalDnsProxy stopped.");
        }

        stopSelf();
        IsRunning = false;
        System.exit(0);
    }

    @Override
    public void onDestroy() {
        System.out.printf("VPNService(%s) destoried.\n", ID);
        if (m_VPNThread != null) {
            m_VPNThread.interrupt();
        }
    }

}
