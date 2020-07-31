package burp;

import org.apache.shiro.codec.Base64;
import org.apache.shiro.crypto.AesCipherService;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.apache.shiro.util.ByteSource;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;
import java.awt.*;
import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

public class BurpExtender extends AbstractTableModel implements IBurpExtender, IScannerCheck, ITab, IMessageEditorController{
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter stdout;
    private JSplitPane mjSplitPane;
    private List<TablesData> Udatas = new ArrayList<TablesData>();
    private List<Ulist> ulists = new ArrayList<Ulist>();
    private IMessageEditor HRequestTextEditor;
    private IMessageEditor HResponseTextEditor;
    private IHttpRequestResponse currentlyDisplayedItem;
    private URLTable Utable;
    private JScrollPane UscrollPane;
    private JSplitPane HjSplitPane;
    private JPanel mjPane;
    private JTabbedPane Ltable;
    private JTabbedPane Rtable;

    /**
     * 注册接口用于burp Extender模块的注册
     * @param callbacks An
     */
    public void registerExtenderCallbacks (IBurpExtenderCallbacks callbacks)
    {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        stdout = new PrintWriter(callbacks.getStdout(),true);

        callbacks.setExtensionName("ShiroScan");
        stdout.println("===========================");
        stdout.println("[+]   load successful!     ");
        stdout.println("[+]   ShiroScan v0.3       ");
        stdout.println("[+]   code by Daybr4ak     ");
        stdout.println("[+] 修复同站不同端口不检测问题  ");
        stdout.println("[+]     增加Key检测          ");
        stdout.println("===========================");
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                mjSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

                Utable = new URLTable(BurpExtender.this);
                UscrollPane = new JScrollPane(Utable);

                HjSplitPane = new JSplitPane();
                HjSplitPane.setDividerLocation(0.5D);
                Ltable = new JTabbedPane();
                HRequestTextEditor = BurpExtender.this.callbacks.createMessageEditor(BurpExtender.this,false);
                Ltable.addTab("Request",HRequestTextEditor.getComponent());
                Rtable = new JTabbedPane();
                HResponseTextEditor = BurpExtender.this.callbacks.createMessageEditor(BurpExtender.this,false);
                Rtable.addTab("Response",HResponseTextEditor.getComponent());
                HjSplitPane.add(Ltable,"left");
                HjSplitPane.add(Rtable,"right");

                mjSplitPane.add(UscrollPane,"left");
                mjSplitPane.add(HjSplitPane,"right");
                BurpExtender.this.callbacks.customizeUiComponent(mjSplitPane);
                BurpExtender.this.callbacks.addSuiteTab(BurpExtender.this);
            }
        });
        //  注册自定义扫描仪器(被动扫描or主动扫描)
        callbacks.registerScannerCheck(this);
    }

    /**
     * 动扫描的每个基本请求/响应调用此方法
     * @param baseRequestResponse The base HTTP request / response that should
     * be passively scanned.
     * @return null未发现问题 or IScanIssue对象列表
     */
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        byte[] request = baseRequestResponse.getRequest();
        URL url = helpers.analyzeRequest(baseRequestResponse).getUrl();
        String reqMethod = helpers.analyzeRequest(baseRequestResponse).getMethod();
        // 设置参数
        IParameter newParameter = helpers.buildParameter("rememberMe","1", (byte) 2);
        // 为request包添加设置好的参数
        byte[] newRequest = helpers.updateParameter(request, newParameter);
        // 创建一个新的HTTP请求
        IHttpService httpService = baseRequestResponse.getHttpService();
        IHttpRequestResponse newIHttpRequestResponse = callbacks.makeHttpRequest(httpService,newRequest);
        // 获取新HTTP请求的响应
        byte[] response = newIHttpRequestResponse.getResponse();
        // 获取响应的header头
        for (ICookie cookies : helpers.analyzeResponse(response).getCookies()) {
            if (cookies.getName().equals("rememberMe") && checUrl(httpService.getHost(), httpService.getPort())){
                String mes;
                this.ulists.add(new Ulist(httpService.getHost(),httpService.getPort()));
                try {
                    mes = FindKey(baseRequestResponse);
                } catch (Exception e) {
                    mes = "[-] FindKey Exception...";
                }
                synchronized (this.Udatas) {
                    int row = this.Udatas.size();
                    this.Udatas.add(
                            new TablesData(
                                    row,
                                    reqMethod,
                                    url.toString(),
                                    helpers.analyzeResponse(response).getStatusCode() + "",
                                    mes,
                                    newIHttpRequestResponse
//                                    httpService.getHost(),
//                                    httpService.getPort()
                            ));
                    fireTableRowsInserted(row,row);
                    List<IScanIssue> issues = new ArrayList(1);
                    issues.add(new CustomScanIssue(
                            httpService,
                            url,
                            new IHttpRequestResponse[]{ newIHttpRequestResponse },
                            "Shiro",
                            mes,
                            "High"
                    ));
                    return issues;
                }
            }
        }
        return null;
    }

    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return null;
    }

    /**
     * 防止报告重复的漏洞问题
     * @param existingIssue An issue that was previously reported by this
     * Scanner check.
     * @param newIssue An issue at the same URL path that has been newly
     * reported by this Scanner check.
     * @return  -1报告现有问题，0报告两个问题，1仅报告新问题
     */
    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        if (existingIssue.getIssueName().equals(newIssue.getIssueName()))
            return -1;
        else return 0;
    }


    /**
     * 同一条URL不重复检测
     * @param host
     * @return
     */
    boolean checUrl(String host, int port){
        for (Ulist u : this.ulists) {
            if (u.host.equals(host) && u.port == port)
                return false;
        }
        return true;
    }

    public class Ulist{
        final String host;
        final int port;

        public Ulist(String host,int port){
            this.host = host;
            this.port = port;
        }
    }

    public String FindKey(IHttpRequestResponse baseRequestResponse) throws Exception{
        SimplePrincipalCollection simplePrincipalCollection = new SimplePrincipalCollection();
        byte[] exp = getBytes(simplePrincipalCollection);
        String[] keys = new String[]{
                "kPH+bIxk5D2deZiIxcaaaA==",
                "4AvVhmFLUs0KTA3Kprsdag==",
                "Z3VucwAAAAAAAAAAAAAAAA==",
                "fCq+/xW488hMTCD+cmJ3aQ==",
                "0AvVhmFLUs0KTA3Kprsdag==",
                "1AvVhdsgUs0FSA3SDFAdag==",
                "1QWLxg+NYmxraMoxAXu/Iw==",
                "25BsmdYwjnfcWmnhAciDDg==",
                "2AvVhdsgUs0FSA3SDFAdag==",
                "3AvVhmFLUs0KTA3Kprsdag==",
                "3JvYhmBLUs0ETA5Kprsdag==",
                "r0e3c16IdVkouZgk1TKVMg==",
                "5aaC5qKm5oqA5pyvAAAAAA==",
                "5AvVhmFLUs0KTA3Kprsdag==",
                "6AvVhmFLUs0KTA3Kprsdag==",
                "6NfXkC7YVCV5DASIrEm1Rg==",
                "6ZmI6I2j5Y+R5aSn5ZOlAA==",
                "cmVtZW1iZXJNZQAAAAAAAA==",
                "7AvVhmFLUs0KTA3Kprsdag==",
                "8AvVhmFLUs0KTA3Kprsdag==",
                "8BvVhmFLUs0KTA3Kprsdag==",
                "9AvVhmFLUs0KTA3Kprsdag==",
                "OUHYQzxQ/W9e/UjiAGu6rg==",
                "a3dvbmcAAAAAAAAAAAAAAA==",
                "aU1pcmFjbGVpTWlyYWNsZQ==",
                "bWljcm9zAAAAAAAAAAAAAA==",
                "bWluZS1hc3NldC1rZXk6QQ==",
                "bXRvbnMAAAAAAAAAAAAAAA==",
                "ZUdsaGJuSmxibVI2ZHc9PQ==",
                "wGiHplamyXlVB11UXWol8g==",
                "U3ByaW5nQmxhZGUAAAAAAA==",
                "MTIzNDU2Nzg5MGFiY2RlZg==",
                "L7RioUULEFhRyxM7a2R/Yg==",
                "a2VlcE9uR29pbmdBbmRGaQ==",
                "WcfHGU25gNnTxTlmJMeSpw==",
                "OY//C4rhfwNxCQAQCrQQ1Q==",
                "5J7bIJIV0LQSN3c9LPitBQ==",
                "f/SY5TIve5WWzT4aQlABJA==",
                "bya2HkYo57u6fWh5theAWw==",
                "WuB+y2gcHRnY2Lg9+Aqmqg==",
                "kPv59vyqzj00x11LXJZTjJ2UHW48jzHN",
                "3qDVdLawoIr1xFd6ietnwg==",
                "ZWvohmPdUsAWT3=KpPqda",
                "YI1+nBV//m7ELrIyDHm6DQ==",
                "6Zm+6I2j5Y+R5aS+5ZOlAA==",
                "2A2V+RFLUs+eTA3Kpr+dag==",
                "6ZmI6I2j3Y+R1aSn5BOlAA==",
                "SkZpbmFsQmxhZGUAAAAAAA==",
                "2cVtiE83c4lIrELJwKGJUw==",
                "fsHspZw/92PrS3XrPW+vxw==",
                "XTx6CKLo/SdSgub+OPHSrw==",
                "sHdIjUN6tzhl8xZMG3ULCQ==",
                "O4pdf+7e+mZe8NyxMTPJmQ==",
                "HWrBltGvEZc14h9VpMvZWw==",
                "rPNqM6uKFCyaL10AK51UkQ==",
                "Y1JxNSPXVwMkyvES/kJGeQ==",
                "lT2UvDUmQwewm6mMoiw4Ig==",
                "MPdCMZ9urzEA50JDlDYYDg==",
                "xVmmoltfpb8tTceuT5R7Bw==",
                "c+3hFGPjbgzGdrC+MHgoRQ==",
                "ClLk69oNcA3m+s0jIMIkpg==",
                "Bf7MfkNR0axGGptozrebag==",
                "1tC/xrDYs8ey+sa3emtiYw==",
                "ZmFsYWRvLnh5ei5zaGlybw==",
                "cGhyYWNrY3RmREUhfiMkZA==",
                "IduElDUpDDXE677ZkhhKnQ==",
                "yeAAo1E8BOeAYfBlm4NG9Q==",
                "cGljYXMAAAAAAAAAAAAAAA==",
                "2itfW92XazYRi5ltW0M2yA==",
                "XgGkgqGqYrix9lI6vxcrRw==",
                "ertVhmFLUs0KTA3Kprsdag==",
                "5AvVhmFLUS0ATA4Kprsdag==",
                "s0KTA3mFLUprK4AvVhsdag==",
                "hBlzKg78ajaZuTE0VLzDDg==",
                "9FvVhtFLUs0KnA3Kprsdyg==",
                "d2ViUmVtZW1iZXJNZUtleQ==",
                "yNeUgSzL/CfiWw1GALg6Ag==",
                "NGk/3cQ6F5/UNPRh8LpMIg==",
                "4BvVhmFLUs0KTA3Kprsdag==",
                "MzVeSkYyWTI2OFVLZjRzZg==",
                "CrownKey==a12d/dakdad",
                "empodDEyMwAAAAAAAAAAAA==",
                "A7UzJgh1+EWj5oBFi+mSgw==",
                "c2hpcm9fYmF0aXMzMgAAAA==",
                "i45FVt72K2kLgvFrJtoZRw==",
                "U3BAbW5nQmxhZGUAAAAAAA==",
                "ZnJlc2h6Y24xMjM0NTY3OA==",
                "Jt3C93kMR9D5e8QzwfsiMw==",
                "MTIzNDU2NzgxMjM0NTY3OA==",
                "vXP33AonIp9bFwGl7aT7rA==",
                "V2hhdCBUaGUgSGVsbAAAAA==",
                "Q01TX0JGTFlLRVlfMjAxOQ==",
                "ZAvph3dsQs0FSL3SDFAdag==",
                "Is9zJ3pzNh2cgTHB4ua3+Q==",
                "NsZXjXVklWPZwOfkvk6kUA==",
                "GAevYnznvgNCURavBhCr1w==",
                "66v1O8keKNV3TTcGPK1wzg==",
                "SDKOLKn2J1j/2BHjeZwAoQ=="
        };
        for (int i = 0; i < keys.length; i++) {
            try {
                String rememberMe = shiroEncrypt(keys[i], exp);
                IParameter newParameter = helpers.buildParameter("rememberMe",rememberMe, (byte) 2);
                byte[] newRequest = helpers.updateParameter(baseRequestResponse.getRequest(), newParameter);
                IHttpService httpService = baseRequestResponse.getHttpService();
                IHttpRequestResponse newIHttpRequestResponse = callbacks.makeHttpRequest(httpService,newRequest);
                byte[] response = newIHttpRequestResponse.getResponse();
                boolean isDeleteMe = false;
                for (ICookie cookies : helpers.analyzeResponse(response).getCookies()) {
                    if (cookies.getName().equals("rememberMe")){
                        isDeleteMe = true;
                    }
                }
                if (!isDeleteMe){
                    return "[+] Found Shiro Key:" + keys[i];
                }
            }catch (Exception ignored){
            }
        }
        return "[-] Not Found Shiro Key...";
    }

    public static byte[] getBytes(Object obj) throws Exception {
        ByteArrayOutputStream byteArrayOutputStream = null;
        ObjectOutputStream objectOutputStream = null;
        byteArrayOutputStream = new ByteArrayOutputStream();
        objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
        objectOutputStream.writeObject(obj);
        objectOutputStream.flush();
        return byteArrayOutputStream.toByteArray();
    }

    public static String shiroEncrypt(String key, byte[] objectBytes) {
        Base64 B64 = new Base64();
        byte[] pwd = Base64.decode(key);
        AesCipherService cipherService = new AesCipherService();
        ByteSource byteSource = cipherService.encrypt(objectBytes, pwd);
        byte[] value = byteSource.getBytes();
        return new String(Base64.encode(value));
    }

    @Override
    public IHttpService getHttpService() {
        return this.currentlyDisplayedItem.getHttpService();
    }

    @Override
    public byte[] getRequest() {
        return this.currentlyDisplayedItem.getRequest();
    }

    @Override
    public byte[] getResponse() {
        return this.currentlyDisplayedItem.getResponse();
    }

    @Override
    public String getTabCaption() {
        return "ShiroScan";
    }

    @Override
    public Component getUiComponent() {
        return mjSplitPane;
    }

    @Override
    public int getRowCount() {
        return this.Udatas.size();
    }

    @Override
    public int getColumnCount() {
        return 5;
    }

    public String getColumnName(int columnIndex) {
        switch (columnIndex) {
            case 0:
                return "#";
            case 1:
                return "Method";
            case 2:
                return "URL";
            case 3:
                return "Status";
            case 4:
                return "Issue";
        }
        return null;
    }


    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        TablesData datas = this.Udatas.get(rowIndex);
        switch (columnIndex) {
            case 0:
                return datas.Id;
            case 1:
                return datas.Method;
            case 2:
                return datas.URL;
            case 3:
                return datas.Status;
            case 4:
                return datas.issue;
        }
        return null;
    }

    /**
     * 自定义Table
     */
    public class URLTable extends JTable{
        public URLTable(TableModel tableModel) {
            super(tableModel);
        }

        public void changeSelection(int row, int col, boolean toggle, boolean extend) {
            TablesData dataEntry = BurpExtender.this.Udatas.get(convertRowIndexToModel(row));
            HRequestTextEditor.setMessage(dataEntry.requestResponse.getRequest(), true);
            HResponseTextEditor.setMessage(dataEntry.requestResponse.getResponse(),false);
            currentlyDisplayedItem = dataEntry.requestResponse;
            super.changeSelection(row, col, toggle, extend);
        }
    }

    /**
     * 界面显示数据存储模块
     */
    public static class TablesData {
        final int Id;
        final String Method;
        final String URL;
        final String Status;
        final String issue;
        final IHttpRequestResponse requestResponse;
//        final String host;
//        final int port;

        public TablesData(int id, String method, String url, String status, String issue,IHttpRequestResponse requestResponse) {
            this.Id = id;
            this.Method = method;
            this.URL = url;
            this.Status = status;
            this.issue = issue;
            this.requestResponse = requestResponse;
//            this.host = host;
//            this.port = port;
        }

    }
}

class CustomScanIssue implements IScanIssue
{
    private IHttpService httpService;
    private URL url;
    private IHttpRequestResponse[] httpMessages;
    private String name;
    private String detail;
    private String severity;

    /**
     *
     * @param httpService   HTTP服务
     * @param url   漏洞url
     * @param httpMessages  HTTP消息
     * @param name  漏洞名称
     * @param detail    漏洞细节
     * @param severity  漏洞等级
     */
    public CustomScanIssue(
            IHttpService httpService,
            URL url,
            IHttpRequestResponse[] httpMessages,
            String name,
            String detail,
            String severity)
    {
        this.httpService = httpService;
        this.url = url;
        this.httpMessages = httpMessages;
        this.name = name;
        this.detail = detail;
        this.severity = severity;
    }

    public URL getUrl()
    {
        return url;
    }

    public String getIssueName()
    {
        return name;
    }

    public int getIssueType()
    {
        return 0;
    }

    public String getSeverity()
    {
        return severity;
    }

    public String getConfidence()
    {
        return "Certain";
    }

    public String getIssueBackground()
    {
        return null;
    }

    public String getRemediationBackground()
    {
        return null;
    }


    public String getIssueDetail()
    {
        return detail;
    }

    public String getRemediationDetail()
    {
        return null;
    }

    public IHttpRequestResponse[] getHttpMessages()
    {
        return httpMessages;
    }

    public IHttpService getHttpService()
    {
        return httpService;
    }

}