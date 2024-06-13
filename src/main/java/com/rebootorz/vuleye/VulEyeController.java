package com.rebootorz.vuleye;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.geometry.Insets;
import javafx.scene.control.*;
import javafx.scene.input.MouseEvent;
import javafx.scene.layout.GridPane;

import javax.net.ssl.*;
import java.io.*;
import java.net.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.stream.Stream;

public class VulEyeController {
    public MenuItem menu_proxy;
    @FXML
    private ScrollPane productsScrollPane;

    @FXML

    private ListView<String> productsListView;


    @FXML
    private void initialize() {
        System.out.println("###初始化");
        String baseDir = "pocs"; // POC根目录
        File dir = new File(baseDir);

        // 获取所有子目录名（产品名）
        File[] subDirs = dir.listFiles((dir1, name) -> new File(dir1, name).isDirectory());
        if (subDirs != null) {
            // 将子目录名转换为字符串列表
            ObservableList<String> directoryNames = FXCollections.observableArrayList();
            Arrays.stream(subDirs)
                    .map(File::getName)
                    .forEach(directoryNames::add);

            // 将列表设置为ListView的项
            productsListView.setItems(directoryNames);
        }


        // 加载配置
        ProxyConfig proxyConfig = ConfigLoader.loadProxyConfig();
        if (proxyConfig.getAddress() != null && proxyConfig.getPort() > 0) {
            // 应用代理配置到你的网络组件
//            applyProxySettings(proxyConfig.getAddress(), proxyConfig.getPort());
            System.out.println("###代理已设置: " + proxyConfig.getAddress() + ":" + proxyConfig.getPort());
            resultTextArea.appendText("###代理已设置: " + proxyConfig.getAddress() + ":" + proxyConfig.getPort() + "\n");
        } else {
            System.out.println("###当前未配置代理。");
            resultTextArea.appendText("###当前未配置代理。" + "\n");
        }


    }

    @FXML
    private ChoiceBox<String> pocChoiceBox;

    @FXML
    private TextArea resultTextArea;

    @FXML
    private void onListViewItemClick(MouseEvent event) {
        String selectedItem = productsListView.getSelectionModel().getSelectedItem();
        if (selectedItem != null) {
            // 直接使用selectedItem构造完整的目录路径
            String directoryPath = "pocs/" + selectedItem;
            updateChoiceBox(directoryPath);
        }
    }

    private void updateChoiceBox(String directoryPath) {
        File directory = new File(directoryPath);
        if (directory.isDirectory()) {
            pocChoiceBox.getItems().clear(); // 先清空ChoiceBox的现有选项
            // 添加默认值
            pocChoiceBox.getItems().add("全部漏洞");

            File[] files = directory.listFiles();
            if (files != null) {
                for (File file : files) {
                    if (!file.isHidden()) {
                        String fileNameWithoutExt = removeExtension(file.getName());
                        pocChoiceBox.getItems().add(fileNameWithoutExt);
                    }
                }
            }

            // 设置“全部漏洞”为当前选中项
            pocChoiceBox.setValue("全部漏洞");
        } else {
            System.out.println("ERR - 目录错误 " + directoryPath);
            resultTextArea.appendText("ERR - 目录错误 " + directoryPath + "\n");
        }
    }

    // 辅助方法用于移除文件名的后缀
    private String removeExtension(String fileName) {
        int lastIndexOfDot = fileName.lastIndexOf('.');
        return (lastIndexOfDot == -1) ? fileName : fileName.substring(0, lastIndexOfDot);
    }


    @FXML
    private Button search; // 对应FXML中的fx:id="search"

    // 处理按钮点击事件的方法
    @FXML
    private TextField searchTextField; // 假设这是您的搜索框对应的TextField

    @FXML
    private void handleSearchButtonClick(ActionEvent event) {
        String searchText = searchTextField.getText().trim().toLowerCase(); // 获取并转换为小写以便不区分大小写的比较

        // 如果搜索框不为空，先重载所有基础数据
        if (!searchText.isEmpty()) {
            String baseDir = "pocs"; // POC根目录
            File dir = new File(baseDir);
            File[] subDirs = dir.listFiles((dir1, name) -> new File(dir1, name).isDirectory());
            if (subDirs != null) {
                ObservableList<String> allDirectoryNames = FXCollections.observableArrayList();
                Arrays.stream(subDirs)
                        .map(File::getName)
                        .forEach(allDirectoryNames::add);

                // 如果搜索框有内容，基于所有基础数据进行过滤
                ObservableList<String> filteredItems = FXCollections.observableArrayList();
                allDirectoryNames.forEach(item -> {
                    if (item.toLowerCase().contains(searchText)) {
                        filteredItems.add(item);
                    }
                });
                productsListView.setItems(filteredItems);
            }
        } else {
            // 如果搜索框直接为空，显示所有基础数据
            String baseDir = "pocs";
            File dir = new File(baseDir);
            File[] subDirs = dir.listFiles((dir1, name) -> new File(dir1, name).isDirectory());
            if (subDirs != null) {
                ObservableList<String> directoryNames = FXCollections.observableArrayList();
                Arrays.stream(subDirs)
                        .map(File::getName)
                        .forEach(directoryNames::add);
                productsListView.setItems(directoryNames);
            }
        }
    }


    @FXML
    private Button run; // 对应FXML中的fx:id="run"

    // 处理按钮点击事件的方法
    @FXML
    private TextField urlTextField; // 假设这是输入URL的TextField

    @FXML
    private void handleRunButtonClick(ActionEvent event) {
        String urlInput = urlTextField.getText().trim();

        try {
            URI uri = new URI(urlInput);
            if (!uri.getScheme().equals("http") && !uri.getScheme().equals("https")) {
                showAlert("URL格式错误", "请输入以http或https开头的有效URL。");
                return;
            }

            // 提取主机名及端口
            String host = uri.getHost();
            String protocol = uri.getScheme();
            int port = uri.getPort();
            // 如果端口不是默认端口，则拼接到主机名后面
            if ((uri.getScheme().equals("http") && port != 80) || (uri.getScheme().equals("https") && port != 443) && port != -1) {
                host += ":" + port;
            }
            System.out.println("###提取的Host部分（含非默认端口）: " + host);

            // 获取ChoiceBox当前选择的漏洞名称
            String selectedPoc = pocChoiceBox.getValue();
            parseAndProcessJsonForHost(protocol, host, selectedPoc);
            // 在这里您可以进一步处理提取到的host，比如发送请求或进行其他操作
        } catch (URISyntaxException e) {
            showAlert("ERR - URL解析错误", "无法解析输入的URL，请检查格式！");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    // 显示警告对话框的方法
    private void showAlert(String title, String content) {
        Alert alert = new Alert(Alert.AlertType.WARNING);
        alert.setTitle(title);
        alert.setHeaderText(null);
        alert.setContentText(content);
        alert.showAndWait();
    }


    private void parseAndProcessJsonForHost(String protocol, String host, String selectedPoc) throws IOException {
        ObjectMapper objectMapper = new ObjectMapper();
        String directoryPath = "pocs/" + productsListView.getSelectionModel().getSelectedItem(); // 获取当前选中的产品目录

        if (selectedPoc == "全部漏洞"){
            //遍历directoryPath下的所有json文件名
            Path dirPath = Paths.get(directoryPath);
            // 检查路径是否为目录且存在
            if (!Files.isDirectory(dirPath)) {
                System.out.println("ERR - 指定的路径不是一个目录或不存在");
                return;
            }
            try {
                // 使用Files.list()获取目录流，这将给出该目录下的所有条目（包括文件和子目录）
                try (Stream<Path> entries = Files.list(dirPath)) {
                    entries.forEach(path -> {
                        // 这里只打印文件名，不包括路径
                        System.out.println(path.getFileName());
                        try {
                            String poc = String.valueOf(path.getFileName());
                            Path pocAbsolutePath = Paths.get(directoryPath + "/" + path.getFileName());
                            exploitPocs(poc, pocAbsolutePath, objectMapper, protocol, host);
                        } catch (IOException e) {
                            throw new RuntimeException(e);
                        }
                    });
                } catch (IOException e) {
                    System.err.println("ERR - 在读取目录内容时发生错误: " + e.getMessage());
                }
            } catch (Exception e) {
                e.printStackTrace();
            }

        } else{
            //不需要执行for
            Path pocAbsolutePath = Paths.get(directoryPath + "/" + selectedPoc + ".json");
            exploitPocs(selectedPoc, pocAbsolutePath, objectMapper, protocol, host);
            }


    }

    // 检查Header方法
    private boolean checkHeaders(JsonNode headerWordsNode, Map<String, List<String>> headers) {
        if (headerWordsNode == null || headerWordsNode.isEmpty()) {
            return true; // 如果headerWordsNode为空或不存在，则直接返回true
        }
        for (JsonNode wordNode : headerWordsNode) {
            String word = wordNode.asText();
            for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
                for (String value : entry.getValue()) {
                    if (value.contains(word)) {
                        return true; // 只要有一个匹配就返回true
                    }
                }
            }
        }
        // 循环结束后，如果没有匹配到任何关键字，则返回false
        return false;
    }

    // 检查Body方法
    private boolean checkBody(JsonNode bodyWordsNode, String responseBody) {
        if (bodyWordsNode == null || bodyWordsNode.isEmpty()) return true;
        for (JsonNode wordNode : bodyWordsNode) {
            String word = wordNode.asText();
            if (responseBody.contains(word)) {
                return true;
            }
        }
        return false;
    }



    public class ProxyInputDialog extends GridPane {
        private TextField proxyAddressField;
        private TextField proxyPortField;

        public ProxyInputDialog(String defaultAddress, String defaultPort) {
            setHgap(10);
            setVgap(10);
            setPadding(new Insets(20, 20, 20, 20));

            Label addressLabel = new Label("代理地址:");
            proxyAddressField = new TextField();
            Label portLabel = new Label("端口:");
            proxyPortField = new TextField();

            add(addressLabel, 0, 0);
            add(proxyAddressField, 1, 0);
            add(portLabel, 0, 1);
            add(proxyPortField, 1, 1);

            proxyAddressField.setText(defaultAddress);
            proxyPortField.setText(defaultPort);

        }

        public String getProxyAddress() {
            return proxyAddressField.getText();
        }

        public String getProxyPort() {
            return proxyPortField.getText().toString();
        }
    }

    @FXML
    private void handleProxyMenuItem(ActionEvent event) {
        // 加载配置
        ProxyConfig proxyConfig = ConfigLoader.loadProxyConfig();
        String defaultAddress = proxyConfig.getAddress();
        String defaultPort = String.valueOf(proxyConfig.getPort());
        // 使用配置信息初始化对话框
        ProxyInputDialog dialog = new ProxyInputDialog(defaultAddress, defaultPort);

        ButtonType saveButtonType = new ButtonType("保存", ButtonBar.ButtonData.OK_DONE);
        ButtonType cancelButtonType = new ButtonType("取消", ButtonBar.ButtonData.CANCEL_CLOSE);
        Dialog<ButtonType> dialogBox = new Dialog<>();
        dialogBox.setTitle("设置代理");
        dialogBox.setHeaderText("请输入代理服务器的详细信息");
        dialogBox.getDialogPane().setContent(dialog);
        dialogBox.getDialogPane().getButtonTypes().addAll(saveButtonType, cancelButtonType);

        Optional<ButtonType> result = dialogBox.showAndWait();
        if (result.isPresent() && result.get() == saveButtonType) {
            String proxyAddress = dialog.getProxyAddress();
            System.out.println("123");
            String proxyPort = dialog.getProxyPort();
            System.out.println("1234");
            saveProxyConfig(proxyAddress, proxyPort);
        }
    }

    private void saveProxyConfig(String proxyAddress, String proxyPort) {
        try (PrintWriter writer = new PrintWriter(new FileWriter("config.ini"))) {
            writer.println("[Proxy]");
            writer.println("Address=" + proxyAddress);
            writer.println("Port=" + proxyPort);
            System.out.println("代理配置已保存到config.ini");
            resultTextArea.appendText("###代理配置已保存。" + "\n");
        } catch (IOException e) {
            e.printStackTrace();
            showAlert("保存错误", "保存代理配置到config.ini时发生错误。");
        }
    }




    public static class ConfigLoader {
        private static final String CONFIG_FILE_PATH = "config.ini";
        public static ProxyConfig loadProxyConfig() {
            Properties properties = new Properties();
            ProxyConfig config = new ProxyConfig();
            try (InputStream input = new FileInputStream(CONFIG_FILE_PATH)) {
                properties.load(input);
                String address = properties.getProperty("Address");
                String portStr = properties.getProperty("Port");
                if (address != null && !portStr.isEmpty()) {
                    try {
                        int port = Integer.parseInt(portStr);
                        config.setAddress(address);
                        config.setPort(port);
                    } catch (NumberFormatException e) {
                        System.err.println("ERR - 端口号转换错误，请检查config.ini文件中的Port设置。");
                    }
                }
            } catch (IOException ex) {
                System.err.println("ERR - 读取配置文件错误: " + ex.getMessage());
            }
            return config;
        }
    }


    public static class ProxyConfig {
        private String address;
        private int port;
        // Getter and Setter methods
        public String getAddress() { return address; }
        public void setAddress(String address) { this.address = address; }
        public int getPort() { return port; }
        public void setPort(int port) { this.port = port; }
    }


    private void exploitPocs(String poc, Path pocAbsolutePath, ObjectMapper objectMapper, String protocol, String host) throws IOException {
        System.out.println("尝试读取的文件路径: " + pocAbsolutePath.toString());
        // 检查是否为隐藏文件
        if (pocAbsolutePath.getFileName().toString().startsWith(".")) {
            System.out.println("跳过隐藏文件: " + pocAbsolutePath);
            return;
        }
        // 使用Path对象创建File对象
        File jsonFile = pocAbsolutePath.toFile();
        if (jsonFile.exists() && jsonFile.isFile()) {
            // 读取并解析JSON文件
            JsonNode jsonNode = objectMapper.readTree(jsonFile);
            System.out.println(jsonNode.toString());
            System.out.println("###成功解析并处理了JSON文件: " + jsonFile);
            JsonNode requestsNode = jsonNode.get("req"); // 获取"req"数组
            int reqNum = requestsNode.size();
            int reqCount = 1;
            System.out.println("\n本次探测，一共需要：" + reqNum + "次请求。\n");
            if (requestsNode.isArray()) { // 检查是否为数组
                for (JsonNode reqNode : requestsNode) { // 遍历数组中的每个请求
                    if (reqCount <= reqNum) {
                        System.out.println("###当前是POC/EXP第：" + reqCount + "次发包。");
                        String method = reqNode.get("method").asText();
                        String uri = reqNode.get("uri").asText();
                        String userAgent = reqNode.path("headers").get("user-agent").asText();
                        String contentType = reqNode.path("headers").get("content-type").asText();
                        String data = reqNode.get("data").asText();

                        // 获取检查条件
                        JsonNode checkNode = reqNode.get("check");
                        int expectedStatus = Integer.parseInt(checkNode.get("status").asText());
                        JsonNode headerWordsNode = checkNode.get("header_words");
                        JsonNode bodyWordsNode = checkNode.get("body_words");

                        // 根据method构造请求
                        if ("GET".equalsIgnoreCase(method)) {
                            // 发送GET请求的逻辑
                            Map<String, List<String>> reqHeader = new HashMap<>(); // 初始化请求头容器
                            try {
                                String fullUrl = protocol + "://" + host + uri; // 构建完整URL
                                URL url = new URL(fullUrl);

                                // 从ProxyConfig获取代理配置
                                ProxyConfig proxyConfig = ConfigLoader.loadProxyConfig();
                                HttpURLConnection connection = null;

                                //不做ssl证书校验
                                if ("https".equalsIgnoreCase(protocol)) {
                                    TrustManager[] trustAllCerts = new TrustManager[]{new X509TrustManager() {
                                        public X509Certificate[] getAcceptedIssuers() {
                                            return null;
                                        }

                                        public void checkClientTrusted(X509Certificate[] certs, String authType) {
                                        }

                                        public void checkServerTrusted(X509Certificate[] certs, String authType) {
                                        }
                                    }};
                                    SSLContext sc = SSLContext.getInstance("SSL");
                                    sc.init(null, trustAllCerts, new SecureRandom());
                                    HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

                                    // 禁用主机名验证
                                    HostnameVerifier allHostsValid = new HostnameVerifier() {
                                        public boolean verify(String hostname, SSLSession session) {
                                            return true;
                                        }
                                    };
                                    HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);
                                }
                                String address = proxyConfig.getAddress();
                                Integer port = proxyConfig.getPort();

                                if (address != null && port != null) {
                                    Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(proxyConfig.getAddress(), proxyConfig.getPort()));
                                    // 打开连接并设置代理
                                    connection = (HttpURLConnection) url.openConnection(proxy);
                                } else {
                                    connection = (HttpURLConnection) url.openConnection();
                                }

                                // 设置请求方法为GET
                                connection.setRequestMethod("GET");
                                // 设置请求头（data只有POST才会添加）
                                connection.setRequestProperty("User-Agent", userAgent); // 设置User-Agent
                                connection.setRequestProperty("Content-Type", contentType); // 设置Content-Type
                                // 设置允许输入流，这里我们只是获取响应不需要发送数据，所以不开启输出流
                                connection.setDoOutput(false);

                                int responseCode = 0;
                                try {
                                    // 获取响应码
                                    responseCode = connection.getResponseCode();
                                } catch (java.net.ConnectException e) {
                                    resultTextArea.appendText("ERR - 网络异常，请检查代理/网站！\n");
                                }

                                // 增加对404错误的处理

                                if (responseCode == HttpURLConnection.HTTP_NOT_FOUND && reqCount == reqNum) { // HTTP_NOT_FOUND 对应404状态码

                                    //resultTextArea.appendText("\nWARN - 请求的资源未找到（404错误），不存在漏洞文件-" + poc.replace(".json","") + "\n");
                                    System.out.println("\n---不存在漏洞：" + poc.replace(".json", "") + "!");
                                    //resultTextArea.appendText("\n---不存在漏洞：" + poc.replace(".json","") + "!" + "\n");

                                }

                                if ((expectedStatus == HttpURLConnection.HTTP_INTERNAL_ERROR && responseCode == expectedStatus) || (responseCode == expectedStatus)) { // 并不是所有漏洞利用都是200才成功，所以得以poc中的status为准
                                    try { // 读取响应内容
                                        BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
                                        String inputLine;
                                        StringBuilder content = new StringBuilder();
                                        while ((inputLine = in.readLine()) != null) {
                                            content.append(inputLine);
                                        }
                                        in.close();
                                        // 处理响应内容
                                        String responseBody = content.toString();
                                        System.out.println("###响应内容: " + responseBody);
                                        // 检查响应是否满足条件
                                        boolean isSuccess = checkHeaders(headerWordsNode, connection.getHeaderFields())
                                                && checkBody(bodyWordsNode, responseBody);
                                        if (isSuccess) {
                                            if (reqCount == reqNum) {
                                                System.out.println("12345");
                                                System.out.println("\n+++存在漏洞：" + poc.replace(".json", "") + " ！");
                                                resultTextArea.appendText("\n+++存在漏洞：" + poc.replace(".json", "") + " ！" + "\n");
                                                // 输出请求数据包
                                                // 拼接请求相关的字符串，构造出请求包内容
                                                String reqData = method + " " + uri + " " + "HTTP/1.1" + "\n"
                                                        + "Host: " + host + "\n"
                                                        + "Content-Type: " + contentType + "\n";
                                                System.out.println("\n【POC/EXP数据包】\n" + reqData);
                                                resultTextArea.appendText("\n【POC/EXP数据包】\n" + "————————————————————————————————————————————————————————\n" + reqData + "\n\n————————————————————————————————————————————————————————" + "\n");
                                            }
                                        } else {
                                            if (reqCount == reqNum){
                                                System.out.println("\n---不存在漏洞：" + poc.replace(".json", "") + "!");
                                                resultTextArea.appendText("\n---不存在漏洞：" + poc.replace(".json", "") + "!" + "\n");
                                            }
                                        }

                                    } catch (IOException e) {
                                        // 如果getInputStream()抛出异常，尝试通过getErrorStream()获取错误信息
                                        if (connection.getErrorStream() != null) {
                                            BufferedReader errorIn = new BufferedReader(new InputStreamReader(connection.getErrorStream()));
                                            String errorInputLine;
                                            StringBuilder errorContent = new StringBuilder();
                                            while ((errorInputLine = errorIn.readLine()) != null) {
                                                errorContent.append(errorInputLine);
                                            }
                                            errorIn.close();
                                            String responseBody = errorContent.toString();
                                            // 处理错误响应内容，这里可以打印出来或者做其他处理
                                            System.out.println("Error Response: " + responseBody);
                                            // 检查响应是否满足条件
                                            boolean isSuccess = checkHeaders(headerWordsNode, connection.getHeaderFields())
                                                    && checkBody(bodyWordsNode, responseBody);
                                            if (isSuccess) {
                                                if (reqCount == reqNum) {
                                                    System.out.println("123456");
                                                    System.out.println("\n+++存在漏洞：" + poc.replace(".json", "") + " ！");
                                                    resultTextArea.appendText("\n+++存在漏洞：" + poc.replace(".json", "") + " ！" + "\n");
                                                    // 输出请求数据包
                                                    // 拼接请求相关的字符串，构造出请求包内容
                                                    String reqData = method + " " + uri + " " + "HTTP/1.1" + "\n"
                                                            + "Host: " + host + "\n"
                                                            + "Content-Type: " + contentType + "\n";
                                                    System.out.println("\n【POC/EXP数据包】\n" + reqData);
                                                    resultTextArea.appendText("\n【POC/EXP数据包】\n" + "————————————————————————————————————————————————————————\n" + reqData + "\n\n————————————————————————————————————————————————————————" + "\n");
                                                }
                                            } else {
                                                if (reqCount == reqNum){
                                                    System.out.println("\n---不存在漏洞：" + poc.replace(".json", "") + "!");
                                                    resultTextArea.appendText("\n---不存在漏洞：" + poc.replace(".json", "") + "!" + "\n");
                                                }
                                            }
                                        } else {
                                            // 没有错误流可读取，直接处理IOException
                                            e.printStackTrace();
                                        }
                                    }


                                } else {
                                    if (reqCount == reqNum) {
                                        System.out.println("\n---不存在漏洞：" + poc.replace(".json", "") + "!");
                                        resultTextArea.appendText("\n---不存在漏洞：" + poc.replace(".json", "") + "!" + "\n");
                                    }
                                }


                                connection.disconnect(); // 关闭连接

                            } catch (Exception e) {
                                e.printStackTrace();
                            }
                        } else if ("POST".equalsIgnoreCase(method)) {
                            // 发送POST请求的逻辑
                            Map<String, List<String>> reqHeader = new HashMap<>(); // 初始化请求头容器
                            try {
                                String fullUrl = protocol + "://" + host + uri; // 构建完整URL
                                URL url = new URL(fullUrl);

                                // 从ProxyConfig获取代理配置
                                ProxyConfig proxyConfig = ConfigLoader.loadProxyConfig();
                                HttpURLConnection connection;

                                //不做ssl证书校验
                                if ("https".equalsIgnoreCase(protocol)) {
                                    TrustManager[] trustAllCerts = new TrustManager[]{new X509TrustManager() {
                                        public X509Certificate[] getAcceptedIssuers() {
                                            return null;
                                        }

                                        public void checkClientTrusted(X509Certificate[] certs, String authType) {
                                        }

                                        public void checkServerTrusted(X509Certificate[] certs, String authType) {
                                        }
                                    }};
                                    SSLContext sc = SSLContext.getInstance("SSL");
                                    sc.init(null, trustAllCerts, new SecureRandom());
                                    HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

                                    // 禁用主机名验证
                                    HostnameVerifier allHostsValid = new HostnameVerifier() {
                                        public boolean verify(String hostname, SSLSession session) {
                                            return true;
                                        }
                                    };
                                    HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);
                                }

                                String address = proxyConfig.getAddress();
                                Integer port = proxyConfig.getPort();
                                if (address != null && port != null) {
                                    Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(proxyConfig.getAddress(), proxyConfig.getPort()));
                                    // 打开连接并设置代理
                                    connection = (HttpURLConnection) url.openConnection(proxy);
                                } else {
                                    connection = (HttpURLConnection) url.openConnection();
                                }
                                // 设置请求方法为POST
                                connection.setRequestMethod("POST");

                                // 设置POST请求相关参数
                                connection.setDoOutput(true);
                                connection.setRequestProperty("User-Agent", userAgent);
                                connection.setRequestProperty("Content-Type", contentType);

                                // 写入POST数据
                                OutputStream os = connection.getOutputStream();
                                os.write(data.getBytes());
                                os.flush();
                                os.close();

                                // 获取响应码
                                int responseCode = connection.getResponseCode();
                                // 增加对404错误的处理
                                if (responseCode == HttpURLConnection.HTTP_NOT_FOUND && reqCount==reqNum) { // HTTP_NOT_FOUND 对应404状态码

                                    //resultTextArea.appendText("\nWARN - 请求的资源未找到（404错误），不存在漏洞文件-" + poc.replace(".json","") + "\n");
                                    System.out.println("\n---不存在漏洞：" + poc.replace(".json", "") + "!");
                                    //resultTextArea.appendText("\n---不存在漏洞：" + poc.replace(".json","") + "!" + "\n");

                                }
                                if ((expectedStatus == HttpURLConnection.HTTP_INTERNAL_ERROR && responseCode == expectedStatus) || (responseCode == expectedStatus)) { // 并不是所有漏洞利用都是200才成功，所以得以poc中的status为准
                                    try {
                                        // 读取响应内容
                                        BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
                                        String inputLine;
                                        StringBuilder content = new StringBuilder();
                                        while ((inputLine = in.readLine()) != null) {
                                            content.append(inputLine);
                                        }
                                        in.close();
                                        // 处理响应内容
                                        String responseBody = content.toString();
                                        System.out.println("响应内容: " + responseBody);
                                        // 检查响应是否满足条件
                                        boolean isSuccess = checkHeaders(headerWordsNode, connection.getHeaderFields())
                                                && checkBody(bodyWordsNode, responseBody);
                                        if (isSuccess) {
                                            if (reqCount == reqNum) {
                                                System.out.println("1234567");
                                                System.out.println("\n+++存在漏洞：" + poc.replace(".json", "") + " ！");
                                                resultTextArea.appendText("\n+++存在漏洞：" + poc.replace(".json", "") + " ！" + "\n");
                                                // 输出请求数据包
                                                // 拼接请求相关的字符串，构造出请求包内容
                                                String reqData = method + " " + uri + " " + "HTTP/1.1" + "\n"
                                                        + "Host: " + host + "\n"
                                                        + "Content-Type: " + contentType + "\n\n" + data;
                                                System.out.println("\n【POC/EXP数据包】\n" + reqData);
                                                resultTextArea.appendText("\n【POC/EXP数据包】\n" + "————————————————————————————————————————————————————————\n" + reqData + "\n\n————————————————————————————————————————————————————————" + "\n");
                                            }
                                        } else {
                                            if (reqCount == reqNum) {
                                                System.out.println("\n---不存在漏洞：" + poc.replace(".json", "") + "!");
                                                resultTextArea.appendText("---不存在漏洞：" + poc.replace(".json", "") + "!" + "\n");
                                            }
                                        }
                                    } catch (IOException e) {
                                        // 如果getInputStream()抛出异常，尝试通过getErrorStream()获取错误信息
                                        if (connection.getErrorStream() != null) {
                                            BufferedReader errorIn = new BufferedReader(new InputStreamReader(connection.getErrorStream()));
                                            String errorInputLine;
                                            StringBuilder errorContent = new StringBuilder();
                                            while ((errorInputLine = errorIn.readLine()) != null) {
                                                errorContent.append(errorInputLine);
                                            }
                                            errorIn.close();
                                            String responseBody = errorContent.toString();
                                            // 处理错误响应内容，这里可以打印出来或者做其他处理
                                            System.out.println("Error Response: " + responseBody);
                                            // 检查响应是否满足条件
                                            boolean isSuccess = checkHeaders(headerWordsNode, connection.getHeaderFields())
                                                    && checkBody(bodyWordsNode, responseBody);
                                            if (isSuccess) {
                                                if (reqCount == reqNum) {
                                                    System.out.println("12345678");
                                                    System.out.println("\n+++存在漏洞：" + poc.replace(".json", "") + " ！");
                                                    resultTextArea.appendText("\n+++存在漏洞：" + poc.replace(".json", "") + " ！" + "\n");
                                                    // 输出请求数据包
                                                    // 拼接请求相关的字符串，构造出请求包内容
                                                    String reqData = method + " " + uri + " " + "HTTP/1.1" + "\n"
                                                            + "Host: " + host + "\n"
                                                            + "Content-Type: " + contentType + "\n";
                                                    System.out.println("\n【POC/EXP数据包】\n" + reqData);
                                                    resultTextArea.appendText("\n【POC/EXP数据包】\n" + "————————————————————————————————————————————————————————\n" + reqData + "\n\n————————————————————————————————————————————————————————" + "\n");
                                                }
                                            } else {
                                                if (reqCount == reqNum) {
                                                    System.out.println("\n---不存在漏洞：" + poc.replace(".json", "") + "!");
                                                    resultTextArea.appendText("\n---不存在漏洞：" + poc.replace(".json", "") + "!" + "\n");
                                                }
                                            }
                                        } else {
                                            // 没有错误流可读取，直接处理IOException
                                            e.printStackTrace();
                                        }
                                    }
                                } else {
                                    if (reqCount == reqNum) {
                                        System.out.println("\n---不存在漏洞：" + poc.replace(".json", "") + "!");
                                        resultTextArea.appendText("\n---不存在漏洞：" + poc.replace(".json", "") + "!" + "\n");
                                    }
                                }
                                connection.disconnect();

                            } catch (Exception e) {
                                e.printStackTrace();
                            }
                        } else {
                            System.out.println("ERR - 不支持的请求方法: " + method);
                        }
                        reqCount = reqCount + 1;
                    }

                }
            } else {
                System.out.println("ERR - req字段不是一个数组。");
            }


        }

    }









}

