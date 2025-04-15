package burp;

import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.net.URL;
import java.util.*;
import java.util.stream.Collectors;
import java.util.List;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.websocket.WebSockets;
import burp.api.montoya.websocket.extension.ExtensionWebSocketCreation;
import burp.api.montoya.websocket.extension.ExtensionWebSocketCreationStatus;
import burp.api.montoya.websocket.extension.ExtensionWebSocketMessageHandler;
import burp.api.montoya.ui.contextmenu.WebSocketContextMenuEvent;
import burp.api.montoya.ui.contextmenu.WebSocketMessage;
import burp.api.montoya.websocket.BinaryMessage;
import burp.api.montoya.websocket.TextMessage;
import burp.api.montoya.core.ByteArray;
import org.apache.commons.lang3.StringEscapeUtils;

import org.apache.commons.lang3.StringEscapeUtils;
import org.apache.commons.lang3.StringUtils;

import javax.swing.*;

public class BurpExtender implements IBurpExtender, BurpExtension {
    private static final String name = "Backslash Powered Scanner";
    private static final String version = "1.25";
    private IBurpExtenderCallbacks callbacks;
    static DiffingScan diffscan = null;

    static SettingsBox settings = new SettingsBox();

    public void initialize(MontoyaApi api) {
        Utilities.montoyaApi = api;
        BulkUtilities.registerContextMenu();
        Utilities.montoyaApi.userInterface().registerContextMenuItemsProvider(new OfferWsFuzz(callbacks));
    }

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        new Utilities(callbacks, new HashMap<>(), name);
        callbacks.setExtensionName(name);

        settings.register("thorough mode", true, "Prioritise scan thoroughness over speed");
        settings.register("skip unresponsive params", true, "Skip scanning parameters where sending a fuzz-string doesn't change the response");
        settings.register("ignore baseresponse", false, "Don't treat the selected request as a sample. Useful if it's old. ");
        settings.register("encode everything", false, "Perform heavier URL encoding on payloads");
        settings.register("debug", false);
        settings.register("include name in title", false);
        settings.register("try transformation scan", false, "Look for suspicious input transformations");
        settings.register("try diffing scan", true);
        settings.register("diff: HPP", true, "Scan for HTTP Parameter Pollution");
        settings.register("diff: HPP auto-followup", false, "If HPP is detected, automatically attempt to identify back-end parameters");
        settings.register("diff: syntax attacks", true);
        settings.register("syntax: interpolation", false, "Detects when ${ or %{ cause different responses. Prone to FPs from WAFs");
        settings.register("diff: value preserving attacks", true);
        settings.register("diff: iterable inputs", true, "Scan for numbers where incrementing has an interesting effect.");
        settings.register("diff: experimental concat attacks", false);
        settings.register("diff: experimental folder attacks", false, "Scan for Orange-style folder escapes. Somewhat unreliable.");
        settings.register("diff: magic value attacks", false, "Look for when configured keywords trigger different code-paths");
        settings.register("diff: magic values", "undefined,null,empty,none,COM1,c!C123449477,aA1537368460!", "Keywords that may trigger interesting code-paths. Try adding your own!");
        settings.register("race-contamination", true, "Detects when synchronised requests cause response cross-contamination. Sometimes finds cache poisoning too.");
        settings.register("race-interference", false, "Detects when synchronised requests make the response change. Useful as a starting point for detecting race conditions. Ensure 'params: dummy' is also enabled.");
        
        settings.register("ws: timeout", 5, "Seconds to wait before closing each connection");
        settings.register("ws: pre-message", "", "Message(s) to send before each payload");
        settings.register("ws: timeout pre-payload", 0, "Milliseconds to wait before sending each payload");
        
        diffscan = new DiffingScan("diff-scan");
        // Scan ipscan = new MagicIPScan("ip-scan");

        new BulkScanLauncher(BulkScan.scans);

        try {
            StringUtils.isNumeric("1");
        } catch (java.lang.NoClassDefFoundError e) {
            Utilities.out("Failed to import the Apache Commons Lang library. You can get it from http://commons.apache.org/proper/commons-lang/");
            throw new NoClassDefFoundError();
        }

        try {
            callbacks.getHelpers().analyzeResponseVariations();
        } catch (java.lang.NoSuchMethodError e) {
            Utilities.out("This extension requires Burp Suite Pro 1.7.10 or later");
            throw new NoSuchMethodError();
        }

        FastScan scan = new FastScan(callbacks);
        callbacks.registerScannerCheck(scan);
        callbacks.registerExtensionStateListener(scan);
        callbacks.registerContextMenuFactory(new OfferParamGuess(callbacks));

        Utilities.out("Loaded " + name + " v" + version);
        SwingUtilities.invokeLater(new ConfigMenu());

    }


}

class FastScan implements IScannerCheck, IExtensionStateListener {
    private TransformationScan transformationScan;
    private DiffingScan diffingScan;
    private IExtensionHelpers helpers;
    private IBurpExtenderCallbacks callbacks;

    FastScan(final IBurpExtenderCallbacks callbacks) {
        transformationScan = new TransformationScan(callbacks);
        diffingScan = BurpExtender.diffscan;
        this.callbacks = callbacks;
        helpers = callbacks.getHelpers();
    }

    public void extensionUnloaded() {
        Utilities.out("Unloading extension...");
        Utilities.unloaded.set(true);
    }

    private IParameter getParameterFromInsertionPoint(IScannerInsertionPoint insertionPoint, byte[] request) {
        IParameter baseParam = null;
        int basePayloadStart = insertionPoint.getPayloadOffsets("x".getBytes())[0];
        List<IParameter> params = helpers.analyzeRequest(request).getParameters();
        for (IParameter param : params) {
            if (param.getValueStart() == basePayloadStart && insertionPoint.getBaseValue().equals(param.getValue())) {
                baseParam = param;
                break;
            }
        }
        return baseParam;
    }

    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {

        ArrayList<IScanIssue> issues = new ArrayList<>();
        if(!(Utilities.globalSettings.getBoolean("try transformation scan") || Utilities.globalSettings.getBoolean("try diffing scan"))) {
            Utilities.out("Aborting scan - all scanner checks disabled");
            return issues;
        }

        // make a custom insertion point to avoid burp excessively URL-encoding payloads
        IParameter baseParam = getParameterFromInsertionPoint(insertionPoint, baseRequestResponse.getRequest());
        if (baseParam != null && (baseParam.getType() == IParameter.PARAM_BODY || baseParam.getType() == IParameter.PARAM_URL)) {
            insertionPoint = new ParamInsertionPoint(baseRequestResponse.getRequest(), baseParam.getName(), baseParam.getValue(), baseParam.getType());
        }

        if (Utilities.globalSettings.getBoolean("try transformation scan")) {
            issues.add(transformationScan.findTransformationIssues(baseRequestResponse, insertionPoint));
        }

        if (Utilities.globalSettings.getBoolean("try diffing scan")) {
            issues.add(diffingScan.findReflectionIssues(baseRequestResponse, insertionPoint));
        }

        if (baseParam != null && (baseParam.getType() == IParameter.PARAM_BODY || baseParam.getType() == IParameter.PARAM_URL) && Utilities.getExtension(baseRequestResponse.getRequest()).equals(".php")) {
            String param_name = baseParam.getName() + "[]";
            byte[] newReq = helpers.removeParameter(baseRequestResponse.getRequest(), baseParam);
            IParameter newParam = helpers.buildParameter(param_name, baseParam.getValue(), baseParam.getType());
            newReq = helpers.addParameter(newReq, helpers.buildParameter(param_name, "", baseParam.getType()));
            newReq = helpers.addParameter(newReq, newParam);

            IScannerInsertionPoint arrayInsertionPoint = new ParamInsertionPoint(newReq, param_name, newParam.getValue(), newParam.getType());
            IHttpRequestResponse newBase = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), arrayInsertionPoint.buildRequest(newParam.getValue().getBytes()));

            if (Utilities.globalSettings.getBoolean("try transformation scan")) {
                issues.add(transformationScan.findTransformationIssues(newBase, arrayInsertionPoint));
            }

            if (Utilities.globalSettings.getBoolean("try diffing scan")) {
                issues.add(diffingScan.findReflectionIssues(newBase, arrayInsertionPoint));
            }
        }

        return issues
                .stream()
                .filter(Objects::nonNull)
                .collect(Collectors.toList());
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        return new ArrayList<>();

    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        if (existingIssue.getIssueName().equals(newIssue.getIssueName()) && existingIssue.getIssueDetail().equals(newIssue.getIssueDetail()))
            return -1;
        else return 0;
    }
}

class InputTransformation extends CustomScanIssue {
    private final static String NAME = "Suspicious input transformation";
    private final static String DETAIL = "The application transforms input in a way that suggests it might be vulnerable to some kind of server-side code injection";
    private final static String REMEDIATION =
            "This issue does not necessarily indicate a vulnerability; it is merely highlighting behaviour worthy of manual investigation. " +
                    "Try to determine the root cause of the observed input transformations. " +
                    "Refer to <a href='http://blog.portswigger.net/2016/11/backslash-powered-scanning-hunting.html'>Backslash Powered Scanning</a> for further details and guidance interpreting results.";
    private final static String CONFIDENCE = "Tentative";

    InputTransformation(ArrayList<String> interesting, ArrayList<String> boring, IHttpRequestResponse base, URL url, String paramName) {
        super(base.getHttpService(), url, new IHttpRequestResponse[]{base}, NAME, generateDetail(interesting, boring, paramName), generateSeverity(interesting), CONFIDENCE, REMEDIATION);
    }

    private static String generateSeverity(ArrayList<String> interesting) {
        String severity = "High";
        if (interesting.size() == 1 && interesting.contains("\\0 => \0")) {
            severity = "Information";
        }
        return severity;
    }

    private static String generateDetail(ArrayList<String> interesting, ArrayList<String> boring, String paramName) {
        String details = DETAIL + "<br/><br/>Affected parameter:<code>" + StringEscapeUtils.escapeHtml4(paramName) + "</code><br/><br/>";
        details += "<p>Interesting transformations:</p><ul> ";
        for (String transform : interesting) {
            details += "<li><b><code style='font-size: 125%;'>" + StringEscapeUtils.escapeHtml4(transform) + "</code></b></li>";
        }
        details += "</ul><p>Boring transformations:</p><ul>";
        for (String transform : boring) {
            details += "<li><b><code>" + StringEscapeUtils.escapeHtml4(transform) + "</code></b></li>";
        }
        details += "</ul>";
        return details;
    }
}

class OfferParamGuess implements IContextMenuFactory {
    private IBurpExtenderCallbacks callbacks;

    public OfferParamGuess(final IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> options = new ArrayList<>();
        if (invocation == null || invocation.getSelectedMessages() == null || invocation.getSelectedMessages().length == 0) {
            return options;
        }
        IHttpRequestResponse req = invocation.getSelectedMessages()[0];
        byte[] resp = req.getRequest();
        if (resp == null) {
            return options;
        }
        if (Utilities.countMatches(resp, Utilities.helpers.stringToBytes("%253c%2561%2560%2527%2522%2524%257b%257b%255c")) > 0) {
            JMenuItem probeButton = new JMenuItem("*Identify backend parameters*");
            probeButton.addActionListener(new TriggerParamGuesser(req));
            options.add(probeButton);
        }
        return options;
    }
}

class TriggerParamGuesser implements ActionListener {
    private IHttpRequestResponse req;

    TriggerParamGuesser(IHttpRequestResponse req) {
        this.req = req;
    }

    public void actionPerformed(ActionEvent e) {
        Runnable runnable = new ParamGuesser(req);
        (new Thread(runnable)).start();
    }
}

class ParamGuesser implements Runnable, IExtensionStateListener {

    private IHttpRequestResponse req;

    public ParamGuesser(IHttpRequestResponse req) {
        this.req = req;
    }

    public void run() {

        IRequestInfo info = Utilities.helpers.analyzeRequest(req);
        List<IParameter> params = info.getParameters();

        for (IParameter param : params) {
            String key = null;
            String[] keys = {"%26zq=%253c", "!zq=%253c"};
            for (String test: keys) {
                if (param.getValue().contains(test)) {
                    key = test;
                    break;
                }
            }

            if (key != null) {
                String originalValue = param.getValue().substring(0, param.getValue().indexOf(key));
                ParamInsertionPoint insertionPoint = new ParamInsertionPoint(req.getRequest(), param.getName(), originalValue, param.getType());
                ArrayList<Attack> paramGuesses = guessParams(req, insertionPoint);
                if (!paramGuesses.isEmpty()) {
                    Utilities.callbacks.addScanIssue(BulkUtilities.reportReflectionIssue(paramGuesses.toArray((new Attack[paramGuesses.size()])), req, "Backend Param", "A potential backend param was identified."));
                }
                break;
            }

        }

    }

    public void extensionUnloaded() {
        Utilities.out("Aborting param bruteforce");
        Utilities.unloaded.set(true);
    }

    public static ArrayList<Attack> guessParams(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {

        String baseValue = insertionPoint.getBaseValue();
        PayloadInjector injector = new PayloadInjector(baseRequestResponse, insertionPoint);
        String targetURL = baseRequestResponse.getHttpService().getHost();
        Utilities.out("Initiating parameter name bruteforce on "+ targetURL);
        Attack base = injector.buildAttack(baseValue+"&"+Utilities.randomString(6)+"=%3c%61%60%27%22%24%7b%7b%5c", false);

        for(int i=0; i<4; i++) {
            base.addAttack(injector.buildAttack(baseValue+"&"+Utilities.randomString((i+1)*(i+1))+"=%3c%61%60%27%22%24%7b%7b%5c", false));
        }

        ArrayList<Attack> attacks = new ArrayList<>();
        try {
            for (int i = 0; i < Utilities.paramNames.size(); i++) { // i<Utilities.paramNames.size();
                String candidate = Utilities.paramNames.get(i);
                Attack paramGuess = injector.buildAttack(baseValue + "&" + candidate + "=%3c%61%60%27%22%24%7b%7b%5c", false);
                if (!BulkUtilities.similar(base, paramGuess)) {
                    Attack confirmParamGuess = injector.buildAttack(baseValue + "&" + candidate + "=%3c%61%60%27%22%24%7b%7b%5c", false);
                    base.addAttack(injector.buildAttack(baseValue + "&" + candidate + "z=%3c%61%60%27%22%24%7b%7b%5c", false));
                    if (!BulkUtilities.similar(base, confirmParamGuess)) {
                        Probe validParam = new Probe("Backend param: " + candidate, 4, "&" + candidate + "=%3c%61%60%27%22%24%7b%7b%5c", "&" + candidate + "=%3c%62%60%27%22%24%7b%7b%5c");
                        validParam.setEscapeStrings("&" + Utilities.randomString(candidate.length()) + "=%3c%61%60%27%22%24%7b%7b%5c", "&" + candidate + "z=%3c%61%60%27%22%24%7b%7b%5c");
                        validParam.setRandomAnchor(false);
                        ArrayList<Attack> confirmed = injector.fuzz(base, validParam);
                        if (!confirmed.isEmpty()) {
                            Utilities.out("Identified backend parameter: " + candidate);
                            attacks.addAll(confirmed);
                        }
                    } else {
                        base.addAttack(paramGuess);
                    }
                }

            }
            Utilities.out("Parameter name bruteforce complete: "+targetURL);
        }
        catch (RuntimeException e) {
            Utilities.out("Parameter name bruteforce aborted: "+targetURL);
        }

        return attacks;
    }
}

class OfferWsFuzz implements ContextMenuItemsProvider {
    private final IBurpExtenderCallbacks callbacks;
    
    public OfferWsFuzz(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
    }

    public List<Component> provideMenuItems(WebSocketContextMenuEvent event) {
        JMenuItem sendToDiffScanMenuItem = new JMenuItem("diff-scan");
        sendToDiffScanMenuItem.addActionListener(l -> performDiffScan(event));

        JMenuItem sendToTransfScanMenuItem = new JMenuItem("transf-scan");
        sendToTransfScanMenuItem.addActionListener(l -> performTransfScan(event));

        return List.of(sendToDiffScanMenuItem, sendToTransfScanMenuItem);
    }

    private void performDiffScan(WebSocketContextMenuEvent event) {
        event.messageEditorWebSocket().ifPresent(editorEvent -> {
            WebSocketMessage webSocketMessage = editorEvent.webSocketMessage();
            WsDiffingScan wsDiffingScan = new WsDiffingScan();
            WsDiffingScan.setCallbacks(callbacks);
            
            List<String> insertionPoints = WsBulkUtilities.getInsertionPoints(webSocketMessage.payload().toString());

            new Thread(() -> {
                for (String insertionPoint : insertionPoints) {
                    WebSocketMessageImpl baseMessage = new WebSocketMessageImpl(ByteArray.byteArray(insertionPoint), webSocketMessage.direction(), webSocketMessage.upgradeRequest(), webSocketMessage.annotations(), BulkUtilities.globalSettings.getInt("ws: timeout"));
                    wsDiffingScan.findReflectionIssues(baseMessage);
                }
            }).start();
        });
    }
    
    private void performTransfScan(WebSocketContextMenuEvent event) {
        event.messageEditorWebSocket().ifPresent(editorEvent -> {
            WebSocketMessage webSocketMessage = editorEvent.webSocketMessage();
            WsTransformationScan wsTransformationScan = new WsTransformationScan();
            WsTransformationScan.setCallbacks(callbacks);
            
            List<String> insertionPoints = WsBulkUtilities.getInsertionPoints(webSocketMessage.payload().toString());

            new Thread(() -> {
                for (String insertionPoint : insertionPoints) {
                    WebSocketMessageImpl baseMessage = new WebSocketMessageImpl(ByteArray.byteArray(insertionPoint), webSocketMessage.direction(), webSocketMessage.upgradeRequest(), webSocketMessage.annotations(), BulkUtilities.globalSettings.getInt("ws: timeout"));
                    wsTransformationScan.findTransformationIssues(baseMessage);
                }
            }).start();
        });
    }

}
