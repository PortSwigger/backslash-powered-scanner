package burp;

import burp.api.montoya.ui.contextmenu.WebSocketMessage;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.core.ByteArray;

import java.util.HashSet;
import java.util.List;
import java.util.Arrays;
import java.util.ArrayList;
import java.net.URLDecoder;
import java.io.UnsupportedEncodingException;
import org.apache.commons.lang3.StringEscapeUtils;

public class WsTransformationScan {

    private static IBurpExtenderCallbacks callbacks;
    private static IExtensionHelpers helpers;

    public WsTransformationScan(final IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        helpers = callbacks.getHelpers();
    }

    private HashSet<String> getTransformationResults(String leftAnchor, String rightAnchor, byte[] response) {
        List<int[]> leftAnchorReflections = Utilities.getMatches(response, leftAnchor.getBytes(), -1);
        HashSet<String> results = new HashSet<>();
        for (int[] reflection_location : leftAnchorReflections) {
            byte[] reflection = Arrays.copyOfRange(response, reflection_location[1], reflection_location[1] + 20);
            List<int[]> matches = Utilities.getMatches(reflection, rightAnchor.getBytes(), -1);
            int reflection_end;
            if (matches.isEmpty()) {
                results.add("Truncated");
            } else {
                reflection_end = matches.get(0)[0];
                results.add(StringEscapeUtils.unescapeHtml4(helpers.bytesToString(Arrays.copyOfRange(reflection, 0, reflection_end))));
            }
        }

        if (leftAnchorReflections.isEmpty()) {
            results.add("Reflection disappeared");
        }

        return results;
    }

    private HashSet<String> recordHandling(WebSocketMessageImpl webSocketMessage, ByteArray baseMessage, String probe) {
        String leftAnchor = Utilities.randomString(3);
        String middleAnchor = "z"+Integer.toString(Utilities.rnd.nextInt(9));
        String rightAnchor = "z"+Utilities.randomString(3);
        String baseMessageString = baseMessage.toString();

        int startI = baseMessageString.indexOf("FU");
        int endI = baseMessageString.indexOf("ZZ");
        String modifiedMessage = baseMessageString.substring(0, startI) + leftAnchor + "\\\\" + middleAnchor + probe + rightAnchor + baseMessageString.substring(endI + 2);

        WebSocketMessageImpl attack = new WebSocketMessageImpl(ByteArray.byteArray(modifiedMessage), webSocketMessage.direction(), webSocketMessage.upgradeRequest(), webSocketMessage.annotations(), BulkUtilities.globalSettings.getInt("ws: timeout"));

        HashSet<String> allTransformations = new HashSet<>();
        for (ByteArray responseBA : attack.responses()) {
            byte[] response = responseBA.getBytes();
            // filter response is not applicable
            allTransformations.addAll(getTransformationResults(leftAnchor + "\\" + middleAnchor, rightAnchor, response));
        }

        return allTransformations;
    }

    private Probe.ProbeResults classifyHandling(WebSocketMessageImpl webSocketMessage, ByteArray baseMessage, String probe, boolean expectBackSlashConsumption) {
        Probe.ProbeResults classifiedTransformations = new Probe.ProbeResults();

        HashSet<String> noTransform = new HashSet<>();
        HashSet<String> backslashConsumed = new HashSet<>();

        HashSet<String> transformations = recordHandling(webSocketMessage, baseMessage, probe);
        for (String transform : transformations) {
            String pretty_transform = probe + " => " + transform;
            try {
                if (probe.startsWith("\\")) {
                    if (transform.equals(probe) || URLDecoder.decode(transform, "UTF-8").equals(probe)) {
                        noTransform.add(pretty_transform);
                    } else if (transform.equals(probe.substring(1))) {
                        backslashConsumed.add(pretty_transform);
                    } else {
                        classifiedTransformations.interesting.add(pretty_transform);
                    }
                } else {
                    if (transform.equals(probe) || URLDecoder.decode(transform, "UTF-8").equals(probe)) {
                        classifiedTransformations.boring.add(pretty_transform);
                    } else {
                        classifiedTransformations.interesting.add(pretty_transform);
                    }
                }
            }
            catch (UnsupportedEncodingException e) {
                classifiedTransformations.interesting.add(pretty_transform);
            }
        }

        if (expectBackSlashConsumption) {
            classifiedTransformations.boring.addAll(backslashConsumed);
            classifiedTransformations.interesting.addAll(noTransform);
        } else {
            classifiedTransformations.boring.addAll(noTransform);
            classifiedTransformations.interesting.addAll(backslashConsumed);
        }

        return classifiedTransformations;
    }

    public IScanIssue findTransformationIssues(WebSocketMessage baseWebSocketMessage) {
        WebSocketMessageImpl webSocketMessage = new WebSocketMessageImpl(baseWebSocketMessage.payload(), baseWebSocketMessage.direction(), baseWebSocketMessage.upgradeRequest(), baseWebSocketMessage.annotations(), BulkUtilities.globalSettings.getInt("ws: timeout"));

        String leftAnchor = Utilities.randomString(5);
        String rightAnchor = "z" + Utilities.randomString(2);
        
        ByteArray baseMessage = webSocketMessage.payload();
        String baseMessageString = baseMessage.toString();

        // send the "normal" payload instead of FUZZ?
        int startI = baseMessageString.indexOf("FU");
        int endI = baseMessageString.indexOf("ZZ");
        String modifiedMessage = baseMessageString.substring(0, startI) + leftAnchor + "\\\\" + rightAnchor + baseMessageString.substring(endI + 2);
        ByteArray fullPayload = ByteArray.byteArray(modifiedMessage);

        // no buildTransformationAttack
        WebSocketMessageImpl basicAttackWsMessage = new WebSocketMessageImpl(fullPayload, webSocketMessage.direction(), webSocketMessage.upgradeRequest(), webSocketMessage.annotations(), BulkUtilities.globalSettings.getInt("ws: timeout"));
        WsAttack basicAttack = new WsAttack(basicAttackWsMessage, null, webSocketMessage.payload().toString(), null);

        boolean anchorFound = basicAttack.getFirstRequest().responses().stream()
            .anyMatch(responseBA ->
                !Utilities.getMatches(
                responseBA.getBytes(),
                (leftAnchor + "\\" + rightAnchor).getBytes(),
                -1
            ).isEmpty()
        );

         if (anchorFound) {
            return null;
        }

        HashSet<String> default_behaviour = recordHandling(webSocketMessage, baseMessage, "\\zz");

        boolean backslashConsumed = false;
        if (default_behaviour.contains("zz")) {
            backslashConsumed = true;
        }

        ArrayList<String> interesting = new ArrayList<>();
        ArrayList<String> boring = new ArrayList<>();

        String[] decodeBasedPayloads = {"101", "x41", "u0041", "0", "1", "x0"};
        String[] payloads = {"'", "\"", "{", "}", "(", ")", "[", "]", "$", "`", "/", "@", "#", ";", "%", "&", "|", ";", "^", "?"};

        for (String payload : decodeBasedPayloads) {
            Probe.ProbeResults handling = classifyHandling(webSocketMessage, baseMessage, "\\" + payload, backslashConsumed);
            interesting.addAll(handling.interesting);
            boring.addAll(handling.boring);
        }

        for (String payload : payloads) {

            String escaped_payload = "\\" + payload;
            String chosen_payload, followUpPayload;
            if (backslashConsumed) {
                chosen_payload = payload;
                followUpPayload = escaped_payload;
            } else {
                chosen_payload = escaped_payload;
                followUpPayload = payload;
            }

            Probe.ProbeResults handling = classifyHandling(webSocketMessage, baseMessage, chosen_payload, backslashConsumed);
            if (!handling.interesting.isEmpty()) {
                interesting.addAll(handling.interesting);

                HashSet<String> followUpTransforms = recordHandling(webSocketMessage, baseMessage, followUpPayload);
                for (String transform : followUpTransforms) {
                    interesting.add(followUpPayload + " => " + transform);
                }
            }

            boring.addAll(handling.boring);
        }

        HttpRequestResponse upgradeRequest = Utilities.montoyaApi.http().sendRequest(webSocketMessage.upgradeRequest());
        Resp upgradeRequestResp = new Resp(upgradeRequest);
        InputTransformation issue = new InputTransformation(interesting, boring, upgradeRequestResp, helpers.analyzeRequest(upgradeRequestResp).getUrl(), "test");
        Utilities.callbacks.addScanIssue(issue);
        return issue;
    }

}
