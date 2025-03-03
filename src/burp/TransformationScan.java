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

public class TransformationScan {

    private WebSocketMessageImpl webSocketMessage;
    private static IBurpExtenderCallbacks callbacks;
    private static IExtensionHelpers helpers;

    public TransformationScan(final IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        helpers = callbacks.getHelpers();
    }

    public void setWSMessage(WebSocketMessage webSocketMessage) {
        this.webSocketMessage = new WebSocketMessageImpl(webSocketMessage.payload(), webSocketMessage.direction(), webSocketMessage.upgradeRequest(), webSocketMessage.annotations(), BulkUtilities.globalSettings.getInt("ws: timeout"));
    }

    private HashSet<String> getTransformationResults(String leftAnchor, String rightAnchor, byte[] response) {
        List<int[]> leftAnchorReflections = Utilities.getMatches(response, leftAnchor.getBytes(), -1);
        HashSet<String> results = new HashSet<>();
        for (int[] reflection_location : leftAnchorReflections) {
            byte[] reflection = Arrays.copyOfRange(response, reflection_location[1], reflection_location[1] + 20);
            List<int[]> matches = Utilities.getMatches(reflection, rightAnchor.getBytes(), -1);
            int reflection_end;
            if (matches.isEmpty()) {
                results.add("Truncated"); //+StringEscapeUtils.unescapeHtml4(helpers.bytesToString(Arrays.copyOfRange(reflection, 0, 8))));
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

    private HashSet<String> recordHandling(Object resp, Object baseData, String probe) {
        String leftAnchor = Utilities.randomString(3);
        String middleAnchor = "z"+Integer.toString(Utilities.rnd.nextInt(9));
        String rightAnchor = "z"+Utilities.randomString(3);

        HashSet<String> allTransformations = new HashSet<>();

        String payload;               
        if (resp instanceof IHttpRequestResponse && baseData instanceof IScannerInsertionPoint) {
            IHttpRequestResponse baseRequestResponse = (IHttpRequestResponse) resp;
            IScannerInsertionPoint insertionPoint = (IScannerInsertionPoint) baseData;

            payload = leftAnchor + "\\\\" + middleAnchor + probe + rightAnchor;
            IHttpRequestResponse attack = callbacks.makeHttpRequest(
                    baseRequestResponse.getHttpService(), insertionPoint.buildRequest(payload.getBytes())); // Utilities.buildRequest(baseRequestResponse, insertionPoint, payload)

        return getTransformationResults(leftAnchor + "\\" + middleAnchor, rightAnchor, helpers.stringToBytes(helpers.bytesToString(BulkUtilities.filterResponse(attack.getResponse()))));
        }  else {
            HttpRequest upgradeRequest = (HttpRequest) resp;
            ByteArray baseMessage = (ByteArray) baseData;
            String baseMessageString = baseMessage.toString();

            int startI = baseMessageString.indexOf("FU");
            int endI = baseMessageString.indexOf("ZZ");
        
            payload = leftAnchor + "\\\\" + middleAnchor + probe + rightAnchor;
            String modifiedMessage = baseMessageString.substring(0, startI) + payload + baseMessageString.substring(endI + 2);

            WebSocketMessageImpl attack = new WebSocketMessageImpl(ByteArray.byteArray(modifiedMessage), webSocketMessage.direction(), upgradeRequest, webSocketMessage.annotations(), BulkUtilities.globalSettings.getInt("ws: timeout"));

            allTransformations = new HashSet<>();
            // look for transformation in all responses
            for (ByteArray responseBA : attack.responses()) {
                byte[] response = responseBA.getBytes();
                // filter response is not applicable
                allTransformations.addAll(getTransformationResults(leftAnchor + "\\" + middleAnchor, rightAnchor, response));
            }

            return allTransformations;
        }
    }

    private Probe.ProbeResults classifyHandling(Object resp, Object insertionPoint, String probe, boolean expectBackSlashConsumption) {
        Probe.ProbeResults classifiedTransformations = new Probe.ProbeResults();

        HashSet<String> noTransform = new HashSet<>();
        HashSet<String> backslashConsumed = new HashSet<>();

        HashSet<String> transformations = recordHandling(resp, insertionPoint, probe);
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

    public IScanIssue findTransformationIssues(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {

        String leftAnchor = Utilities.randomString(5);
        String rightAnchor = "z" + Utilities.randomString(2);

        Attack basicAttack;
        HashSet<String> default_behaviour;
        
        if (this.webSocketMessage == null) {
            basicAttack = BulkUtilities.buildTransformationAttack(baseRequestResponse, insertionPoint, leftAnchor, "\\\\", rightAnchor);
//        if (Utilities.getMatches(BulkUtilities.filterResponse(basicAttack.getFirstRequest().getResponse()), (left    Anchor + "\\" + rightAnchor).getBytes(), -1).isEmpty()) {
  //          return null;
    //    }
            if (basicAttack.getFirstRequest() instanceof IHttpRequestResponse) {
                IHttpRequestResponse request = (IHttpRequestResponse) basicAttack.getFirstRequest();
                if (Utilities.getMatches(BulkUtilities.filterResponse(request.getResponse()), (leftAnchor + "\\" + rightAnchor).getBytes(), -1).isEmpty()) {
                    return null;
                }
            } else {
                return null; // Handle case where the type is unexpected
            }

            default_behaviour = recordHandling(baseRequestResponse, insertionPoint, "\\zz");
        } else {
            ByteArray baseMessage = webSocketMessage.payload();
            String baseMessageString = baseMessage.toString();

            // send the "normal" payload instead of FUZZ?
            int startI = baseMessageString.indexOf("FU");
            int endI = baseMessageString.indexOf("ZZ");
            String modifiedMessage = baseMessageString.substring(0, startI) + leftAnchor + "\\\\" + rightAnchor + baseMessageString.substring(endI + 2);
            ByteArray fullPayload = ByteArray.byteArray(modifiedMessage);

            // no buildTransformationAttack
            WebSocketMessageImpl basicAttackWsMessage = new WebSocketMessageImpl(fullPayload, webSocketMessage.direction(), webSocketMessage.upgradeRequest(), webSocketMessage.annotations(), BulkUtilities.globalSettings.getInt("ws: timeout"));
            basicAttack = new Attack(basicAttackWsMessage, null, webSocketMessage.payload().toString(), null);

            boolean anchorFound = ((WebSocketMessageImpl) basicAttack.getFirstRequest()).responses().stream()
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

            default_behaviour = recordHandling(webSocketMessage.upgradeRequest(), baseMessage, "\\zz");
        }

        boolean backslashConsumed = false;
        if (default_behaviour.contains("zz")) {
            backslashConsumed = true;
        }

        ArrayList<String> interesting = new ArrayList<>();
        ArrayList<String> boring = new ArrayList<>();

        String[] decodeBasedPayloads = {"101", "x41", "u0041", "0", "1", "x0"};
        String[] payloads = {"'", "\"", "{", "}", "(", ")", "[", "]", "$", "`", "/", "@", "#", ";", "%", "&", "|", ";", "^", "?"};

        for (String payload : decodeBasedPayloads) {
            Probe.ProbeResults handling;
            if (this.webSocketMessage == null) {
                handling = classifyHandling(baseRequestResponse, insertionPoint, "\\" + payload, backslashConsumed);
            } else {
                handling = classifyHandling(webSocketMessage.upgradeRequest(), webSocketMessage.payload(), "//" + payload, backslashConsumed);
            }
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

            Probe.ProbeResults handling;
            if (this.webSocketMessage == null) {
                handling = classifyHandling(baseRequestResponse, insertionPoint, chosen_payload, backslashConsumed);

            } else {
                handling = classifyHandling(webSocketMessage.upgradeRequest(), webSocketMessage.payload(), chosen_payload, backslashConsumed);

            }
            if (!handling.interesting.isEmpty()) {
                interesting.addAll(handling.interesting);

            HashSet<String> followUpTransforms;
            if (this.webSocketMessage == null) {
                followUpTransforms = recordHandling(baseRequestResponse, insertionPoint, followUpPayload);
            } else {
                followUpTransforms = recordHandling(webSocketMessage.upgradeRequest(), webSocketMessage.payload(), followUpPayload);
            }
                for (String transform : followUpTransforms) {
                    interesting.add(followUpPayload + " => " + transform);
                }
            }

            boring.addAll(handling.boring);
        }

        if (this.webSocketMessage == null) {
            return new InputTransformation(interesting, boring, (IHttpRequestResponse) basicAttack.getFirstRequest(), helpers.analyzeRequest((IHttpRequestResponse) baseRequestResponse).getUrl(), ((IScannerInsertionPoint) insertionPoint).getInsertionPointName());
        } else {
            HttpRequestResponse upgradeRequestResponse = Utilities.montoyaApi.http().sendRequest((HttpRequest) webSocketMessage.upgradeRequest());
            Resp upgradeResponse = new Resp(upgradeRequestResponse);
            String basePayload = webSocketMessage.payload().toString();
            String baseValue = webSocketMessage.payload().toString().substring(basePayload.indexOf("FU") + 2, basePayload.indexOf("ZZ"));
            InputTransformation issue = new InputTransformation(interesting, boring, upgradeResponse, helpers.analyzeRequest(upgradeResponse).getUrl(), baseValue);
            Utilities.callbacks.addScanIssue(issue);
            return issue;
        }
    }

}
