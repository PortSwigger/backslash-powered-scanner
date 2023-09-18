package burp;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.ArrayList;
import java.util.List;

public class Interference {
    static List<IScanIssue> inteferenceScan(IHttpRequestResponse iHttpRequestResponse, IScannerInsertionPoint iScannerInsertionPoint) {


        boolean checkForContamination = Utilities.globalSettings.getBoolean("race-contamination");
        boolean checkForInteference = Utilities.globalSettings.getBoolean("race-interference");

        if (!checkForContamination && !checkForInteference) {
            return null;
        }

        ArrayList<HttpRequest> preppedRequestBatch = new ArrayList<>();
        final String urlCanary = "xz340fk";
        final String dynamicPrefix = Utilities.generateCanary() + "wrtqv";
        IHttpService service = iHttpRequestResponse.getHttpService();
        boolean seen_synced_id_mismatch = false;
        boolean seen_unsynced_id_mismatch = false;
        ResponseGroup baseline = new ResponseGroup();

        for (int i=0;i<3;i++) {
            HttpRequest montoyaReq = Utilities.buildMontoyaReq(Utilities.addCacheBuster(iScannerInsertionPoint.buildRequest((urlCanary + dynamicPrefix).getBytes()), urlCanary+dynamicPrefix), service);
            HttpRequestResponse reflectionCheck = Utilities.montoyaApi.http().sendRequest(montoyaReq);
            if (reflectionCheck.response() == null || !reflectionCheck.response().contains(urlCanary, false) && !checkForInteference) {
                return null;
            }
            baseline.add(new Resp(reflectionCheck));
            Utilities.sleep(100);
        }

        for (int i = 0; i < 9; i++) {
            String canary = urlCanary+dynamicPrefix+(i%9)+Utilities.generateCanary();
            HttpRequest montoyaReq =  Utilities.buildMontoyaReq(Utilities.addCacheBuster(iScannerInsertionPoint.buildRequest(canary.getBytes()), canary), service);
            preppedRequestBatch.add(montoyaReq);
        }

        Resp interestingResponse = null;
        List<HttpRequestResponse> responses = Utilities.montoyaApi.http().sendRequests(preppedRequestBatch);
        int k = -1;
        for (HttpRequestResponse response : responses) {
            k += 1;
            if (response.response() == null || response.response().statusCode() == 0 || response.response().statusCode() == 429 ) {
                continue;
            }

            Resp resp = new Resp(response);

            if (containsWrongId(resp, dynamicPrefix, k)) {
                interestingResponse = resp;
                seen_synced_id_mismatch = true;
                break;
            }

            if (!baseline.matches(resp)) {
                interestingResponse = resp;
            }
        }

        if (interestingResponse == null) {
            return null;
        }

        Utilities.sleep(1000);

        Resp boringResponse = null;
        for (int i=0;i<9;i++) {
            String canary = urlCanary+dynamicPrefix+(i%9)+Utilities.generateCanary();
            HttpRequest montoyaReq =  Utilities.buildMontoyaReq(Utilities.addCacheBuster(iScannerInsertionPoint.buildRequest(canary.getBytes()), canary), service);
            HttpRequestResponse resp;
            resp = Utilities.montoyaApi.http().sendRequest(montoyaReq);

            if (resp.response() == null || resp.response().statusCode() == 0) {
                continue;
            }

            boringResponse = new Resp(resp);
            if (seen_synced_id_mismatch && containsWrongId(boringResponse, dynamicPrefix, i)) {
                seen_unsynced_id_mismatch = true;
                break;
            }
            baseline.add(boringResponse);
            Utilities.sleep(i*100);
        }

        if (baseline.matches(interestingResponse) && !seen_synced_id_mismatch) {
            return null;
        }

        String title = "";
        String detail = "hmm";
        if (seen_synced_id_mismatch) {
            if (seen_unsynced_id_mismatch) {
                // storage of non-GET parameters is expected and not worth reporting
                if (iScannerInsertionPoint.getInsertionPointType() != IScannerInsertionPoint.INS_PARAM_URL) {
                    return null;
                }
                title = "Input storage";
                detail = "Data submitted in a query parameter is visible in a later response. This may indicate cache poisoning / cache deception potential.";
            } else {
                title = "Cross-contamination race";
                detail = "When ten requests were sent in parallel, data from one request was visible in the response to another. This could indicate a serious info-leak race condition.";
            }
        } else {
            if (boringResponse.getStatus() == 403 && interestingResponse.getStatus() == 421) {
                return null;
            }
            title = "Request interference race";
            detail = "When ten requests were sent in parallel, the application gave a different response. This may indicate a race condition.";
            detail += baseline.describeDiff(interestingResponse);
            if (baseline.gainedInfo(interestingResponse)) {
                // do something?
            }
        }



        Scan.report(title, detail, boringResponse, interestingResponse);

        return null;
    }

    // could add a suffix to eliminate truncation-FPs
    static boolean containsWrongId(Resp resp, String anchor, int expectedId) {
        expectedId = expectedId % 9;
        byte[] response = resp.getResponse();
        List<int[]> matches = Utilities.getMatches(response, anchor.getBytes(), -1);
        for (int[] match: matches) {
            if (response[match[1]] != String.valueOf(expectedId).getBytes()[0]) {
                return true;
            }
        }
        return false;
    }
}
