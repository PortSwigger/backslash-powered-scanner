package burp;

import burp.api.montoya.ui.contextmenu.WebSocketMessage;
import burp.api.montoya.http.message.HttpRequestResponse;

import java.util.ArrayList;
import java.util.List;
import java.util.Arrays;

import org.apache.commons.lang3.StringUtils;

class WsDiffingScan {
    private static IBurpExtenderCallbacks callbacks;
    private static IExtensionHelpers helpers;
    SettingsBox scanSettings;

    public WsDiffingScan() {
    }

    public static void setCallbacks(IBurpExtenderCallbacks callbacks) {
        callbacks = callbacks;
        helpers = callbacks.getHelpers();
    }

    private ArrayList<WsAttack> exploreAvailableFunctions(WsPayloadInjector injector, WsAttack basicAttack, String prefix, String suffix, boolean useRandomAnchor) {
        ArrayList<WsAttack> attacks = new ArrayList<>();
        ArrayList<String[]> functions = new ArrayList<>();

        if (useRandomAnchor) {
            functions.add(new String[]{"Ruby injection", "1.to_s", "1.to_z", "1.tz_s"});
            functions.add(new String[]{"Python injection", "unichr(49)", "unichrr(49)", "unichn(97)"});
        }
        else {
            functions.add(new String[]{"Ruby injection", "1.abs", "1.abz", "1.abf"});
        }

        functions.add(new String[]{"JavaScript injection", "isFinite(1)", "isFinitd(1)", "isFinitee(1)"});
        functions.add(new String[]{"Shell injection", "$((10/10))", "$((10/00))", "$((1/0))"});
        functions.add(new String[]{"Basic function injection", "abs(1)", "abz(1)", "abf(1)"});

        if (!useRandomAnchor) {
            functions.add(new String[]{"Python injection", "int(unichr(49))", "int(unichrr(49))", "int(unichz(49))"});
        }


        functions.add(new String[]{"MySQL injection", "power(unix_timestamp(),0)", "power(unix_timestampp(),0)", "power(unix_timestanp(),0)"});
        functions.add(new String[]{"Oracle SQL injection", "to_number(1)", "to_numberr(1)", "to_numbez(1)"});
        functions.add(new String[]{"SQL Server injection", "power(current_request_id(),0)", "power(current_request_ids(),0)", "power(current_request_ic(),0)"});
        functions.add(new String[]{"PostgreSQL injection", "power(inet_server_port(),0)", "power(inet_server_por(),0)", "power(inet_server_pont(),0)"});
        functions.add(new String[]{"SQLite injection", "min(sqlite_version(),1)", "min(sqlite_versionn(),1)", "min(sqlite_versipn(),1)"});
        functions.add(new String[]{"PHP injection", "pow((int)phpversion(),0)", "pow((int)phpversionn(),0)", "pow((int)phpversiom(),0)"});
        functions.add(new String[]{"Perl injection", "(getppid()**0)", "(getppidd()**0)", "(getppif()**0)"});


        for (String[] entry: functions) {

            String[] invalidCalls = Arrays.copyOfRange(entry, 2, entry.length);
            for (int i=0;i<invalidCalls.length;i++) {
                invalidCalls[i] = prefix+invalidCalls[i]+suffix;
            }
            Probe functionCall = new Probe(entry[0], 9, invalidCalls);
            functionCall.setEscapeStrings(prefix+entry[1]+suffix);
            functionCall.setRandomAnchor(useRandomAnchor);
            ArrayList<WsAttack> functionCallResult = injector.fuzz(basicAttack, functionCall);
            if (functionCallResult.isEmpty() && entry[0].equals("Basic function injection")) {
                break;
            }

            attacks.addAll(injector.fuzz(basicAttack, functionCall));
        }

        return attacks;
    }

    IScanIssue findReflectionIssues(WebSocketMessage baseWebSocketMessage) {
        WebSocketMessageImpl webSocketMessage = new WebSocketMessageImpl(baseWebSocketMessage.payload(), baseWebSocketMessage.direction(), baseWebSocketMessage.upgradeRequest(), baseWebSocketMessage.annotations(), BulkUtilities.globalSettings.getInt("ws: timeout"));
        
        // interference scan skipped

        WsPayloadInjector injector = new WsPayloadInjector(webSocketMessage);

        String basePayload = webSocketMessage.payload().toString();

        int startI = basePayload.indexOf("FU");
        int endI = basePayload.indexOf("ZZ");
        String baseValue = basePayload.substring(startI + 2, endI);

        WsAttack softBase;

        if (Utilities.globalSettings.getBoolean("ignore baseresponse")) {
            softBase = new WsAttack();
            softBase.addAttack(injector.buildAttack(baseValue, false));
        } else {
            softBase = new WsAttack(webSocketMessage);
        }

        ArrayList<WsAttack> results = new ArrayList<>();

        // hpp skipped

        WsAttack crudeFuzz = injector.buildAttack("`z'z\"${{%{{\\", true);
        if (Utilities.globalSettings.getBoolean("skip unresponsive params") && WsBulkUtilities.verySimilar(softBase, crudeFuzz)) {
            return null;
        }

        softBase.addAttack(injector.buildAttack(baseValue, false));
        if (Utilities.globalSettings.getBoolean("skip unresponsive params") && WsBulkUtilities.verySimilar(softBase, crudeFuzz)) {
            return null;
        }

        crudeFuzz.addAttack(injector.buildAttack("\\z`z'z\"${{%{{\\", true));
        if (Utilities.globalSettings.getBoolean("skip unresponsive params") && WsBulkUtilities.verySimilar(softBase, crudeFuzz)) {
            return null;
        }

        WsAttack hardBase = injector.buildAttack("", true);
        if (!WsBulkUtilities.verySimilar(hardBase, crudeFuzz)) {
            hardBase.addAttack(injector.buildAttack("", true));
        }

        if (Utilities.globalSettings.getBoolean("diff: syntax attacks") && !WsBulkUtilities.verySimilar(hardBase, crudeFuzz)) {
            boolean worthTryingInjections = false;
            if (!Utilities.globalSettings.getBoolean("thorough mode")) {
                Probe multiFuzz = new Probe("Basic fuzz", 0, "`z'z\"\\", "\\z`z'z\"\\");
                multiFuzz.addEscapePair("\\`z\\'z\\\"\\\\", "\\`z''z\\\"\\\\");
                worthTryingInjections = !injector.fuzz(hardBase, multiFuzz).isEmpty();
            }

            if (Utilities.globalSettings.getBoolean("thorough mode") || worthTryingInjections) {
                ArrayList<String> potential_delimiters = new ArrayList<>();

                Probe trailer = new Probe("Backslash", 1, "\\\\\\", "\\");
                trailer.setBase("\\");
                trailer.setEscapeStrings("\\\\\\\\", "\\\\");

                Probe apos = new Probe("String - apostrophe", 3, "z'z", "\\zz'z", "z/'z"); // "z'z'z"
                apos.setBase("'");
                apos.addEscapePair("z\\'z", "z''z");
                apos.addEscapePair("z\\\\\\'z", "z\\''z");

                Probe quote = new Probe("String - doublequoted", 3, "\"", "\\zz\"");
                quote.setBase("\"");
                quote.setEscapeStrings("\\\"");

                Probe backtick = new Probe("String - backtick", 2, "`", "\\z`");
                backtick.setBase("`");
                backtick.setEscapeStrings("\\`");

                Probe[] potential_breakers = {trailer, apos, quote, backtick};

                for (Probe breaker : potential_breakers) {
                    ArrayList<WsAttack> breakers = injector.fuzz(hardBase, breaker);
                    if (breakers.isEmpty()) {
                        continue;
                    }
                    potential_delimiters.add(breaker.getBase());
                    results.addAll(breakers);
                }

                if (potential_delimiters.isEmpty()) {
                    Probe quoteSlash = new Probe("Doublequote plus slash", 4, "\"z\\", "z\"z\\");
                    quoteSlash.setEscapeStrings("\"a\\zz", "z\\z", "z\"z/");
                    results.addAll(injector.fuzz(hardBase, quoteSlash));

                    Probe aposSlash = new Probe("Singlequote plus slash", 4, "'z\\", "z'z\\");
                    aposSlash.setEscapeStrings("'a\\zz", "z\\z", "z'z/");
                    results.addAll(injector.fuzz(hardBase, aposSlash));
                }

                if (potential_delimiters.contains("\\")) {
                    Probe unicodeEscape = new Probe("Escape sequence - unicode", 3, "\\g0041", "\\z0041");
                    unicodeEscape.setEscapeStrings("\\u0041", "\\u0042");
                    results.addAll(injector.fuzz(hardBase, unicodeEscape));

                    Probe regexEscape = new Probe("Escape sequence - regex", 4, "\\g0041", "\\z0041");
                    regexEscape.setEscapeStrings("\\s0041", "\\n0041");
                    results.addAll(injector.fuzz(hardBase, regexEscape));

                    // todo follow up with [char]/e%00
                    Probe regexBreakoutAt = new Probe("Regex breakout - @", 5, "z@", "\\@z@");
                    regexBreakoutAt.setEscapeStrings("z\\@", "\\@z\\@");
                    results.addAll(injector.fuzz(hardBase, regexBreakoutAt));

                    Probe regexBreakoutSlash = new Probe("Regex breakout - /", 5, "z/", "\\/z/");
                    regexBreakoutSlash.setEscapeStrings("z\\/", "\\/z\\/");
                    results.addAll(injector.fuzz(hardBase, regexBreakoutSlash));

                }

                // find the concatenation character
                String[] concatenators = {"||", "+", " ", ".", "&", ","};
                ArrayList<String[]> injectionSequence = new ArrayList<>();

                for (String delimiter : potential_delimiters) {
                    for (String concat : concatenators) {
                        Probe concat_attack = new Probe("Concatenation: " + delimiter + concat, 7, "z" + concat + delimiter + "z(z" + delimiter + "z");
                        concat_attack.setEscapeStrings("z(z" + delimiter + concat + delimiter + "z", "zx" + delimiter + concat + delimiter + "zy");
                        ArrayList<WsAttack> concatResults = injector.fuzz(hardBase, concat_attack);
                        if (concatResults.isEmpty()) {
                            continue;
                        }
                        results.addAll(concatResults);
                        injectionSequence.add(new String[]{delimiter, concat});
                    }

                    Probe jsonValue = new Probe("JSON Injection (value)", 6, "z"+delimiter+","+delimiter+"z"+delimiter+"z"+delimiter+"z",
                            "z"+delimiter+","+delimiter+"z"+delimiter+";"+delimiter+"z",
                            "z"+delimiter+","+delimiter+"z"+delimiter+"."+delimiter+"z");
                    jsonValue.setEscapeStrings("z"+delimiter+","+delimiter+"z"+delimiter+":"+delimiter+"z");
                    ArrayList<WsAttack> jsonValueAttack = injector.fuzz(hardBase, jsonValue);
                    results.addAll(jsonValueAttack);

                    Probe jsonKey = new Probe("JSON Injection (key)", 6, "z"+delimiter+":"+delimiter+"z"+delimiter+"z"+delimiter,
                            "z"+delimiter+":"+delimiter+"z"+delimiter+":"+delimiter,
                            "z"+delimiter+":"+delimiter+"z"+delimiter+"."+delimiter);
                    jsonKey.setEscapeStrings("z"+delimiter+":"+delimiter+"z"+delimiter+","+delimiter);
                    ArrayList<WsAttack> jsonKeyAttack = injector.fuzz(hardBase, jsonKey);
                    results.addAll(jsonKeyAttack);

                    // use $where to detect mongodb json injection
                    String wherePrefix = null;
                    String whereSuffix = "";
                    if (!jsonValueAttack.isEmpty()) {
                        wherePrefix = "z"+delimiter+","+delimiter+"$where"+delimiter+":"+delimiter;
                    }
                    else if (!jsonKeyAttack.isEmpty()) {
                        wherePrefix = "z"+delimiter+":"+delimiter+"z"+delimiter+","+delimiter+"$where"+delimiter+":"+delimiter;
                        whereSuffix = delimiter+","+delimiter+"z";
                    }

                    if (wherePrefix != null) {
                        Probe mongo = new Probe("MongoDB Injection", 9, wherePrefix+"0z41"+whereSuffix, wherePrefix+"0v41"+whereSuffix);
                        mongo.setEscapeStrings(wherePrefix+"0x41"+whereSuffix, wherePrefix+"0x42"+whereSuffix);
                        results.addAll(injector.fuzz(hardBase, mongo));
                    }
                }

                // try to invoke a function
                for (String[] injection : injectionSequence) {
                    String delim = injection[0];
                    String concat = injection[1];
                    ArrayList<WsAttack> functionProbeResults = exploreAvailableFunctions(injector, hardBase, delim + concat, concat + delim, true);
                    if (!functionProbeResults.isEmpty()) { //  && !functionProbeResults.get(-1).getProbe().getName().equals("Basic function injection")
                        results.addAll(functionProbeResults);
                        break;
                    }
                }
            }

            if (Utilities.globalSettings.getBoolean("syntax: interpolation")) {
                Probe interp = new Probe("Interpolation fuzz", 2, "%{{z${{z", "z%{{zz${{z");
                interp.setEscapeStrings("%}}$}}", "}}%z}}$z", "z%}}zz$}}z");
                ArrayList<WsAttack> interpResults = injector.fuzz(hardBase, interp);
                if (!interpResults.isEmpty()) {
                    results.addAll(interpResults);

                    Probe curlyParse = new Probe("Interpolation - curly", 5, "{{z", "z{{z");
                    curlyParse.setEscapeStrings("z}}z", "}}z", "z}}");
                    ArrayList<WsAttack> curlyParseAttack = injector.fuzz(hardBase, curlyParse);

                    if (!curlyParseAttack.isEmpty()) {
                        results.addAll(curlyParseAttack);
                        results.addAll(exploreAvailableFunctions(injector, hardBase, "{{", "}}", true));
                    } else {
                        Probe dollarParse = new Probe("Interpolation - dollar", 5, "${{z", "z${{z");
                        dollarParse.setEscapeStrings("$}}", "}}$z", "z$}}z");
                        ArrayList<WsAttack> dollarParseAttack = injector.fuzz(hardBase, dollarParse);
                        results.addAll(dollarParseAttack);

                        Probe percentParse = new Probe("Interpolation - percent", 5, "%{{41", "41%{{41");
                        percentParse.setEscapeStrings("%}}", "}}%41", "41%}}41");
                        ArrayList<WsAttack> percentParseAttack = injector.fuzz(hardBase, percentParse);
                        results.addAll(percentParseAttack);

                        if (!dollarParseAttack.isEmpty()) {
                            results.addAll(exploreAvailableFunctions(injector, hardBase, "${", "}", true));
                            results.addAll(exploreAvailableFunctions(injector, hardBase, "", "", true));
                        } else if (!percentParseAttack.isEmpty()) {
                            results.addAll(exploreAvailableFunctions(injector, hardBase, "%{", "}", true));
                        }
                    }
                }
            }
        }

        boolean isInPath = false;

        // does a request w/random input differ from the base request? (ie 'should I do soft attacks?')
        if (Utilities.globalSettings.getBoolean("diff: value preserving attacks") && !WsBulkUtilities.verySimilar(softBase, hardBase)) {
            if (Utilities.globalSettings.getBoolean("diff: experimental concat attacks") && Utilities.globalSettings.getBoolean("thorough mode")) {
                String[] potential_delimiters = {"'", "\""};
                String[] concatenators = {"||", "+", " ", "."};
                ArrayList<String[]> injectionSequence = new ArrayList<>();
                for (String delimiter : potential_delimiters) {
                    for (String concat : concatenators) {
                        Probe concat_attack = new Probe("Soft-concatenation: " + delimiter + concat, 5,
                                concat + delimiter + delimiter,
                                delimiter + concat + concat,
                                delimiter + concat + delimiter + delimiter,
                                concat + delimiter + delimiter,
                                delimiter + concat + delimiter + delimiter);

                        concat_attack.setEscapeStrings(
                                delimiter + concat + delimiter,
                                delimiter + concat + delimiter + delimiter + concat + delimiter,
                                delimiter + concat + delimiter + delimiter + concat + delimiter + delimiter + concat + delimiter
                        );
                        concat_attack.setRandomAnchor(false);
                        ArrayList<WsAttack> concatResults = injector.fuzz(softBase, concat_attack);
                        if (concatResults.isEmpty()) {
                            continue;
                        }
                        results.addAll(concatResults);
                        injectionSequence.add(new String[]{delimiter, concat});
                    }
                }
                for (String[] injection : injectionSequence) {
                    String delim = injection[0];
                    String concat = injection[1];
                    // delim+concat+ +concat+delim
                    Probe basicFunction = new Probe("Soft function injection", 8, delim + concat + "substri('',0,0)" + concat + delim, delim + concat + "substrin('',0,0)" + concat + delim);
                    basicFunction.setEscapeStrings(delim + concat + "substr('',0,0)" + concat + delim, delim + concat + "substr('foo',0,0)" + concat + delim);
                    basicFunction.setRandomAnchor(false);
                    results.addAll(injector.fuzz(softBase, basicFunction));

                    Probe basicFunction2 = new Probe("Soft function injection 2", 8, delim + concat + "substri('',0,0)" + concat + delim, delim + concat + "substrin('',0,0)" + concat + delim);
                    basicFunction2.setEscapeStrings(delim + concat + "substring('',0,0)" + concat + delim, delim + concat + "substring('foo',0,0)" + concat + delim);
                    basicFunction2.setRandomAnchor(false);
                    results.addAll(injector.fuzz(softBase, basicFunction2));

                    Probe basicMethod = new Probe("Soft method injection", 8, delim + concat + "''.substri(0,0)" + concat + delim, delim + concat + "''.substrin(0,0)" + concat + delim);
                    basicMethod.setEscapeStrings(delim + concat + "''.substr(0,0)" + concat + delim, delim + concat + "''.substr(0,0)" + concat + delim);
                    basicMethod.setRandomAnchor(false);
                    results.addAll(injector.fuzz(softBase, basicMethod));

                }
            }

            /* this is the simplest payload set and could be used as a template */

            // if the input X looks like a number
            if (StringUtils.isNumeric(baseValue)) {

                // compare the results of appending /0 and /1
                Probe div0 = new Probe("Divide by 0", 4, "/0", "/00", "/000");
                div0.setEscapeStrings("/1", "-0", "/01", "-00");
                div0.setRandomAnchor(false);
                ArrayList<WsAttack> div0_results = injector.fuzz(softBase, div0);
                results.addAll(div0_results);
                // we could stop here, but why not try some followup payloads?

                // if that probe worked...
                if (!div0_results.isEmpty()) {
                    // follow up by injecting a sub-expression
                    Probe divArith = new Probe("Divide by expression", 5, "/(2-2)", "/(3-3)");
                    divArith.setEscapeStrings("/(2-1)", "/(1*1)");
                    divArith.setRandomAnchor(false);
                    results.addAll(injector.fuzz(softBase, divArith));

                    // if *that* worked, try injecting a function call
                    results.addAll(exploreAvailableFunctions(injector, softBase, "/", "", false));
                }

                if (Utilities.globalSettings.getBoolean("diff: iterable inputs")) {
                    results.addAll(tryIncrementAttack(injector, softBase, baseValue));
                }
            }

            //if (Utilities.mightBeOrderBy(insertionPoint.getInsertionPointName(), baseValue)) {
            // i don't think its doable to get the insertion point name, just run it anyway
            if (true) {
                Probe comment = new Probe("Comment injection", 3, "/'z*/**/", "/*/*/z'*/", "/*z'/");
                comment.setEscapeStrings("/*'z*/", "/**z'*/","/*//z'//*/");
                comment.setRandomAnchor(false);
                ArrayList<WsAttack> commentAttack = injector.fuzz(softBase, comment);
                if (!commentAttack.isEmpty()) {
                    results.addAll(commentAttack);

                    Probe htmlTag = new Probe("HTML tag stripping (WAF?)", 4, ">zz<", "z>z<z", "z>><z");
                    htmlTag.setEscapeStrings("<zz>", "<-zz->", "<xyz>");
                    htmlTag.setRandomAnchor(false);
                    ArrayList<WsAttack> htmlTagAttack = injector.fuzz(softBase, htmlTag);
                    results.addAll(htmlTagAttack);

                    if (htmlTagAttack.isEmpty()) {
                        Probe htmlComment = new Probe("HTML comment injection (WAF?)", 4, "<!-zz-->", "<--zz-->", "<!--zz->");
                        htmlComment.setEscapeStrings("<!--zz-->", "<!--z-z-->", "<!-->z<-->");
                        htmlComment.setRandomAnchor(false);
                        ArrayList<WsAttack> htmlCommentAttack = injector.fuzz(softBase, htmlComment);
                        results.addAll(htmlCommentAttack);
                    }

                    Probe procedure = new Probe("MySQL order-by", 7, " procedure analyse (0,0,0)-- -", " procedure analyze (0,0)-- -");
                    procedure.setEscapeStrings(" procedure analyse (0,0)-- -", " procedure analyse (0,0)-- -z");
                    procedure.setRandomAnchor(false);
                    results.addAll(injector.fuzz(softBase, procedure));
                }


                Probe commaAbs = new Probe("Order-by function injection", 5, ",abz(1)", ",abs(0,1)", ",abs()","abs(z)");
                commaAbs.setEscapeStrings(",ABS(1)", ",abs(1)", ",abs(01)"); //  1
                commaAbs.setRandomAnchor(false);
                ArrayList<WsAttack> commaAbsAttack = injector.fuzz(softBase, commaAbs);

                if (!commaAbsAttack.isEmpty()) {
                    results.addAll(commaAbsAttack);
                    results.addAll(exploreAvailableFunctions(injector, softBase, ",", "", false));
                }
            }

            if (Utilities.globalSettings.getBoolean("thorough mode") && !isInPath && Utilities.mightBeIdentifier(baseValue) && !baseValue.equals("")) {
                Probe dotSlash = new Probe("File Path Manipulation", 3, "../", "z/", "_/", "./../");
                dotSlash.setEscapeStrings("./", "././", "./././");
                dotSlash.setRandomAnchor(false);
                dotSlash.setPrefix(Probe.PREPEND);
                ArrayList<WsAttack> filePathManip = injector.fuzz(softBase, dotSlash);
                if (!filePathManip.isEmpty()) {
                    results.addAll(filePathManip);
                    Probe normalisedDotSlash = new Probe("File Path Manipulation (normalised)", 4, "../", "z/", "_/", "./../");
                    normalisedDotSlash.setEscapeStrings("./cow/../", "./foo/bar/../../", "./z/../");
                    normalisedDotSlash.setRandomAnchor(false);
                    normalisedDotSlash.setPrefix(Probe.PREPEND);
                    results.addAll(injector.fuzz(softBase, normalisedDotSlash));
                }
            }

            // experimental folder attacks

            // magic value attacks

        }

        if (!results.isEmpty()) {
            HttpRequestResponse upgradeRequest = Utilities.montoyaApi.http().sendRequest(webSocketMessage.upgradeRequest());
            Resp upgradeRequest2 = new Resp(upgradeRequest);
            IScanIssue issue = WsBulkUtilities.reportReflectionIssue(results.toArray((new WsAttack[results.size()])), upgradeRequest2, "Interesting input handling", "The application reacts to inputs in a way that you may find interesting. The probes are listed below in chronological order, with evidence. Response attributes that only stay consistent in one probe-set are italicised, with the variable attribute starred. ");
            return issue;
        }
        else {
            return null;
        }
    }

    private ArrayList<WsAttack> tryIncrementAttack(WsPayloadInjector injector, WsAttack softBase, String baseValue) {
        ArrayList<WsAttack> attacks = new ArrayList<>();
        int value;
        try {
            // todo support non-base10
            value = Integer.parseInt(baseValue);
        } catch (NumberFormatException e) {
            return attacks;
        }

        WsAttack X = new WsAttack();
        X.addAttack(softBase);
        X.addAttack(injector.buildAttack("0"+baseValue, false));

        WsAttack incrementedX = new WsAttack();
        incrementedX.addAttack(injector.buildAttack(""+(value+1), false));
        incrementedX.addAttack(injector.buildAttack("0"+(value+1), false));
        if (WsBulkUtilities.verySimilar(X, incrementedX)) {
            return attacks;
        }

        int highValue = Integer.max(value+1000, value*1000);
        WsAttack highX = new WsAttack();
        highX.addAttack(injector.buildAttack(""+highValue, false));
        highX.addAttack(injector.buildAttack("0"+highValue, false));
        if (WsBulkUtilities.verySimilar(highX, incrementedX)) {
            return attacks;
        }

        WsAttack incrementedHighX = new WsAttack();
        incrementedHighX.addAttack(injector.buildAttack(""+(highValue+1), false));
        incrementedHighX.addAttack(injector.buildAttack("0"+(highValue+1), false));
        if (!WsBulkUtilities.similar(incrementedHighX, highX)) {
            return attacks;
        }
        
        String title = "Iterable input";
        //if (Utilities.globalSettings.getBoolean("include name in title")) {
        //    title += " "+injector.getInsertionPoint().getInsertionPointName();
        //}

        Probe iterable1 = new Probe(title, 1, ""+(value+1), "0"+(value+1), "00"+(value+1));
        iterable1.setEscapeStrings(baseValue, "0"+baseValue, "00"+baseValue, "000"+baseValue);
        iterable1.setRandomAnchor(false);
        iterable1.setPrefix(Probe.REPLACE);
        ArrayList<WsAttack> plusOne = injector.fuzz(X, iterable1);
        if (plusOne.isEmpty()) {
            return attacks;
        }

        Probe iterable2 = new Probe(title, 1, ""+(value+2), "0"+(value+2), "00"+(value+2));
        iterable2.setEscapeStrings(""+(value+1), "0"+(value+1), "00"+(value+1), "000"+(value+1));
        iterable2.setRandomAnchor(false);
        iterable2.setPrefix(Probe.REPLACE);
        ArrayList<WsAttack> plusTwo = injector.fuzz(incrementedX, iterable2);
        if (plusTwo.isEmpty()) {
            return attacks;
        }

        attacks.addAll(plusOne);
        attacks.addAll(plusTwo);

        return attacks;
    }
}
