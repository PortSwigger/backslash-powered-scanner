package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.contextmenu.WebSocketMessage;
import burp.api.montoya.http.message.HttpRequestResponse;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.*;

import org.apache.commons.lang3.StringUtils;

class DiffingScan extends ParamScan {
    private WebSocketMessageImpl webSocketMessage;
    private static IBurpExtenderCallbacks callbacks;
    private static IExtensionHelpers helpers;

    public DiffingScan(String name) {
        super(name);
        scanSettings.importSettings(BurpExtender.settings);
    }

    public void setWSMessage(WebSocketMessage webSocketMessage) {
        this.webSocketMessage = new WebSocketMessageImpl(webSocketMessage.payload(), webSocketMessage.direction(), webSocketMessage.upgradeRequest(), webSocketMessage.annotations(), BulkUtilities.globalSettings.getInt("ws: timeout"));
    }

    public static void setCallbacks(IBurpExtenderCallbacks callbacks) {
        callbacks = callbacks;
        helpers = callbacks.getHelpers();
    }

    private ArrayList<Attack> exploreAvailableFunctions(PayloadInjector injector, Attack basicAttack, String prefix, String suffix, boolean useRandomAnchor) {
        ArrayList<Attack> attacks = new ArrayList<>();
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
            ArrayList<Attack> functionCallResult = injector.fuzz(basicAttack, functionCall);
            if (functionCallResult.isEmpty() && entry[0].equals("Basic function injection")) {
                break;
            }

            attacks.addAll(injector.fuzz(basicAttack, functionCall));
        }

        return attacks;
    }

    IScanIssue findReflectionIssues(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        String baseValue;  
        Attack softBase;
        PayloadInjector injector;

        if (this.webSocketMessage == null) {
            Interference.interferenceScan(baseRequestResponse, insertionPoint);

            injector = new PayloadInjector(baseRequestResponse, insertionPoint);
            baseValue = insertionPoint.getBaseValue();
            
            if (Utilities.globalSettings.getBoolean("ignore baseresponse")) {
                softBase = new Attack();
                softBase.addAttack(injector.buildAttack(baseValue, false));
            } else {
                softBase = new Attack(new Resp(baseRequestResponse));
            }
        } else {
            // interference scan skipped for websockets
            
            injector = new PayloadInjector(webSocketMessage);
        
            String basePayload = webSocketMessage.payload().toString();

            int startI = basePayload.indexOf("FU");
            int endI = basePayload.indexOf("ZZ");
            baseValue = basePayload.substring(startI + 2, endI);
        
            if (Utilities.globalSettings.getBoolean("ignore baseresponse")) {
                softBase = new Attack();
                softBase.addAttack(injector.buildAttack(baseValue, false));
            } else {
                softBase = new Attack(webSocketMessage);
            }

            if (Utilities.globalSettings.getBoolean("ignore baseresponse")) {
                softBase = new Attack();
                softBase.addAttack(injector.buildAttack(baseValue, false));
            } else {
                softBase = new Attack(webSocketMessage);
            }
        } 

        ArrayList<Attack> results = new ArrayList<>();

        // hpp skipped for websockets
        if (Utilities.globalSettings.getBoolean("diff: HPP") && (this.webSocketMessage == null)) {
            Probe backendParameterInjection = new Probe("Backend Parameter Injection", 2, "$zq=%3c%61%60%27%22%24%7b%7b%5c&zq%3d", "|zqy=x%3c%61%60%27%22%24%7b%7b%5c", "!zq=%3c%61%60%27%22%24%7b%7b%5c");
            backendParameterInjection.setEscapeStrings("%26zqy=%3c%61%60%27%22%24%7b%7b%5c", "%26zq=x%3c%61%60%27%22%24%7b%7b%5c"); // "#zq=%3c%61%60%27%22%24%7b%7b%5c"
            backendParameterInjection.setRandomAnchor(false);
            backendParameterInjection.setTip("To scan for backend parameters, right click on the attached request and select 'Identify Backend Parameters'. This option may not be available for non-standard parameters. Scan progress is visible in this extension's output tab, and new scanner issues will be created for any parameters identified.");
            ArrayList<Attack> backendParameterAttack = injector.fuzz(softBase, backendParameterInjection);
            results.addAll(backendParameterAttack);
            if (Utilities.globalSettings.getBoolean("diff: HPP auto-followup") && !backendParameterAttack.isEmpty()) {
                results.addAll(ParamGuesser.guessParams(baseRequestResponse, insertionPoint));
            }

        }

        // work out which payloads (if any) are worth trying
        Attack crudeFuzz = injector.buildAttack("`z'z\"${{%{{\\", true);
        if (Utilities.globalSettings.getBoolean("skip unresponsive params") && BulkUtilities.verySimilar(softBase, crudeFuzz)) {
            return null;
        }

        softBase.addAttack(injector.buildAttack(baseValue, false));
        if (Utilities.globalSettings.getBoolean("skip unresponsive params") && BulkUtilities.verySimilar(softBase, crudeFuzz)) {
            return null;
        }

        crudeFuzz.addAttack(injector.buildAttack("\\z`z'z\"${{%{{\\", true));
        if (Utilities.globalSettings.getBoolean("skip unresponsive params") && BulkUtilities.verySimilar(softBase, crudeFuzz)) {
            return null;
        }

        Attack hardBase = injector.buildAttack("", true);
        if (!BulkUtilities.verySimilar(hardBase, crudeFuzz)) {
            hardBase.addAttack(injector.buildAttack("", true));
        }

        if (Utilities.globalSettings.getBoolean("diff: syntax attacks") && !BulkUtilities.verySimilar(hardBase, crudeFuzz)) {
            boolean worthTryingInjections = false;
            if (!Utilities.globalSettings.getBoolean("thorough mode")) {
                Probe multiFuzz = new Probe("Basic fuzz", 0, "`z'z\"\\", "\\z`z'z\"\\");
                multiFuzz.addEscapePair("\\`z\\'z\\\"\\\\", "\\`z''z\\\"\\\\");
                worthTryingInjections = !injector.fuzz(hardBase, multiFuzz).isEmpty();
            }

            if( Utilities.globalSettings.getBoolean("thorough mode") || worthTryingInjections) {
                ArrayList<String> potential_delimiters = new ArrayList<>();

                // find the encapsulating quote type: ` ' "
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
                    ArrayList<Attack> breakers = injector.fuzz(hardBase, breaker);
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
                        ArrayList<Attack> concatResults = injector.fuzz(hardBase, concat_attack);
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
                    ArrayList<Attack> jsonValueAttack = injector.fuzz(hardBase, jsonValue);
                    results.addAll(jsonValueAttack);

                    Probe jsonKey = new Probe("JSON Injection (key)", 6, "z"+delimiter+":"+delimiter+"z"+delimiter+"z"+delimiter,
                            "z"+delimiter+":"+delimiter+"z"+delimiter+":"+delimiter,
                            "z"+delimiter+":"+delimiter+"z"+delimiter+"."+delimiter);
                    jsonKey.setEscapeStrings("z"+delimiter+":"+delimiter+"z"+delimiter+","+delimiter);
                    ArrayList<Attack> jsonKeyAttack = injector.fuzz(hardBase, jsonKey);
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
                    ArrayList<Attack> functionProbeResults = exploreAvailableFunctions(injector, hardBase, delim + concat, concat + delim, true);
                    if (!functionProbeResults.isEmpty()) { //  && !functionProbeResults.get(-1).getProbe().getName().equals("Basic function injection")
                        results.addAll(functionProbeResults);
                        break;
                    }
                }

            }

            if (Utilities.globalSettings.getBoolean("syntax: interpolation")) {
                Probe interp = new Probe("Interpolation fuzz", 2, "%{{z${{z", "z%{{zz${{z");
                interp.setEscapeStrings("%}}$}}", "}}%z}}$z", "z%}}zz$}}z");
                ArrayList<Attack> interpResults = injector.fuzz(hardBase, interp);
                if (!interpResults.isEmpty()) {
                    results.addAll(interpResults);

                    Probe curlyParse = new Probe("Interpolation - curly", 5, "{{z", "z{{z");
                    curlyParse.setEscapeStrings("z}}z", "}}z", "z}}");
                    ArrayList<Attack> curlyParseAttack = injector.fuzz(hardBase, curlyParse);

                    if (!curlyParseAttack.isEmpty()) {
                        results.addAll(curlyParseAttack);
                        results.addAll(exploreAvailableFunctions(injector, hardBase, "{{", "}}", true));
                    } else {
                        Probe dollarParse = new Probe("Interpolation - dollar", 5, "${{z", "z${{z");
                        dollarParse.setEscapeStrings("$}}", "}}$z", "z$}}z");
                        ArrayList<Attack> dollarParseAttack = injector.fuzz(hardBase, dollarParse);
                        results.addAll(dollarParseAttack);

                        Probe percentParse = new Probe("Interpolation - percent", 5, "%{{41", "41%{{41");
                        percentParse.setEscapeStrings("%}}", "}}%41", "41%}}41");
                        ArrayList<Attack> percentParseAttack = injector.fuzz(hardBase, percentParse);
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

        boolean isInPath;
        if (this.webSocketMessage == null) {
            isInPath = Utilities.isInPath(insertionPoint);
        } else {
            isInPath = false;
        }

        // does a request w/random input differ from the base request? (ie 'should I do soft attacks?')
        if (Utilities.globalSettings.getBoolean("diff: value preserving attacks") && !BulkUtilities.verySimilar(softBase, hardBase)) {
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
                        ArrayList<Attack> concatResults = injector.fuzz(softBase, concat_attack);
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
                ArrayList<Attack> div0_results = injector.fuzz(softBase, div0);
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

            // i don't think its doable to get the insertion point name for websockets, just run it anyway
            if ((this.webSocketMessage != null) || (insertionPoint != null && Utilities.mightBeOrderBy(insertionPoint.getInsertionPointName(), baseValue))) {
                Probe comment = new Probe("Comment injection", 3, "/'z*/**/", "/*/*/z'*/", "/*z'/");
                comment.setEscapeStrings("/*'z*/", "/**z'*/","/*//z'//*/");
                comment.setRandomAnchor(false);
                ArrayList<Attack> commentAttack = injector.fuzz(softBase, comment);
                if (!commentAttack.isEmpty()) {
                    results.addAll(commentAttack);

                    Probe htmlTag = new Probe("HTML tag stripping (WAF?)", 4, ">zz<", "z>z<z", "z>><z");
                    htmlTag.setEscapeStrings("<zz>", "<-zz->", "<xyz>");
                    htmlTag.setRandomAnchor(false);
                    ArrayList<Attack> htmlTagAttack = injector.fuzz(softBase, htmlTag);
                    results.addAll(htmlTagAttack);

                    if (htmlTagAttack.isEmpty()) {
                        Probe htmlComment = new Probe("HTML comment injection (WAF?)", 4, "<!-zz-->", "<--zz-->", "<!--zz->");
                        htmlComment.setEscapeStrings("<!--zz-->", "<!--z-z-->", "<!-->z<-->");
                        htmlComment.setRandomAnchor(false);
                        ArrayList<Attack> htmlCommentAttack = injector.fuzz(softBase, htmlComment);
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
                ArrayList<Attack> commaAbsAttack = injector.fuzz(softBase, commaAbs);

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
                ArrayList<Attack> filePathManip = injector.fuzz(softBase, dotSlash);
                if (!filePathManip.isEmpty()) {
                    results.addAll(filePathManip);
                    Probe normalisedDotSlash = new Probe("File Path Manipulation (normalised)", 4, "../", "z/", "_/", "./../");
                    normalisedDotSlash.setEscapeStrings("./cow/../", "./foo/bar/../../", "./z/../");
                    normalisedDotSlash.setRandomAnchor(false);
                    normalisedDotSlash.setPrefix(Probe.PREPEND);
                    results.addAll(injector.fuzz(softBase, normalisedDotSlash));
                }
            }

            // skip for websockets
            if (Utilities.globalSettings.getBoolean("diff: experimental folder attacks") && (this.webSocketMessage == null)) {
                String firstBlat = "z" + baseValue.substring(Math.min(baseValue.length(), 1));
                String lastBlat = baseValue.substring(0, Math.max(baseValue.length() - 1, 0)) + "z";
                Probe orangeSlash = new Probe("Possible Nginx alias escape", 4, baseValue + "..", baseValue + "../."); // get static 404
                orangeSlash.setEscapeStrings(firstBlat + "..", lastBlat + "..", baseValue + "/../xyz"); // get app 404

                orangeSlash.setRandomAnchor(false);
                orangeSlash.setPrefix(Probe.REPLACE);
                ArrayList<Attack> orangeAttack = injector.fuzz(hardBase, orangeSlash);
                if (!orangeAttack.isEmpty()) {
                    results.addAll(orangeAttack);
                    Probe guessFolder = new Probe("Confirmed Nginx alias escape type 1", 8, baseValue + "../asdfz", baseValue + "../statik");
                    guessFolder.setEscapeStrings(baseValue + "../static", baseValue + "../static/.");
                    guessFolder.setRandomAnchor(false);
                    guessFolder.setPrefix(Probe.REPLACE);
                    results.addAll(injector.fuzz(softBase, guessFolder));

                    // fixme gets FPs on WordPress due to... prefix-matching?
                    Probe guessFolder2 = new Probe("Confirmed Nginx alias escape type 2", 7, baseValue + "../asdfz", baseValue + "../statik");
                    guessFolder2.setEscapeStrings(baseValue + "../" + baseValue, baseValue + "../" + baseValue + "/.");
                    guessFolder2.setRandomAnchor(false);
                    guessFolder2.setPrefix(Probe.REPLACE);
                    results.addAll(injector.fuzz(softBase, guessFolder2));
                }

                Probe proxyEscape = new Probe("Proxy subfolder escape?", 4, "..;/", "..;foo/", "..;bar/");
                proxyEscape.setEscapeStrings("../", ".;/", "..:/", "..:bar/", "..#/");
                proxyEscape.setRandomAnchor(false);
                proxyEscape.setPrefix(Probe.REPLACE);
                results.addAll(injector.fuzz(hardBase, proxyEscape));
            }
        }

        // skip for websockets
        if (Utilities.globalSettings.getBoolean("diff: magic value attacks") && (!BulkUtilities.verySimilar(softBase, hardBase) || Utilities.globalSettings.getBoolean("thorough mode")) && (this.webSocketMessage == null)) {

            String[] magicValues = Utilities.globalSettings.getString("diff: magic values").split(",");

            for (String magicValue: magicValues) {
                if (baseValue.equals(magicValue)) {
                    continue;
                }

                if(magicValue.equals("COM1") && isInPath) {
                    continue;
                }

                String[] corruptedMagic = new String[5];
                for (int i=0;i<4; i++) {
                    StringBuilder corruptor = new StringBuilder(magicValue);
                    corruptor.setCharAt(i % magicValue.length(), 'z');
                    corruptedMagic[i] = corruptor.toString();
                }
                corruptedMagic[4] = "help"; // send a real word to filter out things like usernames and hostnames where 'null' is plausible
                Probe magic = new Probe("Magic value: "+magicValue, 3, magicValue);
                magic.setEscapeStrings(corruptedMagic);
                magic.setPrefix(Probe.REPLACE);
                magic.setUseCacheBuster(true);
                magic.setRequireConsistentEvidence(true);
                results.addAll(injector.fuzz(hardBase, magic));
            }

            if((!Utilities.globalSettings.getBoolean("thorough mode") && Utilities.mightBeIdentifier(baseValue)) || (Utilities.globalSettings.getBoolean("thorough mode") && Utilities.mightBeFunction(baseValue))) {
                Probe functionCall = new Probe("Function hijacking", 6, "sprimtf", "sprintg", "exception", "malloc");
                functionCall.setEscapeStrings("sprintf");
                functionCall.setPrefix(Probe.REPLACE);
                results.addAll(injector.fuzz(softBase, functionCall));
            }
        }
 
        if (!results.isEmpty()) {
            if (this.webSocketMessage == null) {
                return BulkUtilities.reportReflectionIssue(results.toArray((new Attack[results.size()])), baseRequestResponse, "Interesting input handling", "The application reacts to inputs in a way that you may find interesting. The probes are listed below in chronological order, with evidence. Response attributes that only stay consistent in one probe-set are italicised, with the variable attribute starred. ");
            } else {
                HttpRequestResponse upgradeRequest = Utilities.montoyaApi.http().sendRequest(webSocketMessage.upgradeRequest());
                Resp upgradeRequest2 = new Resp(upgradeRequest);
                IScanIssue issue = BulkUtilities.reportReflectionIssue(results.toArray((new Attack[results.size()])), upgradeRequest2, "Interesting input handling", "The application reacts to inputs in a way that you may find interesting. The probes are listed below in chronological order, with evidence. Response attributes that only stay consistent in one probe-set are italicised, with the variable attribute starred. ");
                return issue;
            }
        }
        else {
            return null;
        }
    }

    @Override
    List<IScanIssue> doScan(IHttpRequestResponse iHttpRequestResponse, IScannerInsertionPoint iScannerInsertionPoint) {
        IScanIssue issue = findReflectionIssues(iHttpRequestResponse, iScannerInsertionPoint);
        if (issue != null) {
            Utilities.callbacks.addScanIssue(issue);
        }
        return null;
    }

    @Override
    List<IScanIssue> doScan(byte[] bytes, IHttpService iHttpService) {
        return null;
    }

    private ArrayList<Attack> tryIncrementAttack(PayloadInjector injector, Attack softBase, String baseValue) {
        ArrayList<Attack> attacks = new ArrayList<>();
        int value;
        try {
            // todo support non-base10
            value = Integer.parseInt(baseValue);
        } catch (NumberFormatException e) {
            return attacks;
        }

        Attack X = new Attack();
        X.addAttack(softBase);
        X.addAttack(injector.buildAttack("0"+baseValue, false));

        Attack incrementedX = new Attack();
        incrementedX.addAttack(injector.buildAttack(""+(value+1), false));
        incrementedX.addAttack(injector.buildAttack("0"+(value+1), false));
        if (BulkUtilities.verySimilar(X, incrementedX)) {
            return attacks;
        }

        int highValue = Integer.max(value+1000, value*1000);
        Attack highX = new Attack();
        highX.addAttack(injector.buildAttack(""+highValue, false));
        highX.addAttack(injector.buildAttack("0"+highValue, false));
        if (BulkUtilities.verySimilar(highX, incrementedX)) {
            return attacks;
        }

        Attack incrementedHighX = new Attack();
        incrementedHighX.addAttack(injector.buildAttack(""+(highValue+1), false));
        incrementedHighX.addAttack(injector.buildAttack("0"+(highValue+1), false));
        if (!BulkUtilities.similar(incrementedHighX, highX)) {
            return attacks;
        }

        String title = "Iterable input";
        if (Utilities.globalSettings.getBoolean("include name in title") && (this.webSocketMessage == null)) {
            title += " "+injector.getInsertionPoint().getInsertionPointName();
        }

        Probe iterable1 = new Probe(title, 1, ""+(value+1), "0"+(value+1), "00"+(value+1));
        iterable1.setEscapeStrings(baseValue, "0"+baseValue, "00"+baseValue, "000"+baseValue);
        iterable1.setRandomAnchor(false);
        iterable1.setPrefix(Probe.REPLACE);
        ArrayList<Attack> plusOne = injector.fuzz(X, iterable1);
        if (plusOne.isEmpty()) {
            return attacks;
        }

        Probe iterable2 = new Probe(title, 1, ""+(value+2), "0"+(value+2), "00"+(value+2));
        iterable2.setEscapeStrings(""+(value+1), "0"+(value+1), "00"+(value+1), "000"+(value+1));
        iterable2.setRandomAnchor(false);
        iterable2.setPrefix(Probe.REPLACE);
        ArrayList<Attack> plusTwo = injector.fuzz(incrementedX, iterable2);
        if (plusTwo.isEmpty()) {
            return attacks;
        }

        attacks.addAll(plusOne);
        attacks.addAll(plusTwo);

        return attacks;
    }
}
