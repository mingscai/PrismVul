package org.example;

import com.github.gumtreediff.actions.EditScript;
import com.github.gumtreediff.actions.EditScriptGenerator;
import com.github.gumtreediff.actions.model.Action;
import com.github.gumtreediff.actions.model.Insert;
import com.github.gumtreediff.actions.SimplifiedChawatheScriptGenerator;

import com.github.gumtreediff.gen.srcml.SrcmlCppTreeGenerator;
import com.github.gumtreediff.matchers.MappingStore;
import com.github.gumtreediff.matchers.Matchers;
import com.github.gumtreediff.matchers.Matcher;
import com.github.gumtreediff.tree.Tree;
import com.github.gumtreediff.tree.TreeContext;

import static org.example.FunctionSignatureUtils.*;
import static org.example.DiffDebugUtils.*;
import static org.example.PreProcessUtils.*;
import static org.example.TreeMatcherUtils.*;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import java.io.FileWriter;
import java.util.Map;
import java.nio.file.Files;
import java.nio.file.Paths;

public class App {

    private static final boolean DEBUG = false;

    public static void main(String[] args) throws Exception {

        ArgParseUtils result = ArgParseUtils.argParse(args);

        String srcFilePath = result.srcFilePath;
        String dstFilePath = result.dstFilePath;
        String rawSrcFilePath = result.rawSrcFilePath;
        String rawDstFilePath = result.rawDstFilePath;
        String outputJsonPath = result.outputJsonPath;
        boolean preprocess = result.preprocess;
        boolean strictMapping = result.strictMapping;

        String srcCode, dstCode;
        boolean isPreprocessed = false;
        if (preprocess) {
            String originalSrcCode = Files.readString(Paths.get(srcFilePath));
            String originalDstCode = Files.readString(Paths.get(dstFilePath));

            srcCode = preprocessSource(originalSrcCode);
            dstCode = preprocessSource(originalDstCode);

            isPreprocessed = !originalSrcCode.equals(srcCode) || !originalDstCode.equals(dstCode);
        } else {
            srcCode = Files.readString(Paths.get(srcFilePath));
            dstCode = Files.readString(Paths.get(dstFilePath));
        }

        debugPrint("Preprocessed source code:");
        debugPrint(">>>>>>>>>>>> Source file: " + srcFilePath);
        debugPrint(srcCode);
        debugPrint("<<<<<<<<<<<< Destination file: " + dstFilePath);
        debugPrint(dstCode);

        String rawSrcCode = Files.readString(Paths.get(rawSrcFilePath));
        String rawDstCode = Files.readString(Paths.get(rawDstFilePath));

        TreeContext src = new SrcmlCppTreeGenerator().generateFrom().string(srcCode);
        TreeContext dst = new SrcmlCppTreeGenerator().generateFrom().string(dstCode);
        TreeContext rawSrc = new SrcmlCppTreeGenerator().generateFrom().string(rawSrcCode);
        TreeContext rawDst = new SrcmlCppTreeGenerator().generateFrom().string(rawDstCode);

        Tree tSrc = src.getRoot();
        Tree tDst = dst.getRoot();
        Tree tRawSrc = rawSrc.getRoot();
        Tree tRawDst = rawDst.getRoot();

        removeTestMacros(tSrc);
        removeTestMacros(tDst);
        removeTestMacros(tRawSrc);
        removeTestMacros(tRawDst);

        debugPrint(">>>>>>>>>>>> AST for source file: \n" + getTree(tSrc, 0));
        debugPrint("<<<<<<<<<<<< AST for destination file: \n" + getTree(tDst, 0));

        List<Tree> srcFuncs = StreamSupport.stream(tSrc.preOrder().spliterator(), false)
            .filter(FunctionSignatureUtils::isFunctionNode)
            .collect(Collectors.toList());

        List<Tree> dstFuncs = StreamSupport.stream(tDst.preOrder().spliterator(), false)
            .filter(FunctionSignatureUtils::isFunctionNode)
            .collect(Collectors.toList());

        List<Tree> rawSrcFuncs = StreamSupport.stream(tRawSrc.preOrder().spliterator(), false)
            .filter(FunctionSignatureUtils::isFunctionNode)
            .collect(Collectors.toList());

        List<Tree> rawDstFuncs = StreamSupport.stream(tRawDst.preOrder().spliterator(), false)
            .filter(FunctionSignatureUtils::isFunctionNode)
            .collect(Collectors.toList());

        Set<String> addedFunctions = new HashSet<>();
        Set<String> removedFunctions = new HashSet<>();
        Set<String> modifiedFunctions = new HashSet<>();
        Map<String, String> modifiedSrcToDst = new HashMap<>();

        boolean skipEditScript = false;
        if (srcCode.trim().isEmpty() && !dstCode.trim().isEmpty()) {
            dstFuncs.forEach(f -> addedFunctions.add(getFunctionSignature(f, dstCode)));
            skipEditScript = true;
        } else if (!srcCode.trim().isEmpty() && dstCode.trim().isEmpty()) {
            srcFuncs.forEach(f -> removedFunctions.add(getFunctionSignature(f, srcCode)));
            skipEditScript = true;
        }

        if (!skipEditScript) {

        Matcher matcher = Matchers.getInstance().getMatcher("classic-gumtree-theta");

        MappingStore mappings = matcher.match(tSrc, tDst);

        if (strictMapping) {

            debugPrint("Source functions found: " + srcFuncs.size());
            for (Tree func : srcFuncs) {
                debugPrint(getTree(func, 0));
            }

            debugPrint("Destination functions found: " + dstFuncs.size());
            for (Tree func : dstFuncs) {
                debugPrint(getTree(func, 0));
            }

            for (Tree srcFunc : srcFuncs) {
                Tree dstFunc = mappings.getDstForSrc(srcFunc);
                if (dstFunc != null && isFunctionNode(dstFunc)) {
                    if (!areSubtreesSimilar(srcFunc, dstFunc)) {

                        mappings.removeMapping(srcFunc, dstFunc);
                        debugPrint("Removed mapping between non-similar functions:");
                        debugPrint("Source function: " + getTree(srcFunc, 0));
                        debugPrint("Destination function: " + getTree(dstFunc, 0));
                    }
                }
            }
        }

        EditScriptGenerator editScriptGenerator = new SimplifiedChawatheScriptGenerator();

        EditScript editScript = editScriptGenerator.computeActions(mappings);

        debugPrint(DiffDebugUtils.getEditScript(editScript));

        Set<String> srcFunctionSignatures = srcFuncs.stream()
            .map(f -> getFunctionSignature(f, srcCode))
            .collect(Collectors.toSet());

        for (Action action : editScript) {
            debugPrint("\nProcessing action:\n" + action);

            String actionName = action.getName();
            Tree changedNode = action.getNode();

            if (actionName.contains("insert") && isScopeContainerNode(changedNode)) {
                collectFunctionsRecursively(changedNode, addedFunctions, dstCode);
                continue;
            }
            if (actionName.contains("delete") && isScopeContainerNode(changedNode)) {
                collectFunctionsRecursively(changedNode, removedFunctions, srcCode);
                continue;
            }

            debugPrint("Node type: " + changedNode.getType().name + ", label: " + changedNode.getLabel());
            debugPrint(getPathToRoot(changedNode));

            Tree func = findEnclosingFunction(changedNode);

            if (func == null) {
                if (action instanceof Insert) {
                    func = findFunctionByPosition(dstFuncs, changedNode);
                } else {
                    func = findFunctionByPosition(srcFuncs, changedNode);
                }
            }

            if (func == null) {

                if (actionName.contains("delete")) {

                    collectFunctionsRecursively(changedNode, removedFunctions, srcCode);

                } else if (actionName.contains("insert")) {
                    collectFunctionsRecursively(changedNode, addedFunctions, dstCode);
                }
                continue;
            }

            debugPrint("Enclosing function candidate:");
            debugPrint(getTree(func, 0));

            String funcSignature = getFunctionSignature(func, (action instanceof Insert) ? dstCode : srcCode);

            debugPrint("actionName = " + actionName
                + ", changedNodeType = " + changedNode.getType().name
                + ", label = " + changedNode.getLabel());

            if (actionName.contains("insert")) {
                Tree oldMapped = mappings.getSrcForDst(func);

                if (oldMapped != null && isFunctionNode(oldMapped)) {
                    String oldSig = getFunctionSignature(oldMapped, srcCode);
                    modifiedFunctions.add(oldSig);
                    modifiedSrcToDst.put(oldSig, funcSignature);
                    debugPrint("[insert] One function signature added to modifiedFunctions: " + oldSig);
                } else {
                    if (!srcFunctionSignatures.contains(funcSignature)) {
                        addedFunctions.add(funcSignature);
                        debugPrint("[insert] One function signature added to addedFunctions: " + funcSignature);
                    } else {
                        debugPrint("[insert] Skip pseudo-added function already in src: " + funcSignature);
                    }
                }
            } else if (actionName.contains("delete")) {
                Tree newMapped = mappings.getDstForSrc(func);

                if (newMapped != null && isFunctionNode(newMapped)) {
                    String newSig = getFunctionSignature(newMapped, dstCode);
                    modifiedFunctions.add(funcSignature);
                    modifiedSrcToDst.put(funcSignature, newSig);
                    debugPrint("[delete] One function signature added to modifiedFunctions: " + funcSignature);
                } else {
                    removedFunctions.add(funcSignature);
                    debugPrint("[delete] One function signature added to removedFunctions: " + funcSignature);
                }
            } else {

                if (!removedFunctions.contains(funcSignature)) {
                    modifiedFunctions.add(funcSignature);

                    Tree dstMapped = mappings.getDstForSrc(func);
                    if (dstMapped != null && isFunctionNode(dstMapped)) {
                        modifiedSrcToDst.put(funcSignature, getFunctionSignature(dstMapped, dstCode));
                    } else {
                        modifiedSrcToDst.put(funcSignature, funcSignature);
                    }
                    debugPrint("[update/move] One function signature added to modifiedFunctions: " + funcSignature);
                }
            }
        }

        modifiedFunctions.removeAll(removedFunctions);
        }

        String horizontalLine = "+--------------------------------------------------------------------------------------------------------------------------------------------------------—+";
        String titleLine = "|" + " ".repeat((horizontalLine.length() - 2 - "Function Changes".length()) / 2) + "Function Changes" + " ".repeat(horizontalLine.length() - 2 - "Function Changes".length() - (horizontalLine.length() - 2 - "Function Changes".length()) / 2) + "|";

        System.out.println(horizontalLine);
        System.out.println(titleLine);
        System.out.println(horizontalLine);

        if (!addedFunctions.isEmpty()) {
            System.out.println("|>> [Added Functions]" + " ".repeat(Math.max(0, titleLine.length() - "|>> [Added Functions]".length() - 1)) + "|");
            addedFunctions.stream().sorted().forEach(f -> System.out.println("|   + " + f + " ".repeat(Math.max(0, titleLine.length() - ("|   + " + f).length() - 1)) + "|"));
        } else {
            System.out.println("|>> [Added Functions]" + " ".repeat(Math.max(0, titleLine.length() - "|>> [Added Functions]".length() - 1)) + "|");
            System.out.println("|   (None)" + " ".repeat(Math.max(0, titleLine.length() - ("|   (None)").length() - 1)) + "|");
        }
        System.out.println("|" + " ".repeat(titleLine.length() - 2) + "|");

        if (!removedFunctions.isEmpty()) {
            System.out.println("|>> [Removed Functions]" + " ".repeat(Math.max(0, titleLine.length() - "|>> [Removed Functions]".length() - 1)) + "|");
            removedFunctions.stream().sorted().forEach(f -> System.out.println("|   - " + f + " ".repeat(Math.max(0, titleLine.length() - ("|   - " + f).length() - 1)) + "|"));
        } else {
            System.out.println("|>> [Removed Functions]" + " ".repeat(Math.max(0, titleLine.length() - "|>> [Removed Functions]".length() - 1)) + "|");
            System.out.println("|   (None)" + " ".repeat(Math.max(0, titleLine.length() - ("|   (None)").length() - 1)) + "|");
        }
        System.out.println("|" + " ".repeat(titleLine.length() - 2) + "|");

        if (!modifiedFunctions.isEmpty()) {
            System.out.println("|>> [Modified Functions]" + " ".repeat(Math.max(0, titleLine.length() - "|>> [Modified Functions]".length() - 1)) + "|");
            modifiedFunctions.stream().sorted().forEach(f -> System.out.println("|   * " + f + " ".repeat(Math.max(0, titleLine.length() - ("|   * " + f).length() - 1)) + "|"));
        } else {
            System.out.println("|>> [Modified Functions]" + " ".repeat(Math.max(0, titleLine.length() - "|>> [Modified Functions]".length() - 1)) + "|");
            System.out.println("|   (None)" + " ".repeat(Math.max(0, titleLine.length() - ("|   (None)").length() - 1)) + "|");
        }

        Map<String, List<Tree>> rawSrcBySig = buildSignatureIndex(rawSrcFuncs, rawSrcCode);
        Map<String, List<Tree>> rawDstBySig = buildSignatureIndex(rawDstFuncs, rawDstCode);

        List<Map<String, Object>> addedPayload = buildFunctionPayload(addedFunctions, rawDstBySig, rawDstCode);
        List<Map<String, Object>> removedPayload = buildFunctionPayload(removedFunctions, rawSrcBySig, rawSrcCode);
        List<Map<String, Object>> modifiedPayload = buildModifiedPayload(modifiedFunctions, modifiedSrcToDst, rawSrcBySig, rawSrcCode, rawDstBySig, rawDstCode);

        Map<String, Object> jsonResult = new LinkedHashMap<>();

        jsonResult.put("src_path", srcFilePath);
        jsonResult.put("dst_path", dstFilePath);

        jsonResult.put("added", addedPayload);
        jsonResult.put("removed", removedPayload);
        jsonResult.put("modified", modifiedPayload);
        jsonResult.put("is_preprocessed", isPreprocessed);

        Gson gson = new GsonBuilder().disableHtmlEscaping().setPrettyPrinting().create();
        try (FileWriter writer = new FileWriter(outputJsonPath)) {
            gson.toJson(jsonResult, writer);
        }

        System.out.println(horizontalLine);
        System.out.println("| Result written to: " + outputJsonPath + " ".repeat(Math.max(0, titleLine.length() - ("| Result written to: " + outputJsonPath).length() - 1)) + "|");
        System.out.println(horizontalLine);
    }

    private static void debugPrint(String msg) {
        if (DEBUG) {
            System.out.println(msg);
        }
    }

    private static boolean isScopeContainerNode(Tree node) {
        String type = node.getType().name;
        return "namespace".equals(type)
            || "class".equals(type)
            || "struct".equals(type)
            || "union".equals(type);
    }

    private static Map<String, List<Tree>> buildSignatureIndex(List<Tree> funcs, String rawCode) {
        Map<String, List<Tree>> index = new HashMap<>();
        for (Tree func : funcs) {
            String sig = getFunctionSignature(func, rawCode);
            index.computeIfAbsent(sig, k -> new ArrayList<>()).add(func);
        }
        return index;
    }

    private static List<Map<String, Object>> buildFunctionPayload(
            Set<String> signatures,
            Map<String, List<Tree>> index,
            String rawCode) {
        List<Map<String, Object>> payload = new ArrayList<>();
        signatures.stream().sorted().forEach(sig -> {
            Tree best = chooseBestNode(index.get(sig));
            String code = extractNodeCode(best, rawCode);

            Map<String, Object> item = new LinkedHashMap<>();
            item.put("sig", sig);
            item.put("code", code);
            payload.add(item);
        });
        return payload;
    }

    private static List<Map<String, Object>> buildModifiedPayload(
            Set<String> srcSignatures,
            Map<String, String> srcToDst,
            Map<String, List<Tree>> srcIndex,
            String rawSrcCode,
            Map<String, List<Tree>> dstIndex,
            String rawDstCode) {

        Map<String, List<String>> dstShortNameIndex = new HashMap<>();
        for (String sig : dstIndex.keySet()) {
            String shortName = extractFuncShortName(sig);
            if (!shortName.isEmpty()) {
                dstShortNameIndex.computeIfAbsent(shortName, k -> new ArrayList<>()).add(sig);
            }
        }

        List<Map<String, Object>> payload = new ArrayList<>();
        srcSignatures.stream().sorted().forEach(srcSig -> {
            Tree srcBest = chooseBestNode(srcIndex.get(srcSig));
            String code = extractNodeCode(srcBest, rawSrcCode);

            String dstSig = srcToDst.getOrDefault(srcSig, srcSig);
            List<Tree> dstCandidates = dstIndex.get(dstSig);

            if ((dstCandidates == null || dstCandidates.isEmpty())) {
                String shortName = extractFuncShortName(dstSig);
                List<String> matchedSigs = dstShortNameIndex.get(shortName);
                if (matchedSigs != null && matchedSigs.size() == 1) {
                    dstCandidates = dstIndex.get(matchedSigs.get(0));
                } else if (matchedSigs != null && matchedSigs.size() > 1) {

                    String best = matchedSigs.stream()
                        .min(Comparator.comparingInt(s -> editDistance(s, dstSig)))
                        .orElse(null);
                    if (best != null) {
                        dstCandidates = dstIndex.get(best);
                    }
                }
            }

            Tree dstBest = chooseBestNode(dstCandidates);
            String codeAfter = extractNodeCode(dstBest, rawDstCode);

            Map<String, Object> item = new LinkedHashMap<>();
            item.put("sig", srcSig);
            item.put("code", code);
            item.put("code_after", codeAfter);
            payload.add(item);
        });
        return payload;
    }

    private static String extractFuncShortName(String sig) {
        if (sig == null || sig.isBlank()) return "";

        int parenIdx = sig.indexOf('(');
        String nameAndQual = parenIdx >= 0 ? sig.substring(0, parenIdx) : sig;

        int colonIdx = nameAndQual.lastIndexOf(':');
        if (colonIdx >= 0) {
            nameAndQual = nameAndQual.substring(0, colonIdx);
        }

        int dotIdx = nameAndQual.lastIndexOf('.');
        return dotIdx >= 0 ? nameAndQual.substring(dotIdx + 1).trim() : nameAndQual.trim();
    }

    private static int editDistance(String a, String b) {
        int la = a.length(), lb = b.length();
        int[] prev = new int[lb + 1], curr = new int[lb + 1];
        for (int j = 0; j <= lb; j++) prev[j] = j;
        for (int i = 1; i <= la; i++) {
            curr[0] = i;
            for (int j = 1; j <= lb; j++) {
                curr[j] = a.charAt(i - 1) == b.charAt(j - 1)
                    ? prev[j - 1]
                    : 1 + Math.min(prev[j - 1], Math.min(prev[j], curr[j - 1]));
            }
            int[] tmp = prev; prev = curr; curr = tmp;
        }
        return prev[lb];
    }

    private static Tree chooseBestNode(List<Tree> candidates) {
        if (candidates == null || candidates.isEmpty()) {
            return null;
        }

        return candidates.stream()
            .max(Comparator
                .comparingInt(App::bodyPriority)
                .thenComparingInt(App::nodeSpan))
            .orElse(null);
    }

    private static int bodyPriority(Tree node) {
        if (hasBlockChild(node)) {
            return 3;
        }

        String type = node.getType().name;
        if ("function".equals(type)
                || "function_definition".equals(type)
                || "constructor".equals(type)
                || "destructor".equals(type)) {
            return 2;
        }
        if ("function_decl".equals(type)
                || "constructor_decl".equals(type)
                || "destructor_decl".equals(type)) {
            return 1;
        }
        return 0;
    }

    private static boolean hasBlockChild(Tree node) {
        if (node == null) {
            return false;
        }
        for (Tree child : node.getChildren()) {
            if ("block".equals(child.getType().name)) {
                return true;
            }
        }
        return false;
    }

    private static int nodeSpan(Tree node) {
        if (node == null) {
            return -1;
        }
        return Math.max(0, node.getEndPos() - node.getPos());
    }

    private static String extractNodeCode(Tree node, String rawCode) {
        if (node == null || rawCode == null) {
            return null;
        }

        int start = node.getPos();
        int end = node.getEndPos();
        if (start < 0 || end <= start || end > rawCode.length()) {
            return null;
        }
        return rawCode.substring(start, end);
    }

}

