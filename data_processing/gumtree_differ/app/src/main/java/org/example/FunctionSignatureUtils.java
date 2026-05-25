package org.example;

import com.github.gumtreediff.tree.Tree;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public class FunctionSignatureUtils {

    private static final String ANON_SCOPE_TAG = "__anon__";

    public static boolean isFunctionNode(Tree node) {
        String type = node.getType().name;
        return type.equals("function")
            || type.equals("function_definition")
            || type.equals("function_decl")
            || type.equals("constructor")
            || type.equals("destructor")
            || type.equals("constructor_decl")
            || type.equals("destructor_decl");
    }

    private static boolean isCtorOrDtorNodeType(String nodeType) {
        return nodeType.equals("constructor")
            || nodeType.equals("destructor")
            || nodeType.equals("constructor_decl")
            || nodeType.equals("destructor_decl");
    }

    public static Tree findEnclosingFunction(Tree node) {
        Tree cur = node;
        while (cur != null) {
            if (isFunctionNode(cur)) {
                return cur;
            }
            cur = cur.getParent();
        }
        return null;
    }

    public static Tree findFunctionByPosition(List<Tree> functions, Tree node) {
        if (node == null) return null;
        int nodePos = node.getPos();
        int nodeEnd = node.getEndPos();

        Tree best = null;
        int bestSpan = Integer.MAX_VALUE;
        for (Tree func : functions) {
            int funcPos = func.getPos();
            int funcEnd = func.getEndPos();
            if (funcPos <= nodePos && nodeEnd <= funcEnd) {
                int span = funcEnd - funcPos;
                if (span < bestSpan) {
                    best = func;
                    bestSpan = span;
                }
            }
        }
        return best;
    }

    public static Tree findNearestFunctionByPosition(List<Tree> functions, Tree node) {
        if (node == null || functions.isEmpty()) return null;
        int nodePos = node.getPos();

        Tree nearestBefore = null;
        int bestBeforePos = Integer.MIN_VALUE;
        Tree nearestAfter = null;
        int bestAfterPos = Integer.MAX_VALUE;

        for (Tree func : functions) {
            int funcPos = func.getPos();
            if (funcPos <= nodePos && funcPos > bestBeforePos) {
                nearestBefore = func;
                bestBeforePos = funcPos;
            }
            if (funcPos > nodePos && funcPos < bestAfterPos) {
                nearestAfter = func;
                bestAfterPos = funcPos;
            }
        }

        return nearestBefore != null ? nearestBefore : nearestAfter;
    }

    public static String resolveName(Tree node) {
        if (node.getChildren().isEmpty()) {
            return node.getLabel();
        }
        StringBuilder sb = new StringBuilder();
        for (Tree child : node.getChildren()) {
            String part = resolveName(child);
            if (!part.isEmpty()) {
                if (sb.length() > 0 && !part.equals("::")) {
                    sb.append("::");
                }
                sb.append(part);
            }
        }
        return sb.length() == 0 ? node.getLabel() : sb.toString();
    }

    public static String getFunctionName(Tree functionNode) {
        for (Tree child : functionNode.getChildren()) {
            if (child.getType().name.equals("name")) {
                String name = resolveName(child);

                return name.replaceAll(":+", "::");
            }
        }
        return "<anonymous>";
    }

    public static String getFunctionSignature(Tree functionNode) {
        return getFunctionSignature(functionNode, null);
    }

    public static String getFunctionSignature(Tree functionNode, String sourceCode) {
        String nodeType = functionNode.getType().name;
        String returnTypeFromAst = "";
        String functionName = "";
        StringBuilder params = new StringBuilder();

        for (Tree child : functionNode.getChildren()) {
            String typeName = child.getType().name;

            if (typeName.equals("type") && !isCtorOrDtorNodeType(nodeType)) {
                returnTypeFromAst = parseType(child);
            }

            else if (typeName.equals("name")) {
                functionName = parseQualifiedName(child);
            }

            else if (typeName.equals("parameter_list")) {
                params.append(parseParameterList(child));
            }
        }

        String namespacePrefix = extractEnclosingNamespace(functionNode, sourceCode);
        String typePrefix = extractEnclosingType(functionNode, sourceCode);
        String scopePrefix = joinScope(namespacePrefix, typePrefix);
        if (!scopePrefix.isEmpty() && !functionName.isEmpty()
                && !functionName.startsWith(scopePrefix + "::")) {
            functionName = scopePrefix + "::" + functionName;
        }

        functionName = toDotQualified(functionName);
        String paramsText = normalizeParams(params.toString());

        if (isCtorOrDtorNodeType(nodeType)) {
            return String.format("%s:(%s)", functionName, paramsText);
        }

        String returnType = returnTypeFromAst;
        if (shouldPreferSourceReturnType(returnTypeFromAst)) {
            String fromSource = extractReturnTypeFromSource(functionNode, sourceCode);
            if (isCompatibleReturnTypeHint(returnTypeFromAst, fromSource)) {
                returnType = fromSource;
            }
        }
        returnType = normalizeType(returnType);

        return String.format("%s:%s(%s)", functionName, returnType, paramsText);
    }

    private static String toDotQualified(String name) {
        if (name == null || name.isEmpty()) return "<anonymous>";
        return name.replaceAll("::", ".").replaceAll("\\.+", ".");
    }

    private static String normalizeType(String type) {
        if (type == null) return "";
        String t = type.trim().replaceAll("\\s+", " ");
        t = t.replaceAll("::", ".").replaceAll("\\.+", ".");
        t = t.replaceFirst("^\\.", "");
        return t;
    }

    private static String extractReturnTypeFromSource(Tree functionNode, String sourceCode) {
        if (sourceCode == null || sourceCode.isEmpty()) return "";

        Tree nameNode = null;
        for (Tree child : functionNode.getChildren()) {
            if ("name".equals(child.getType().name)) {
                nameNode = child;
                break;
            }
        }
        if (nameNode == null) return "";

        int start = functionNode.getPos();
        int end = nameNode.getPos();
        if (start < 0 || end <= start || end > sourceCode.length()) return "";

        String text = sourceCode.substring(start, end);
        if (text.startsWith("::") && start > 0 && isIdentifierChar(sourceCode.charAt(start - 1))) {
            int i = start - 1;
            while (i >= 0 && isIdentifierChar(sourceCode.charAt(i))) {
                i--;
            }
            String prefix = sourceCode.substring(i + 1, start);
            if (!prefix.isEmpty()) {
                text = prefix + text;
            }
        }
        return text.trim().replaceAll("\\s+", " ");
    }

    private static boolean shouldPreferSourceReturnType(String returnTypeFromAst) {
        if (returnTypeFromAst == null) return true;
        String t = returnTypeFromAst.trim();
        if (t.isEmpty()) return true;
        return t.startsWith("::");
    }

    private static boolean isCompatibleReturnTypeHint(String astType, String sourceType) {
        if (sourceType == null || sourceType.trim().isEmpty()) return false;
        if (astType == null) return true;

        String astTail = astType.trim().replaceFirst("^:+", "");
        if (astTail.isEmpty()) return true;

        String sourceNorm = normalizeType(sourceType);
        String astTailNorm = normalizeType(astTail);
        return sourceNorm.contains(astTailNorm);
    }

    private static boolean isIdentifierChar(char c) {
        return Character.isLetterOrDigit(c) || c == '_';
    }

    private static String normalizeParams(String params) {
        if (params == null || params.trim().isEmpty()) return "";
        String[] parts = params.split(",");
        StringBuilder out = new StringBuilder();
        for (String part : parts) {
            if (out.length() > 0) out.append(",");
            out.append(normalizeType(part));
        }
        return out.toString();
    }

    private static String joinScope(String left, String right) {
        if (left == null || left.isEmpty()) return right == null ? "" : right;
        if (right == null || right.isEmpty()) return left;
        return left + "::" + right;
    }

    private static String extractEnclosingNamespace(Tree node, String sourceCode) {
        int funcPos = node.getPos();
        int funcEnd = node.getEndPos();
        Tree root = node;
        while (root.getParent() != null) {
            root = root.getParent();
        }

        List<Tree> matched = new ArrayList<>();
        for (Tree t : root.preOrder()) {
            if (!"namespace".equals(t.getType().name)) continue;
            if (t.getPos() <= funcPos && funcEnd <= t.getEndPos()) {
                matched.add(t);
            }
        }

        matched.sort((a, b) -> Integer.compare(a.getPos(), b.getPos()));

        List<String> parts = new ArrayList<>();
        for (Tree ns : matched) {
            String name = "";
            for (Tree child : ns.getChildren()) {
                if ("name".equals(child.getType().name)) {
                    name = parseQualifiedName(child);
                    break;
                }
            }
            if (!name.isEmpty()) {
                parts.add(name);
            } else {
                parts.add(ANON_SCOPE_TAG);
            }
        }

        String astNamespace = String.join("::", parts);
        String sourceNamespace = extractNamespaceFromSource(sourceCode, funcPos);

        if (!sourceNamespace.isEmpty()) {
            if (astNamespace.isEmpty()) {
                return sourceNamespace;
            }
            if (!sourceNamespace.equals(astNamespace)
                    && (sourceNamespace.endsWith("::" + astNamespace)
                        || countScopeSegments(sourceNamespace) > countScopeSegments(astNamespace))) {
                return sourceNamespace;
            }
        }

        return astNamespace;
    }

    private static int countScopeSegments(String scope) {
        if (scope == null || scope.isEmpty()) return 0;
        return scope.split("::").length;
    }

    private static String extractNamespaceFromSource(String sourceCode, int funcPos) {
        if (sourceCode == null || sourceCode.isEmpty() || funcPos <= 0 || funcPos > sourceCode.length()) {
            return "";
        }

        int depth = 0;
        List<String> nsStack = new ArrayList<>();
        List<Integer> nsDepthStack = new ArrayList<>();

        int i = 0;
        while (i < funcPos) {
            char c = sourceCode.charAt(i);

            if (Character.isLetter(c) || c == '_') {
                int tokenStart = i;
                i++;
                while (i < funcPos) {
                    char ch = sourceCode.charAt(i);
                    if (!Character.isLetterOrDigit(ch) && ch != '_') break;
                    i++;
                }
                String token = sourceCode.substring(tokenStart, i);
                if ("namespace".equals(token)) {
                    int j = i;
                    while (j < funcPos && Character.isWhitespace(sourceCode.charAt(j))) j++;

                    int nameStart = j;
                    while (j < funcPos) {
                        char ch = sourceCode.charAt(j);
                        boolean ok = Character.isLetterOrDigit(ch) || ch == '_' || ch == ':';
                        if (!ok) break;
                        j++;
                    }
                    String nsName = sourceCode.substring(nameStart, j).trim();

                    while (j < funcPos && Character.isWhitespace(sourceCode.charAt(j))) j++;

                    if (j < funcPos && sourceCode.charAt(j) == '{') {
                        depth++;
                        if (!nsName.isEmpty()) {
                            nsStack.add(nsName);
                        } else {
                            nsStack.add(ANON_SCOPE_TAG);
                        }
                        nsDepthStack.add(depth);
                        i = j + 1;
                        continue;
                    }
                }
                continue;
            }

            if (c == '{') {
                depth++;
            } else if (c == '}') {
                if (!nsDepthStack.isEmpty() && nsDepthStack.get(nsDepthStack.size() - 1) == depth) {
                    nsDepthStack.remove(nsDepthStack.size() - 1);
                    nsStack.remove(nsStack.size() - 1);
                }
                depth = Math.max(0, depth - 1);
            }

            i++;
        }

        if (nsStack.isEmpty()) return "";
        StringBuilder out = new StringBuilder();
        for (String part : nsStack) {
            if (part == null || part.isEmpty()) continue;
            if (out.length() > 0) out.append("::");
            out.append(part);
        }
        return out.toString();
    }

    private static String extractEnclosingType(Tree node, String sourceCode) {
        int funcPos = node.getPos();
        int funcEnd = node.getEndPos();
        Tree root = node;
        while (root.getParent() != null) {
            root = root.getParent();
        }

        List<Tree> matched = new ArrayList<>();
        for (Tree t : root.preOrder()) {
            String type = t.getType().name;
            if (!"class".equals(type) && !"struct".equals(type) && !"union".equals(type)) continue;
            if (t.getPos() <= funcPos && funcEnd <= t.getEndPos()) {
                matched.add(t);
            }
        }

        matched.sort((a, b) -> Integer.compare(a.getPos(), b.getPos()));
        List<String> parts = new ArrayList<>();
        for (Tree n : matched) {
            String name = "";
            for (Tree child : n.getChildren()) {
                if ("name".equals(child.getType().name)) {
                    name = parseQualifiedName(child);
                    break;
                }
            }
            if (!name.isEmpty()) {
                parts.add(name);
            } else {
                parts.add(ANON_SCOPE_TAG);
            }
        }

        String astType = String.join("::", parts);
        String sourceType = extractTypeFromSource(sourceCode, funcPos);

        if (!sourceType.isEmpty()) {
            if (astType.isEmpty()) {
                return sourceType;
            }
            if (!sourceType.equals(astType)
                    && (sourceType.endsWith("::" + astType)
                        || astType.endsWith("::" + sourceType)
                        || countScopeSegments(sourceType) > countScopeSegments(astType))) {
                return sourceType;
            }
        }

        return astType;
    }

    private static String extractTypeFromSource(String sourceCode, int funcPos) {
        if (sourceCode == null || sourceCode.isEmpty() || funcPos <= 0 || funcPos > sourceCode.length()) {
            return "";
        }

        int depth = 0;
        List<String> typeStack = new ArrayList<>();
        List<Integer> typeDepthStack = new ArrayList<>();

        int i = 0;
        while (i < funcPos) {
            char c = sourceCode.charAt(i);

            if (Character.isLetter(c) || c == '_') {
                int tokenStart = i;
                i++;
                while (i < funcPos) {
                    char ch = sourceCode.charAt(i);
                    if (!Character.isLetterOrDigit(ch) && ch != '_') break;
                    i++;
                }
                String token = sourceCode.substring(tokenStart, i);
                if ("class".equals(token) || "struct".equals(token) || "union".equals(token)) {
                    int j = i;
                    while (j < funcPos && Character.isWhitespace(sourceCode.charAt(j))) j++;

                    int nameStart = j;
                    while (j < funcPos) {
                        char ch = sourceCode.charAt(j);
                        if (!Character.isLetterOrDigit(ch) && ch != '_') break;
                        j++;
                    }
                    String typeName = sourceCode.substring(nameStart, j).trim();

                    while (j < funcPos && sourceCode.charAt(j) != '{' && sourceCode.charAt(j) != ';') j++;
                    if (j < funcPos && sourceCode.charAt(j) == '{') {
                        depth++;
                        if (!typeName.isEmpty()) {
                            typeStack.add(typeName);
                        } else {
                            typeStack.add(ANON_SCOPE_TAG);
                        }
                        typeDepthStack.add(depth);
                        i = j + 1;
                        continue;
                    }
                }
                continue;
            }

            if (c == '{') {
                depth++;
            } else if (c == '}') {
                if (!typeDepthStack.isEmpty() && typeDepthStack.get(typeDepthStack.size() - 1) == depth) {
                    typeDepthStack.remove(typeDepthStack.size() - 1);
                    typeStack.remove(typeStack.size() - 1);
                }
                depth = Math.max(0, depth - 1);
            }
            i++;
        }

        if (typeStack.isEmpty()) return "";
        return String.join("::", typeStack);
    }

    private static List<String> parseMultiDeclStmt(Tree declStmt) {
        List<String> functions = new ArrayList<>();

        for (Tree decl : declStmt.getChildren()) {
            if (!"decl".equals(decl.getType().name)) continue;

            int i = 0;

            if (i < decl.getChildren().size() && "type".equals(decl.getChildren().get(i).getType().name)) {
                Tree typeNode = decl.getChildren().get(i++);
                Tree maybeMacro = decl.getChildren().get(i++);
                Tree maybeArgList = decl.getChildren().get(i++);

                StringBuilder tmp = new StringBuilder();
                for (Tree t : typeNode.getChildren()) {
                    if (!"macro".equals(t.getType().name)) {
                        tmp.append(parseType(t)).append(" ");
                    }
                }
                String returnType = tmp.toString().trim();
                if (!returnType.contains("virtual")) {
                    returnType = "virtual " + returnType;
                }

                for (Tree t : typeNode.getChildren()) {
                    if ("macro".equals(t.getType().name)) {
                        String functionName = "";
                        StringBuilder params = new StringBuilder();
                        for (Tree macroChild : t.getChildren()) {
                            if ("name".equals(macroChild.getType().name)) {
                                functionName = macroChild.getLabel();
                            } else if ("argument_list".equals(macroChild.getType().name)) {
                                params.append(parseParameterListLikeArgumentList(macroChild));
                            }
                        }
                        functions.add(returnType + " " + functionName + "(" + params.toString() + ")");
                    }
                }
            }

            while (i + 4 < decl.getChildren().size()) {
                Tree returnName = decl.getChildren().get(i++);
                Tree funcNameNode = decl.getChildren().get(i++);
                Tree argList = decl.getChildren().get(i++);
                Tree maybeMacro = decl.getChildren().get(i++);
                Tree maybeArgList = decl.getChildren().get(i++);

                if (!"name".equals(returnName.getType().name) ||
                    !"name".equals(funcNameNode.getType().name) ||
                    !"argument_list".equals(argList.getType().name)) {
                    continue;
                }

                String returnType = returnName.getLabel();
                String funcName = funcNameNode.getLabel();
                functions.add(returnType + " " + funcName + "(" + parseParameterListLikeArgumentList(argList) + ")");
            }
        }
        return functions;
    }

    private static String parseParameterListLikeArgumentList(Tree argListNode) {
        return parseParameterListLikeArgumentList(argListNode, null);
    }

    private static String parseParameterListLikeArgumentList(Tree argListNode, String sourceCode) {
        StringBuilder params = new StringBuilder();

        for (Tree arg : argListNode.getChildren()) {
            if (arg.getType().name.equals("argument")) {
                String text = "";

                if (sourceCode != null && !sourceCode.isEmpty()) {
                    int pos = arg.getPos();
                    int end = arg.getEndPos();
                    if (pos >= 0 && end > pos && end <= sourceCode.length()) {
                        String rawArgText = sourceCode.substring(pos, end);
                        text = extractTypeFromParameterText(rawArgText);
                    }
                }

                if (text.isEmpty()) {
                    text = parseType(arg).trim();
                }

                if (text.isEmpty()) {
                    text = "auto";
                }
                if (!text.isEmpty()) {
                    if (params.length() > 0) params.append(", ");
                    params.append(text);
                }
            }
        }
        return params.toString();
    }

    private static String extractTypeFromParameterText(String rawArgText) {
        if (rawArgText == null) return "";
        String t = rawArgText.trim().replaceAll("\\s+", " ");
        if (t.isEmpty()) return "";

        int eq = t.indexOf('=');
        if (eq >= 0) {
            t = t.substring(0, eq).trim();
        }

        t = t.replaceAll("\\s*\\[[^\\]]*\\]$", "").trim();
        if (t.equals("void")) return "void";

        String removed = t.replaceFirst("^(.*\\S)\\s+[A-Za-z_][A-Za-z0-9_]*$", "$1");
        if (!removed.equals(t)) {
            t = removed.trim();
        }

        return t;
    }

    private static String parseQualifiedName(Tree nameNode) {

        if (nameNode.getLabel() != null && !nameNode.getLabel().isEmpty()) {
            return nameNode.getLabel();
        }

        StringBuilder result = new StringBuilder();
        for (Tree sub : nameNode.getChildren()) {
            if (sub.getType().name.equals("name")) {
                if (result.length() > 0) result.append("::");
                result.append(parseQualifiedName(sub));
            } else if (sub.getType().name.equals("operator") && "::".equals(sub.getLabel())) {

            }
        }
        return result.toString();
    }

    private static String parseParameterList(Tree paramListNode) {
        StringBuilder params = new StringBuilder();
        for (Tree param : paramListNode.getChildren()) {
            if (param.getType().name.equals("parameter")) {
                for (Tree decl : param.getChildren()) {
                    if (decl.getType().name.equals("decl")) {
                        for (Tree typeNode : decl.getChildren()) {
                            if (typeNode.getType().name.equals("type")) {
                                if (params.length() > 0) params.append(", ");
                                params.append(parseType(typeNode).trim());
                            }
                        }
                    }
                }
            }
        }
        return params.toString();
    }

    private static String parseType(Tree typeNode) {

        if (typeNode.getLabel() != null && !typeNode.getLabel().isEmpty()) {
            return typeNode.getLabel();
        }

        StringBuilder typeStr = new StringBuilder();
        boolean lastWasScope = false;

        for (Tree sub : typeNode.getChildren()) {
            String typeName = sub.getType().name;
            String label = sub.getLabel() != null ? sub.getLabel() : "";

            if ("::".equals(label)) {

                typeStr.append("::");
                lastWasScope = true;
            } else if (label.equals("*") || label.equals("&") || label.equals("&&")) {

                typeStr.append(label);
                lastWasScope = false;
            } else if (typeName.equals("argument_list")) {

                StringBuilder args = new StringBuilder();
                for (Tree arg : sub.getChildren()) {
                    if (arg.getType().name.equals("argument")) {
                        for (Tree expr : arg.getChildren()) {
                            String argText = parseType(expr).trim();
                            if (!argText.isEmpty()) {
                                args.append(argText).append(", ");
                            }
                        }
                    }
                }
                if (args.length() > 2) {
                    args.setLength(args.length() - 2);
                }
                typeStr.append("<").append(args).append(">");
                lastWasScope = false;
            } else {
                String nested = parseType(sub);
                if (!label.isEmpty()) {
                    if (typeStr.length() > 0 && !lastWasScope) typeStr.append(" ");
                    typeStr.append(label);
                    lastWasScope = false;
                } else if (!nested.isEmpty()) {
                    if (typeStr.length() > 0) typeStr.append(" ");
                    typeStr.append(nested);
                    lastWasScope = false;
                }
            }
        }
        return typeStr.toString();
    }

    public static void collectFunctionsRecursively(Tree node, Set<String> result) {
        collectFunctionsRecursively(node, result, null);
    }

    public static void collectFunctionsRecursively(Tree node, Set<String> result, String sourceCode) {
        if (isFunctionNode(node)) {
            result.add(getFunctionSignature(node, sourceCode));
            return;
        }
        if (isMethodLikeMacroNode(node)) {
            String sig = getMethodLikeSignature(node, sourceCode);
            if (!sig.isEmpty()) {
                result.add(sig);
            }
        }
        for (Tree child : node.getChildren()) {
            collectFunctionsRecursively(child, result, sourceCode);
        }
    }

    private static boolean isMethodLikeMacroNode(Tree node) {
        if (!"macro".equals(node.getType().name)) return false;
        if (findEnclosingFunction(node) != null) return false;
        if (!hasClassLikeAncestor(node)) return false;

        boolean hasName = false;
        boolean hasArgList = false;
        for (Tree child : node.getChildren()) {
            if ("name".equals(child.getType().name) && child.getLabel() != null && !child.getLabel().isEmpty()) {
                hasName = true;
            } else if ("argument_list".equals(child.getType().name)) {
                hasArgList = true;
            }
        }
        if (!hasName || !hasArgList) return false;

        Tree parent = node.getParent();
        if (parent == null) return false;
        List<Tree> siblings = parent.getChildren();
        int idx = siblings.indexOf(node);
        if (idx < 0) return false;

        for (int i = idx + 1; i < siblings.size(); i++) {
            Tree s = siblings.get(i);
            String t = s.getType().name;
            if ("block".equals(t)) return true;
            if ("macro".equals(t) || "expr".equals(t) || "decl".equals(t) || "decl_stmt".equals(t)) return false;
        }
        return false;
    }

    private static String getMethodLikeSignature(Tree macroNode, String sourceCode) {
        String functionName = "";
        String paramsText = "";
        for (Tree child : macroNode.getChildren()) {
            if ("name".equals(child.getType().name)) {
                functionName = parseQualifiedName(child);
            } else if ("argument_list".equals(child.getType().name)) {
                paramsText = normalizeParams(parseParameterListLikeArgumentList(child, sourceCode));
            }
        }
        if (functionName.isEmpty()) return "";

        String namespacePrefix = extractEnclosingNamespace(macroNode, sourceCode);
        String typePrefix = extractEnclosingType(macroNode, sourceCode);
        String scopePrefix = joinScope(namespacePrefix, typePrefix);
        if (!scopePrefix.isEmpty() && !functionName.startsWith(scopePrefix + "::")) {
            functionName = scopePrefix + "::" + functionName;
        }

        String fullName = toDotQualified(functionName);
        String returnType = normalizeType(inferMethodLikeReturnType(macroNode));

        if (isCtorOrDtorLikeName(functionName, typePrefix)) {
            return String.format("%s:(%s)", fullName, paramsText);
        }
        if (returnType.isEmpty()) {
            returnType = "unknown";
        }
        return String.format("%s:%s(%s)", fullName, returnType, paramsText);
    }

    private static boolean hasClassLikeAncestor(Tree node) {
        Tree cur = node.getParent();
        while (cur != null) {
            String t = cur.getType().name;
            if ("class".equals(t) || "struct".equals(t) || "union".equals(t)) return true;
            cur = cur.getParent();
        }
        return false;
    }

    private static String inferMethodLikeReturnType(Tree macroNode) {
        Tree parent = macroNode.getParent();
        if (parent == null) return "";
        List<Tree> siblings = parent.getChildren();
        int idx = siblings.indexOf(macroNode);
        if (idx <= 0) return "";

        Tree prev = siblings.get(idx - 1);
        if ("name".equals(prev.getType().name) || "type".equals(prev.getType().name)) {
            String t = parseType(prev).trim();
            if (!isAccessSpecifier(t)) {
                return t;
            }
        }
        return "";
    }

    private static boolean isAccessSpecifier(String t) {
        return "public".equals(t) || "protected".equals(t) || "private".equals(t);
    }

    private static boolean isCtorOrDtorLikeName(String functionName, String typePrefix) {
        String simpleName = functionName;
        int i = functionName.lastIndexOf("::");
        if (i >= 0 && i + 2 < functionName.length()) {
            simpleName = functionName.substring(i + 2);
        }
        if (simpleName.startsWith("~")) return true;

        if (typePrefix == null || typePrefix.isEmpty()) return false;
        String enclosingType = typePrefix;
        int j = typePrefix.lastIndexOf("::");
        if (j >= 0 && j + 2 < typePrefix.length()) {
            enclosingType = typePrefix.substring(j + 2);
        }
        return simpleName.equals(enclosingType);
    }

}
