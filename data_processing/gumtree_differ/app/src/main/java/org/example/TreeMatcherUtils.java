package org.example;

import com.github.gumtreediff.tree.Tree;

import java.util.*;
import java.util.stream.Collectors;

public class TreeMatcherUtils {

    public static class Match {
        public final Tree x;
        public final Tree y;
        public final double score;
        public Match(Tree x, Tree y, double score) {
            this.x = x; this.y = y; this.score = score;
        }
        @Override public String toString() {
            return "Match{" + x + " <-> " + y + ", score=" + score + "}";
        }
    }

    private static final double LEAF_SEED_THRESHOLD = 0.50;

    private static final double BASE_THRESHOLD = 0.60;

    private static final double THR_A_LOG_SIZE = 0.05;
    private static final double THR_B_DEPTH    = 0.02;
    private static final double THR_MIN        = 0.40;
    private static final double THR_MAX        = 0.70;

    private static final double CHILD_OVERLAP_BOOST = 0.15;

    private static final double W_NAME   = 0.30;
    private static final double W_COUNT  = 0.40;
    private static final double W_TOPO   = 0.30;

    private static final double LEVENSHTEIN_THRESHOLD = 0.50;
    private static final double NAME_STRICT = 0.85;
    private static final double NAME_WEAK   = 0.70;
    private static final double SIZE_RATIO_MIN = 0.30;
    private static final double KEEP_RULE1_COVER = 0.35;
    private static final double KEEP_RULE2_COVER = 0.55;
    private static final double KEEP_RULE3_COVER = 0.40;
    private static final double FUSION_KEEP_THRESHOLD = 0.60;

    public static List<Match> matchTrees(Tree t1, Tree t2) {
        List<Match> M_final = new ArrayList<>();
        List<Cand> M_tmp = new ArrayList<>();

        Set<Tree> matched1 = new HashSet<>();
        Set<Tree> matched2 = new HashSet<>();
        Map<Tree, Tree> map12 = new IdentityHashMap<>();
        Map<Tree, Tree> map21 = new IdentityHashMap<>();

        List<Tree> leaves1 = collectLeaves(t1);
        Map<String, List<Tree>> leaves2Buckets = collectLeavesByType(t2);

        for (Tree x : leaves1) {
            List<Tree> ys = leaves2Buckets.getOrDefault(x.getType().name, Collections.emptyList());
            for (Tree y : ys) {
                double s = similarityScore(x, y);
                if (s >= LEAF_SEED_THRESHOLD) {
                    M_tmp.add(new Cand(x, y, s));
                }
            }
        }

        M_tmp.sort((a, b) -> Double.compare(b.s, a.s));

        for (Cand c : M_tmp) {
            if (matched1.contains(c.x) || matched2.contains(c.y)) continue;
            pick(c.x, c.y, c.s, matched1, matched2, map12, map21, M_final);
        }

        List<Tree> postOrder1 = postOrder(t1);
        Map<String, List<Tree>> allNodes2ByType = indexAllNodesByType(t2);

        for (Tree x : postOrder1) {
            if (matched1.contains(x)) continue;
            List<Tree> candidates = allNodes2ByType.getOrDefault(x.getType().name, Collections.emptyList());

            Cand best = null;
            double thr = dynamicThreshold(x);
            for (Tree y : candidates) {
                if (matched2.contains(y)) continue;

                double base = similarityScore(x, y);
                double overlap = childOverlap(x, y, map12);
                double s = base + CHILD_OVERLAP_BOOST * overlap;

                if (s >= thr && (best == null || s > best.s)) {
                    best = new Cand(x, y, s);
                }
            }

            if (best != null) {
                pick(best.x, best.y, best.s, matched1, matched2, map12, map21, M_final);
            }
        }

        return M_final;
    }

    public static boolean areSubtreesSimilar(Tree srcFunc, Tree dstFunc) {

        if (!Objects.equals(srcFunc.getType().name, dstFunc.getType().name)) return false;

        String nameA = extractStableName(srcFunc);
        String nameB = extractStableName(dstFunc);
        double nameSim = labelSimilarity(nameA, nameB);

        if (nameSim < Math.max(0.0, Math.min(1.0, 0.8 * LEVENSHTEIN_THRESHOLD))) {

        }

        Tree bodyA = firstChildByType(srcFunc, "block");
        Tree bodyB = firstChildByType(dstFunc, "block");
        if (bodyA == null) bodyA = srcFunc;
        if (bodyB == null) bodyB = dstFunc;

        int sizeA = countNodes(bodyA);
        int sizeB = countNodes(bodyB);
        double sizeRatio = (double) Math.min(sizeA, sizeB) / Math.max(sizeA, sizeB);

        List<Match> matches = matchTrees(bodyA, bodyB);
        Set<Tree> matchedA = new HashSet<>();
        Set<Tree> matchedB = new HashSet<>();
        for (Match m : matches) {
            matchedA.add(m.x);
            matchedB.add(m.y);
        }
        double coverA = sizeA == 0 ? 1.0 : (double) matchedA.size() / sizeA;
        double coverB = sizeB == 0 ? 1.0 : (double) matchedB.size() / sizeB;
        double cover  = Math.min(coverA, coverB);

        boolean keep = false;

        if (nameSim >= Math.max(NAME_STRICT, LEVENSHTEIN_THRESHOLD)
                && cover >= KEEP_RULE1_COVER
                && sizeRatio >= SIZE_RATIO_MIN) {
            keep = true;
        }

        else if (cover >= KEEP_RULE2_COVER && sizeRatio >= SIZE_RATIO_MIN) {
            keep = true;
        }

        else if (nameSim >= Math.max(NAME_WEAK, 0.5 * LEVENSHTEIN_THRESHOLD)
                && sizeRatio >= 0.50
                && cover >= KEEP_RULE3_COVER) {
            keep = true;
        }

        else {
            double fusion = 0.45 * nameSim + 0.15 * sizeRatio + 0.40 * cover;
            keep = fusion >= FUSION_KEEP_THRESHOLD;
        }

        return keep;
    }

    public static double similarityScore(Tree a, Tree b) {

        String ta = a.getType().name;
        String tb = b.getType().name;
        if (!Objects.equals(ta, tb)) return 0.0;

        double nameSim = labelSimilarity(extractStableName(a), extractStableName(b));
        double countSim = multisetNodeTypeJaccard(a, b);
        double topoSim  = parentChildBigramJaccard(a, b);

        return clamp01(W_NAME * nameSim + W_COUNT * countSim + W_TOPO * topoSim);
    }

    private static String extractStableName(Tree t) {
        String lab = safeNorm(t.getLabel());
        if (!lab.isEmpty()) return lab;
        Tree nameNode = firstDescendantByType(t, "name");
        return nameNode != null ? safeNorm(nameNode.getLabel()) : "";
    }

    private static double labelSimilarity(String a, String b) {
        if (a.isEmpty() && b.isEmpty()) return 0.6;
        if (a.isEmpty() || b.isEmpty()) return 0.5;
        String aa = a.toLowerCase(Locale.ROOT);
        String bb = b.toLowerCase(Locale.ROOT);
        if (aa.equals(bb)) return 1.0;
        if (aa.contains(bb) || bb.contains(aa)) return 0.9;
        int d = levenshtein(aa, bb);
        return clamp01(1.0 - (double) d / Math.max(aa.length(), bb.length()));
    }

    private static double multisetNodeTypeJaccard(Tree a, Tree b) {
        Map<String, Integer> ca = countNodeTypes(a);
        Map<String, Integer> cb = countNodeTypes(b);
        if (ca.isEmpty() && cb.isEmpty()) return 1.0;
        long inter = 0, uni = 0;
        Set<String> keys = new HashSet<>(ca.keySet());
        keys.addAll(cb.keySet());
        for (String k : keys) {
            int va = ca.getOrDefault(k, 0);
            int vb = cb.getOrDefault(k, 0);
            inter += Math.min(va, vb);
            uni   += Math.max(va, vb);
        }
        return uni == 0 ? 1.0 : (double) inter / (double) uni;
    }

    private static double parentChildBigramJaccard(Tree a, Tree b) {
        Set<String> pa = parentChildPairs(a);
        Set<String> pb = parentChildPairs(b);
        if (pa.isEmpty() && pb.isEmpty()) return 1.0;
        Set<String> inter = new HashSet<>(pa); inter.retainAll(pb);
        Set<String> uni   = new HashSet<>(pa); uni.addAll(pb);
        return (double) inter.size() / (double) uni.size();
    }

    private static double dynamicThreshold(Tree x) {
        int size  = countNodes(x);
        int depth = depthOf(x);
        double t = BASE_THRESHOLD
                - THR_A_LOG_SIZE * Math.log(Math.max(1, size))
                - THR_B_DEPTH    * Math.min(16, Math.max(0, depth));
        return clamp(t, THR_MIN, THR_MAX);
    }

    private static double childOverlap(Tree x, Tree y, Map<Tree, Tree> map12) {
        if (x.getChildren().isEmpty() && y.getChildren().isEmpty()) return 1.0;
        Set<Tree> mappedFromX =
                x.getChildren().stream().map(map12::get).filter(Objects::nonNull).collect(Collectors.toSet());
        if (mappedFromX.isEmpty()) return 0.0;
        Set<Tree> setYChildren = new HashSet<>(y.getChildren());
        int inter = 0;
        for (Tree t : mappedFromX) if (setYChildren.contains(t)) inter++;
        int uni = setYChildren.size() + mappedFromX.size() - inter;
        return uni == 0 ? 0.0 : (double) inter / (double) uni;
    }

    private static class Cand {
        final Tree x, y; final double s;
        Cand(Tree x, Tree y, double s) { this.x = x; this.y = y; this.s = s; }
    }

    private static void pick(
            Tree x, Tree y, double s,
            Set<Tree> matched1, Set<Tree> matched2,
            Map<Tree, Tree> map12, Map<Tree, Tree> map21,
            List<Match> M_final
    ) {
        matched1.add(x);
        matched2.add(y);
        map12.put(x, y);
        map21.put(y, x);
        M_final.add(new Match(x, y, s));
    }

    private static List<Tree> collectLeaves(Tree root) {
        List<Tree> out = new ArrayList<>();
        Deque<Tree> dq = new ArrayDeque<>();
        dq.add(root);
        while (!dq.isEmpty()) {
            Tree t = dq.pollFirst();
            List<Tree> ch = t.getChildren();
            if (ch.isEmpty()) out.add(t);
            else dq.addAll(ch);
        }
        return out;
    }

    private static Map<String, List<Tree>> collectLeavesByType(Tree root) {
        Map<String, List<Tree>> m = new HashMap<>();
        for (Tree leaf : collectLeaves(root)) {
            m.computeIfAbsent(leaf.getType().name, k -> new ArrayList<>()).add(leaf);
        }
        return m;
    }

    private static List<Tree> postOrder(Tree root) {
        List<Tree> out = new ArrayList<>();
        Deque<Tree> st = new ArrayDeque<>();
        Deque<Boolean> vis = new ArrayDeque<>();
        st.push(root); vis.push(false);
        while (!st.isEmpty()) {
            Tree cur = st.pop();
            boolean v = vis.pop();
            if (v) { out.add(cur); continue; }
            st.push(cur); vis.push(true);
            List<Tree> ch = cur.getChildren();
            for (int i = ch.size() - 1; i >= 0; --i) {
                st.push(ch.get(i)); vis.push(false);
            }
        }
        return out;
    }

    private static Map<String, List<Tree>> indexAllNodesByType(Tree root) {
        Map<String, List<Tree>> m = new HashMap<>();
        Deque<Tree> dq = new ArrayDeque<>();
        dq.add(root);
        while (!dq.isEmpty()) {
            Tree t = dq.pollFirst();
            m.computeIfAbsent(t.getType().name, k -> new ArrayList<>()).add(t);
            dq.addAll(t.getChildren());
        }
        return m;
    }

    private static int depthOf(Tree x) {
        int d = 0; Tree p = x.getParent();
        while (p != null) { d++; p = p.getParent(); }
        return d;
    }

    private static int countNodes(Tree node) {
        int c = 1;
        for (Tree ch : node.getChildren()) c += countNodes(ch);
        return c;
    }

    private static Tree firstDescendantByType(Tree root, String typeName) {
        Deque<Tree> dq = new ArrayDeque<>();
        dq.add(root);
        while (!dq.isEmpty()) {
            Tree cur = dq.pollFirst();
            if (cur != root && typeName.equalsIgnoreCase(cur.getType().name)) return cur;
            dq.addAll(cur.getChildren());
        }
        return null;
    }

    private static Tree firstChildByType(Tree node, String typeName) {
        for (Tree c : node.getChildren()) {
            if (typeName.equalsIgnoreCase(c.getType().name)) return c;
        }
        return null;
    }

    private static Map<String, Integer> countNodeTypes(Tree node) {
        Map<String, Integer> m = new HashMap<>();
        Deque<Tree> dq = new ArrayDeque<>();
        dq.add(node);
        while (!dq.isEmpty()) {
            Tree cur = dq.pollFirst();
            String k = cur.getType().name;
            m.put(k, m.getOrDefault(k, 0) + 1);
            dq.addAll(cur.getChildren());
        }
        return m;
    }

    private static Set<String> parentChildPairs(Tree root) {
        Set<String> pairs = new HashSet<>();
        Deque<Tree> dq = new ArrayDeque<>();
        dq.add(root);
        while (!dq.isEmpty()) {
            Tree p = dq.pollFirst();
            String pn = p.getType().name;
            for (Tree c : p.getChildren()) {
                String cn = c.getType().name;
                pairs.add(pn + "->" + cn);
                dq.addLast(c);
            }
        }
        return pairs;
    }

    private static String safeNorm(String s) {
        if (s == null) return "";
        String t = s.trim();
        return t.replaceAll("\\s+", " ");
    }

    private static double clamp(double v, double lo, double hi) {
        return Math.max(lo, Math.min(hi, v));
    }

    private static double clamp01(double v) {
        return clamp(v, 0.0, 1.0);
    }

    private static int levenshtein(String a, String b) {
        int n = a.length(), m = b.length();
        if (n == 0) return m;
        if (m == 0) return n;
        int[] prev = new int[m + 1];
        int[] cur  = new int[m + 1];
        for (int j = 0; j <= m; j++) prev[j] = j;
        for (int i = 1; i <= n; i++) {
            cur[0] = i;
            char ca = a.charAt(i - 1);
            for (int j = 1; j <= m; j++) {
                int cost = (ca == b.charAt(j - 1)) ? 0 : 1;
                cur[j] = Math.min(
                        Math.min(cur[j - 1] + 1, prev[j] + 1),
                        prev[j - 1] + cost
                );
            }
            int[] tmp = prev; prev = cur; cur = tmp;
        }
        return prev[m];
    }

    public static String summarize(List<Match> matches) {
        StringBuilder sb = new StringBuilder();
        for (Match m : matches) {
            sb.append(String.format(
                    "[%s] %s  <->  [%s] %s  (score=%.3f)\n",
                    m.x.getType().name, safeNorm(m.x.getLabel()),
                    m.y.getType().name, safeNorm(m.y.getLabel()),
                    m.score
            ));
        }
        return sb.toString();
    }
}
