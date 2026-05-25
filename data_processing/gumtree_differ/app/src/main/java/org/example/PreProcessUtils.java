package org.example;

import com.github.gumtreediff.tree.Tree;

import static org.example.DiffDebugUtils.*;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.regex.Pattern;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;

public class PreProcessUtils {

    public static String preprocessSource(String code) throws Exception {

        Pattern p = Pattern.compile("\\)\\s+(?:[A-Za-z_][A-Za-z0-9_]*(?:\\([^)]*\\))?\\s+)*[A-Za-z_][A-Za-z0-9_]*(?:\\([^)]*\\))?\\s*(?=[;{])");
        Matcher m = p.matcher(code);
        return m.replaceAll(")");
    }

    public static String removeCommentsWithGcc(String inputFile) throws Exception {

        ProcessBuilder pb = new ProcessBuilder(
                "gcc", "-fpreprocessed", "-dD", "-E", inputFile
        );
        pb.redirectErrorStream(true);

        Process process = pb.start();
        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
        }

        int exitCode = process.waitFor();

        if (exitCode != 0) {

            StringBuilder original = new StringBuilder();
            try (BufferedReader br = new BufferedReader(new FileReader(inputFile))) {
                String line;
                while ((line = br.readLine()) != null) {
                    original.append(line).append("\n");
                }
            }
            return original.toString();
        }

        return output.toString();
    }

    public static void removeTestMacros(Tree node) {
        List<Tree> toRemove = new ArrayList<>();

        for (Tree child : node.getChildren()) {
            removeTestMacros(child);

            if ("macro".equals(child.getType().name)) {
                if (!child.getChildren().isEmpty()
                        && "name".equals(child.getChildren().get(0).getType().name)
                        && child.getChildren().get(0).getLabel().startsWith("TEST")) {

                    Tree parent = child.getParent();
                    Tree blockNode = null;
                    int idx = parent.getChildren().indexOf(child);
                    if (idx + 1 < parent.getChildren().size()) {
                        Tree next = parent.getChildren().get(idx + 1);
                        if ("block".equals(next.getType().name)) {
                            blockNode = next;
                        }
                    }

                    toRemove.add(child);
                    if (blockNode != null) toRemove.add(blockNode);
                }
            }
        }

        node.getChildren().removeAll(toRemove);
    }

}
