package org.example;

import com.github.gumtreediff.tree.Tree;
import com.github.gumtreediff.actions.model.Action;
import com.github.gumtreediff.actions.model.Insert;
import com.github.gumtreediff.actions.model.Delete;
import com.github.gumtreediff.actions.model.Move;
import com.github.gumtreediff.actions.model.Update;
import com.github.gumtreediff.actions.EditScript;

public class DiffDebugUtils {

    public static String getEditScript(EditScript editScript) {
        StringBuilder sb = new StringBuilder();
        sb.append("==== Begin EditScript ====\n");
        int idx = 1;
        for (Action action : editScript) {
            String type = action instanceof Insert ? "Insert" :
                          action instanceof Delete ? "Delete" :
                          action instanceof Move   ? "Move"   :
                          action instanceof Update ? "Update" : "Other";

            sb.append(String.format("[%02d] %-7s%n", idx++, type));
            for (String line : action.toString().split("\n")) {
                sb.append("      ").append(line).append("\n");
            }
            sb.append("--------------------------------------------------\n");
        }
        sb.append("==== End EditScript ====\n");
        return sb.toString();
    }

    public static String getPathToRoot(Tree node) {
        StringBuilder sb = new StringBuilder();
        sb.append("Path: ");
        Tree cur = node;
        while (cur != null) {
            sb.append(cur.getType().name).append(" -> ");
            cur = cur.getParent();
        }
        sb.append("ROOT");
        return sb.toString();
    }

    public static String getTree(Tree node, int indent) {
        StringBuilder sb = new StringBuilder();
        String pad = " ".repeat(indent);
        sb.append(pad).append(node.getType().name).append(": ").append(node.getLabel()).append("\n");
        for (Tree child : node.getChildren()) {
            sb.append(getTree(child, indent + 2));
        }
        return sb.toString();
    }

}
