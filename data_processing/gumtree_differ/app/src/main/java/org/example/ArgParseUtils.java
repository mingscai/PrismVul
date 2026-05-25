package org.example;

public class ArgParseUtils {
    public String srcFilePath;
    public String dstFilePath;
    public String rawSrcFilePath;
    public String rawDstFilePath;
    public String outputJsonPath;
    public boolean preprocess;
    public boolean strictMapping;

    public ArgParseUtils(
            String srcFilePath,
            String dstFilePath,
            String rawSrcFilePath,
            String rawDstFilePath,
            String outputJsonPath,
            boolean preprocess,
            boolean strictMapping) {
        this.srcFilePath = srcFilePath;
        this.dstFilePath = dstFilePath;
        this.rawSrcFilePath = rawSrcFilePath;
        this.rawDstFilePath = rawDstFilePath;
        this.outputJsonPath = outputJsonPath;
        this.preprocess = preprocess;
        this.strictMapping = strictMapping;
    }

    public static ArgParseUtils argParse(String[] args) {
        String srcFilePath = null;
        String dstFilePath = null;
        String rawSrcFilePath = null;
        String rawDstFilePath = null;
        String outputJsonPath = null;
        boolean preprocess = false;
        boolean strictMapping = false;

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--srcPath":
                    if (i + 1 < args.length) {
                        srcFilePath = args[++i];
                    } else {
                        System.err.println("Error: --srcPath requires a file path");
                        System.exit(1);
                    }
                    break;
                case "--dstPath":
                    if (i + 1 < args.length) {
                        dstFilePath = args[++i];
                    } else {
                        System.err.println("Error: --dstPath requires a file path");
                        System.exit(1);
                    }
                    break;
                case "--outPath":
                    if (i + 1 < args.length) {
                        outputJsonPath = args[++i];
                    } else {
                        System.err.println("Error: --outPath requires a file path");
                        System.exit(1);
                    }
                    break;
                case "--rawSrcPath":
                    if (i + 1 < args.length) {
                        rawSrcFilePath = args[++i];
                    } else {
                        System.err.println("Error: --rawSrcPath requires a file path");
                        System.exit(1);
                    }
                    break;
                case "--rawDstPath":
                    if (i + 1 < args.length) {
                        rawDstFilePath = args[++i];
                    } else {
                        System.err.println("Error: --rawDstPath requires a file path");
                        System.exit(1);
                    }
                    break;
                case "--preprocess":
                    preprocess = true;
                    break;
                case "--strictMapping":
                    strictMapping = true;
                    break;
                default:
                    System.err.println("Unknown argument: " + args[i]);
                    System.err.println(
                            "Usage: java -jar ast-diff-analyzer.jar --srcPath <srcFile> --dstPath <dstFile> --outPath <outputJSON> "
                                    + "[--rawSrcPath <rawSrcFile>] [--rawDstPath <rawDstFile>] [--preprocess] [--strictMapping]");
                    System.exit(1);
            }
        }

        if (srcFilePath == null || dstFilePath == null || outputJsonPath == null) {
            System.err.println("Error: Missing required arguments");
            System.err.println(
                    "Usage: java -jar ast-diff-analyzer.jar --srcPath <srcFile> --dstPath <dstFile> --outPath <outputJSON> "
                            + "[--rawSrcPath <rawSrcFile>] [--rawDstPath <rawDstFile>] [--preprocess] [--strictMapping]");
            System.exit(1);
        }

        if (rawSrcFilePath == null || rawSrcFilePath.isBlank()) {
            rawSrcFilePath = srcFilePath;
        }
        if (rawDstFilePath == null || rawDstFilePath.isBlank()) {
            rawDstFilePath = dstFilePath;
        }

        return new ArgParseUtils(
                srcFilePath,
                dstFilePath,
                rawSrcFilePath,
                rawDstFilePath,
                outputJsonPath,
                preprocess,
                strictMapping);
    }
}
