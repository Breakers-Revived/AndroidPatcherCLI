package fr.chaikew.bbapkrebuild;

import fr.chaikew.signing.SignedJar;
import fr.chaikew.signing.SignerConfig;
import com.iyxan23.zipalignjava.InvalidZipException;
import com.iyxan23.zipalignjava.ZipAlign;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.jf.baksmali.Baksmali;
import org.jf.baksmali.BaksmaliOptions;
import org.jf.dexlib2.Opcodes;
import org.jf.dexlib2.dexbacked.DexBackedDexFile;
import org.jf.dexlib2.iface.DexFile;
import org.jf.smali.Smali;
import org.jf.smali.SmaliOptions;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Enumeration;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;


public final class SinumPatcher {
    private static final int kDEX_API_LEVEL = 19;
    private static final int kDEX_SMALI_THREADS = 1;


    public static void sinumPatch(File inputApk, File outputApk, File cacheDir, String protocol, String host, String port) throws IOException {
        final File smaliDir = new File(cacheDir, "smali");
        final File tmpDir = new File(cacheDir, "tmp");

        final File originalDexTmp = new File(tmpDir, "classes-original.dex");
        final File patchedDexTmp = new File(tmpDir, "classes-patched.dex");
        final File outApkTmp = new File(tmpDir, "output.unaligned.apk");

        FileUtils.cleanDirectory(smaliDir);
        FileUtils.cleanDirectory(smaliDir);

        final SignerConfig signerConfig = SignerConfig.DEFAULT_CONFIG
                .withPath(new File(cacheDir, "keystore.bks").getAbsolutePath());

        try (OutputStream os = Files.newOutputStream(outApkTmp.toPath())) {
            try (SignedJar outputApkZ = signerConfig.createSignedJar(os)) {
                try (ZipFile inputApkZ = new ZipFile(inputApk)) {
                    Enumeration<? extends ZipEntry> entries = inputApkZ.entries();

                    while (entries.hasMoreElements()) {
                        ZipEntry entry = entries.nextElement();

                        try (InputStream is = inputApkZ.getInputStream(entry)) {
                            byte[] bytes = IOUtils.toByteArray(is);

                            // transform dex
                            if (entry.getName().equals("classes.dex")) {
                                Files.write(originalDexTmp.toPath(), bytes);

                                DexClasses_disassemble(originalDexTmp, smaliDir);
                                DexClasses_injectSinum(smaliDir, protocol, host, port);
                                DexClasses_assemble(smaliDir, patchedDexTmp);

                                bytes = Files.readAllBytes(patchedDexTmp.toPath());
                            }

                            outputApkZ.addFileContents(entry.getName(), bytes, entry.getCompressedSize() != entry.getSize(), true);
                        }
                    }
                }

                // Append the Sinum native libraries
                final ClassLoader cl = SinumPatcher.class.getClassLoader();
                final String[] archs = new String[]{"arm64-v8a", "armeabi-v7a", "x86_64"};

                for (final String arch : archs) {
                    final String vpath = "sinum/" + arch + "/libsinum.so";
                    try (final InputStream soStream = cl.getResourceAsStream(vpath)) {
                        if (soStream == null)
                            throw new IOException("Couldn't load: " + vpath);
                        final byte[] bytes = IOUtils.toByteArray(soStream);

                        outputApkZ.addFileContents("lib/" + arch + "/libsinum.so", bytes, true);
                    }
                }
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        try (RandomAccessFile zipIn = new RandomAccessFile(outApkTmp, "r")) {
            try (OutputStream zipOut = Files.newOutputStream(outputApk.toPath())) {
                ZipAlign.alignZip(zipIn, zipOut);
            } catch (InvalidZipException e) {
                throw new RuntimeException(e);
            }
        }
    }

    private static void DexClasses_disassemble(File dexFile, File outputDir) throws IOException {
        DexFile dex = new DexBackedDexFile(Opcodes.forApi(kDEX_API_LEVEL), Files.readAllBytes(dexFile.toPath()));
        BaksmaliOptions opts = new BaksmaliOptions();
        opts.apiLevel = kDEX_API_LEVEL;
        Baksmali.disassembleDexFile(dex, outputDir, kDEX_SMALI_THREADS, opts);
    }


    private static void DexClasses_injectSinum(final File smaliDir, String protocol, String host, String port) throws IOException, SinumPatcherException {
        injectNativeSoLoader:
        {
            final File ue4GameActivityPath = Paths.get(smaliDir.getAbsolutePath(), "com", "epicgames", "ue4", "GameActivity.smali").toFile();
            final String ue4GameActivity = FileUtils.readFileToString(ue4GameActivityPath, StandardCharsets.UTF_8);

            // Define the pattern for onCreate and registers line
            final Pattern pattern = Pattern.compile("(\\.method public onCreate\\(Landroid/os/Bundle;\\)V\\s*\\.registers \\d+)");
            final Matcher matcher = pattern.matcher(ue4GameActivity);

            // Define the string to append after .registers
            final String toAppend = "\n    const-string v0, \"sinum\"\n    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V";

            // Replace the first occurrence only
            if (matcher.find()) {
                final String newUE4GameActivity = new StringBuilder(ue4GameActivity).insert(matcher.end(), toAppend).toString();
                FileUtils.writeStringToFile(ue4GameActivityPath, newUE4GameActivity, StandardCharsets.UTF_8);
            } else {
                throw new SinumPatcherException("Failed to find UE4 game entry point (onCreate) :(");
            }
        }

        injectSinumClass:
        {
            final String generatedSinumClass =
                    ".class Lio/sinum/Sinum;\n" +
                    ".super Ljava/lang/Object;\n" +
                    "\n" +
                    "\n" +
                    ".field public static final PROTOCOL:Ljava/lang/String; = \"" + escapeSmaliConstant(protocol) + "\"\n" +
                    ".field public static final HOST:Ljava/lang/String; = \"" + escapeSmaliConstant(host) + "\"\n" +
                    ".field public static final PORT:Ljava/lang/String; = \"" + escapeSmaliConstant(port) + "\"";

            final File soOut = Paths.get(smaliDir.getAbsolutePath(), "io", "sinum", "Sinum.smali").toFile();
            FileUtils.writeStringToFile(soOut, generatedSinumClass, StandardCharsets.UTF_8);
        }
    }

    private static void DexClasses_assemble(File smaliDir, File outputDex) throws IOException {
        SmaliOptions opts = new SmaliOptions();
        opts.jobs = kDEX_SMALI_THREADS;
        opts.apiLevel = kDEX_API_LEVEL;
        opts.outputDexFile = outputDex.getAbsolutePath();
        Smali.assemble(opts, smaliDir.getAbsolutePath());
    }

    private static String escapeSmaliConstant(String constant) {
        return constant
                .replace("\n", "")
                .replace("\r", "")
                .replace("\"", "\\\"");
    }

    public static final class SinumPatcherException extends Exception {
        public SinumPatcherException(String s) {
            super(s);
        }
    }
}
