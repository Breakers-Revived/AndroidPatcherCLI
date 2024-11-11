package fr.chaikew.bbapkrebuild;

import androidx.annotation.NonNull;
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
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Injector of modified Sinum (libsinum.so) into APKs
 * so we could redirect Unreal Engine 4 network requests
 * to an arbitrary chosen server :)
 *
 * @author Chaikew
 */
public final class SinumPatcher {
    public static final int DEX_MIN_API_LEVEL = 15;
    public static final int DEX_API_LEVEL = 19;
    public static final int DEX_SMALI_THREADS = 1;

    /**
     * Api level of the Dalvik EXecutable (DEX) file.
     */
    public final int apiLevel;

    /**
     * Number of threads (also referred to as "jobs") to
     * use for conversion between DEX and SMALI files.
     */
    public final int smaliThreads;


    /**
     * Default constructor.
     *
     * @see #DEX_API_LEVEL
     * @see #DEX_SMALI_THREADS
     * @see #SinumPatcher(int, int)
     */
    public SinumPatcher() {
        this(DEX_API_LEVEL, DEX_SMALI_THREADS);
    }

    /**
     * Constructor to use custom api level.
     *
     * @param apiLevel Api level use to read the Dalvik EXecutable (DEX) file
     *
     * @see #DEX_API_LEVEL
     * @see #DEX_SMALI_THREADS
     * @see #SinumPatcher(int, int)
     */
    public SinumPatcher(final int apiLevel) {
        this(apiLevel, DEX_SMALI_THREADS);
    }

    /**
     * Constructor to use custom api level
     * and custom thread counts.
     *
     * @param apiLevel Api level use to read the Dalvik EXecutable (DEX) file. Must be greater or equals to 15.
     * @param smaliThreads The number of threads used to convert between DEX and SMALI. Must be between 1 and Runtime->availableProcessors()
     *
     * @see #DEX_API_LEVEL
     * @see #DEX_SMALI_THREADS
     */
    public SinumPatcher(final int apiLevel, final int smaliThreads) {
        if (apiLevel < DEX_MIN_API_LEVEL)
            throw new RuntimeException("apiLevel is lower than the minimum supported version: expected >= " + DEX_MIN_API_LEVEL + " got " + apiLevel);

        if (smaliThreads < 1)
            throw new RuntimeException("smaliThreads is lower than 1... What do you expect? Running on a \"ghost cpu\"?");

        if (smaliThreads > Runtime.getRuntime().availableProcessors())
            throw new RuntimeException("smaliThreads is greater than avaiable processors (" + Runtime.getRuntime().availableProcessors() + ")");

        this.apiLevel = apiLevel;
        this.smaliThreads = smaliThreads;
    }


    /**
     * Injects Sinum into a given apk.
     *
     * @param inputApk  The apk to be patched (= injected with Sinum)
     * @param outputApk The output (patched) apk
     * @param cacheDir  A cache directory (e.g. Android Context->getExternalCacheDir())
     * @param protocol  The web protocol used by the target server (e.g. "http" or "https")
     * @param host      The target server address (e.g. "example.com" or "127.0.0.1")
     * @param port      The target server port (e.g. "1234")
     * @throws IOException       File system / bundled files errors
     * @throws SecurityException Certificate and signing issues
     */
    public void sinumPatch(
            final @NonNull File inputApk, final @NonNull File outputApk, final @NonNull File cacheDir,
            final @NonNull String protocol, final @NonNull String host, final @NonNull String port
    ) throws IOException {
        Objects.requireNonNull(inputApk, "SinumPatcher->sinumPatch(...)  inputApk was null");
        Objects.requireNonNull(outputApk, "SinumPatcher->sinumPatch(...)  outputApk was null");
        Objects.requireNonNull(cacheDir, "SinumPatcher->sinumPatch(...)  cacheDir was null");
        Objects.requireNonNull(protocol, "SinumPatcher->sinumPatch(...)  protocol was null");
        Objects.requireNonNull(host, "SinumPatcher->sinumPatch(...)  host was null");
        Objects.requireNonNull(port, "SinumPatcher->sinumPatch(...)  port was null");

        final File smaliDir = new File(cacheDir, "smali");
        final File tmpDir = new File(cacheDir, "tmp");

        final File originalDexTmp = new File(tmpDir, "classes-original.dex");
        final File patchedDexTmp = new File(tmpDir, "classes-patched.dex");
        final File outApkTmp = new File(tmpDir, "output.unaligned.apk");

        if (smaliDir.exists())
            FileUtils.cleanDirectory(smaliDir);

        if (tmpDir.exists())
            FileUtils.cleanDirectory(tmpDir);

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

    private void DexClasses_disassemble(final @NonNull File dexFile, final @NonNull File outputDir) throws IOException {
        DexFile dex = new DexBackedDexFile(Opcodes.forApi(this.apiLevel), Files.readAllBytes(dexFile.toPath()));
        BaksmaliOptions opts = new BaksmaliOptions();
        opts.apiLevel = this.apiLevel;
        Baksmali.disassembleDexFile(dex, outputDir, this.smaliThreads, opts);
    }


    private void DexClasses_injectSinum(final @NonNull File smaliDir, final @NonNull String protocol, final @NonNull String host, final @NonNull String port) throws IOException {
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
                throw new FileNotFoundException("Failed to find UE4 game entry point (onCreate) :(");
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

    private void DexClasses_assemble(final @NonNull File smaliDir, final @NonNull File outputDex) throws IOException {
        SmaliOptions opts = new SmaliOptions();
        opts.jobs = this.smaliThreads;
        opts.apiLevel = this.apiLevel;
        opts.outputDexFile = outputDex.getAbsolutePath();
        Smali.assemble(opts, smaliDir.getAbsolutePath());
    }

    @NonNull
    private static String escapeSmaliConstant(final @NonNull String constant) {
        return constant
                .replace("\n", "")
                .replace("\r", "")
                .replace("\"", "\\\"");
    }
}
