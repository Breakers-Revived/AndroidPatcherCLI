package fr.chaikew.bbapkrebuild.cli;

import fr.chaikew.bbapkrebuild.SinumPatcher;

import java.io.File;
import java.io.IOException;

public class Main {
    public static void main(String[] args) throws IOException, InterruptedException {
        if (args.length != 6) {
            System.out.println("Invalid command line: expected 6 arguments, saw " + args.length + " arguments!");
            System.out.println("Command line format: ");
            System.out.println("    1. input  apk  ");
            System.out.println("    2. output apk  ");
            System.out.println("    3. cache dir   ");
            System.out.println("    4. url protocol");
            System.out.println("    5. url host    ");
            System.out.println("    6. url port    ");
            return;
        }

        String input = args[0];
        String output = args[1];
        String cache = args[2];
        String protocol = args[3];
        String host = args[4];
        String port = args[5];
        System.out.println("Patch config: ");
        System.out.println("    input  apk  " + input);
        System.out.println("    output apk  " + output);
        System.out.println("    cache dir   " + cache);
        System.out.println("    url protocol" + protocol);
        System.out.println("    url host    " + host);
        System.out.println("    url port    " + port);
        System.out.println("Waiting 3s for you to review them before continuing...");
        Thread.sleep(3000);

        new SinumPatcher().sinumPatch(new File(input), new File(output), new File(cache), protocol, host, port);
    }
}