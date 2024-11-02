# AndroidPatcherCLI
### What is it?
A small command line interface (CLI) application entirely written in Java. It aims to provide an easy way to rebuild Battle Breakers APK to redirect them to Dippy's private server.

### How to build it?
 `$ gradlew build`

### How to use it?
After building it, run the following:
```
$ java -jar build/libs/BattleBreakersAPKRebuilder-1.0-SNAPSHOT.jar BattleBreakers.apk BattleBreakers-patched.apk cache_tmp_dir http 127.0.0.1 80
```
The arguments are described as follows:
 1. input  apk
 2. output apk
 3. cache dir
 4. url protocol
 5. url host
 6. url port