plugins {
    id("java")
}

group = "fr.chaikew"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
    google()
    maven {
        url = uri("https://jitpack.io")
    }
}

dependencies {
    implementation("commons-io:commons-io:2.17.0")

    // patching
    implementation("org.smali:baksmali:2.5.2")
    implementation("org.smali:smali:2.5.2")

    // signing
    val spongycastle_version = "1.58.0.0"
    implementation("com.madgag.spongycastle:core:$spongycastle_version")
    implementation("com.madgag.spongycastle:prov:$spongycastle_version")
    implementation("com.madgag.spongycastle:bcpkix-jdk15on:$spongycastle_version")
    implementation("com.madgag.spongycastle:bcpg-jdk15on:$spongycastle_version")

    // aligning
    implementation("com.github.iyxan23:zipalign-java:1.2.0")

    implementation("androidx.annotation:annotation:1.5.0")

    //testImplementation(platform("org.junit:junit-bom:5.10.0"))
    //testImplementation("org.junit.jupiter:junit-jupiter")
}

tasks.withType<Jar> {
    manifest {
        attributes["Main-Class"] = "fr.chaikew.bbapkrebuild.Main"
    }

    enabled = true
    isZip64 = true
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE

    from(sourceSets.main.get().output)
    dependsOn(configurations.runtimeClasspath)
    from({
        configurations.runtimeClasspath.get().filter {
            it.name.endsWith("jar")
        }.map { zipTree(it) }
    }) {
        exclude("META-INF/*.RSA", "META-INF/*.SF", "META-INF/*.DSA")
    }
}

tasks.test {
    useJUnitPlatform()
}