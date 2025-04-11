plugins {
    id("java-library")
    id("io.github.gradle-nexus.publish-plugin") version "2.0.0"
    id("maven-publish")
    id("signing")
}

repositories {
    mavenCentral()
}

dependencies {
    api(libs.org.purejava.tweetnacl.java)
    api(libs.org.json.json)
    api(libs.org.apache.commons.commons.lang3)
    api(libs.org.slf4j.slf4j.api)
    testImplementation(libs.org.junit.jupiter.junit.jupiter.api)
    testImplementation(libs.org.junit.jupiter.junit.jupiter.engine)
    testImplementation(libs.org.junit.jupiter.junit.jupiter)
    testImplementation(libs.org.slf4j.slf4j.simple)
}

group = "org.purejava"
version = "1.2.8-SNAPSHOT"
description = "A Java library to access KeePassXC via its build-in proxy."

java {
    sourceCompatibility = JavaVersion.VERSION_17
    withSourcesJar()
    withJavadocJar()
}

val sonatypeUsername: String = System.getenv("SONATYPE_USERNAME") ?: ""
val sonatypePassword: String = System.getenv("SONATYPE_PASSWORD") ?: ""

tasks.test {
    useJUnitPlatform()
    filter {
        includeTestsMatching("KeepassProxyAccessTest")
    }
}

publishing {
    publications {
        create<MavenPublication>("mavenJava") {
            from(components["java"])
            pom {
                name.set("keepassxc-proxy-access")
                description.set("A Java library to access KeePassXC via its build-in proxy.")
                url.set("https://github.com/purejava/keepassxc-proxy-access")
                licenses {
                    license {
                        name.set("MIT License")
                        url.set("https://opensource.org/licenses/MIT")
                    }
                }
                developers {
                    developer {
                        id.set("purejava")
                        name.set("Ralph Plawetzki")
                        email.set("ralph@purejava.org")
                    }
                }
                scm {
                    connection.set("scm:git:git://github.com/purejava/keepassxc-proxy-access.git")
                    developerConnection.set("scm:git:ssh://github.com/purejava/keepassxc-proxy-access.git")
                    url.set("https://github.com/purejava/keepassxc-proxy-access/tree/main")
                }
                issueManagement {
                    system.set("GitHub Issues")
                    url.set("https://github.com/purejava/keepassxc-proxy-access/issues")
                }
            }
        }
    }
}

nexusPublishing {
    repositories {
        sonatype {
            nexusUrl.set(uri("https://s01.oss.sonatype.org/service/local/"))
            snapshotRepositoryUrl.set(uri("https://s01.oss.sonatype.org/content/repositories/snapshots/"))
            username.set(sonatypeUsername)
            password.set(sonatypePassword)
        }
    }
}

if (!version.toString().endsWith("-SNAPSHOT")) {
    signing {
        useGpgCmd()
        sign(configurations.runtimeElements.get())
        sign(publishing.publications["mavenJava"])
    }
}

tasks.withType<JavaCompile> {
    options.encoding = "UTF-8"
}

tasks.withType<Javadoc> {
    options.encoding = "UTF-8"
    if (JavaVersion.current().isJava9Compatible) {
        (options as StandardJavadocDocletOptions).addBooleanOption("html5", true)
    }
}
