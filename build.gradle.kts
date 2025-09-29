import net.thebugmc.gradle.sonatypepublisher.PublishingType.*

plugins {
    id("java-library")
    id("net.thebugmc.gradle.sonatype-central-portal-publisher") version "1.2.4"
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
    testRuntimeOnly(libs.org.junit.platform.junit.platform.launcher)
    testImplementation(libs.org.slf4j.slf4j.simple)
}

group = "org.purejava"
version = "1.2.9-SNAPSHOT"
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

centralPortal {
    publishingType.set(USER_MANAGED)

    username.set(sonatypeUsername)
    password.set(sonatypePassword)

    // Configure POM metadata
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
