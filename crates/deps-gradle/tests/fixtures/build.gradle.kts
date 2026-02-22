plugins {
    id("java")
    id("org.springframework.boot") version "3.2.0"
}

repositories {
    mavenCentral()
}

dependencies {
    implementation("org.springframework.boot:spring-boot-starter:3.2.0")
    implementation("org.springframework.boot:spring-boot-starter-web:3.2.0")
    api("com.google.guava:guava:33.0.0-jre")
    compileOnly("org.projectlombok:lombok:1.18.30")
    runtimeOnly("mysql:mysql-connector-java:8.0.33")
    annotationProcessor("org.projectlombok:lombok:1.18.30")
    kapt("com.google.dagger:dagger-compiler:2.51")
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.mockito:mockito-core:5.8.0")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    classpath("com.android.tools.build:gradle:8.2.0")
}
