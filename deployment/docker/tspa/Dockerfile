# Our TSPA (TRAIN trust-list publication): upstream eclipse-xfsc/train-trust-framework-manager at
# ecd5fdc with its train-shared model at 6a0abe4, both pinned by checksum, and two patches
# (patches/, offerable upstream):
#   0001  the trust-list VC's expirationDate = issuance + trustlist.vc.validity (an ISO-8601
#         duration); without it no VC is issued, so a list never carries upstream's stale 2025 date;
#   0002  the signing key comes from tspa.signing-key-file (a mounted Secret); the key shipped in
#         upstream's source (classpath:Vault/PrivateKey) is public and is never used;
#   0003  the VC template defines its subject's terms (trustlisttype, trustlistURI, hash), which
#         JSON-LD would otherwise drop from what the proof signs.
# Otherwise upstream's own Dockerfile: a Maven build, the WAR on Tomcat, port 16003.
#
#   docker build -f deployment/docker/tspa/Dockerfile .   (the repository root, as every image here)
FROM maven:3.9.6-eclipse-temurin-21@sha256:8d63d4c1902cb12d9e79a70671b18ebe26358cb592561af33ca1808f00d935cb AS builder
WORKDIR /build
ADD --checksum=sha256:300b68c2e46527f45591edbd2db36dd47f2b2911ce45ccc74c8272ddb24e67a6 \
    https://github.com/eclipse-xfsc/train-trust-framework-manager/archive/ecd5fdc1b01d4aac2e0cbcb1d44dff1ac0202c17.tar.gz /tmp/tfm.tgz
ADD --checksum=sha256:e408564fe0c8edfbae846502305600092b8ddbc889972d65e7869ed4878cb938 \
    https://github.com/eclipse-xfsc/train-shared/archive/6a0abe4bcbb42c6f3273417af990271a475ba2cc.tar.gz /tmp/shared.tgz
RUN tar -xzf /tmp/tfm.tgz --strip-components=1 \
 && mkdir -p shared && tar -xzf /tmp/shared.tgz -C shared --strip-components=1 \
 && mvn -q -B dependency:go-offline
COPY deployment/docker/tspa/patches/ /patches/
# Every patch must apply; the published key is removed from the build, and the build stops if any
# source still names it, if the validity setting is not required, or if the WAR carries the key.
RUN set -e; \
    for p in /patches/*.patch; do git apply "$p" || exit 1; done; \
    rm -rf src/main/resources/Vault/PrivateKey; \
    if grep -rq 'Vault/PrivateKey/' src/main; then echo 'the published signing key is still referenced' >&2; exit 1; fi; \
    grep -q 'trustlist.vc.validity is not set' src/main/java/eu/xfsc/train/tspa/services/VCServiceImpl.java; \
    grep -q 'tspa.signing-key-file is not set' src/main/java/eu/xfsc/train/tspa/signer/VcSignHandler.java; \
    mvn -q -B clean package -DskipTests; \
    if jar tf target/tspa-service.war | grep -q 'Vault/PrivateKey/.'; then echo 'the WAR carries the published key' >&2; exit 1; fi

FROM tomcat:10.1.62-jdk21-temurin-jammy@sha256:47f597973609529f5ee73dcb91655aeeec4881bbc1f21937f0dde154c2429801
RUN sed -i 's/port="8080"/port="16003"/' "${CATALINA_HOME}/conf/server.xml"
COPY --from=builder /build/target/tspa-service.war /usr/local/tomcat/webapps/tspa-service.war
CMD ["catalina.sh", "run"]
