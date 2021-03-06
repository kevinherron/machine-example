package com.digitalpetri.opcua.machine.example;

import java.io.File;
import java.io.InputStream;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutionException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.eclipse.milo.opcua.sdk.server.OpcUaServer;
import org.eclipse.milo.opcua.sdk.server.api.ManagedAddressSpaceFragmentWithLifecycle;
import org.eclipse.milo.opcua.sdk.server.api.config.OpcUaServerConfig;
import org.eclipse.milo.opcua.sdk.server.util.HostnameUtil;
import org.eclipse.milo.opcua.stack.core.StatusCodes;
import org.eclipse.milo.opcua.stack.core.UaRuntimeException;
import org.eclipse.milo.opcua.stack.core.security.DefaultCertificateManager;
import org.eclipse.milo.opcua.stack.core.security.DefaultTrustListManager;
import org.eclipse.milo.opcua.stack.core.security.SecurityPolicy;
import org.eclipse.milo.opcua.stack.core.transport.TransportProfile;
import org.eclipse.milo.opcua.stack.core.types.builtin.DateTime;
import org.eclipse.milo.opcua.stack.core.types.builtin.LocalizedText;
import org.eclipse.milo.opcua.stack.core.types.enumerated.MessageSecurityMode;
import org.eclipse.milo.opcua.stack.core.types.structured.BuildInfo;
import org.eclipse.milo.opcua.stack.core.util.CertificateUtil;
import org.eclipse.milo.opcua.stack.server.EndpointConfiguration;
import org.eclipse.milo.opcua.stack.server.security.DefaultServerCertificateValidator;
import org.slf4j.LoggerFactory;

import static com.google.common.collect.Lists.newArrayList;
import static org.eclipse.milo.opcua.sdk.server.api.config.OpcUaServerConfig.USER_TOKEN_POLICY_ANONYMOUS;
import static org.eclipse.milo.opcua.sdk.server.api.config.OpcUaServerConfig.USER_TOKEN_POLICY_USERNAME;
import static org.eclipse.milo.opcua.sdk.server.api.config.OpcUaServerConfig.USER_TOKEN_POLICY_X509;

public class ExampleServer {

  static {
    // Required for SecurityPolicy.Aes256_Sha256_RsaPss
    Security.addProvider(new BouncyCastleProvider());
  }

  public static void main(String[] args) throws Exception {
    ExampleServer server = new ExampleServer();

    server.startup().get();

    final CompletableFuture<Void> future = new CompletableFuture<>();

    Runtime.getRuntime().addShutdownHook(new Thread(() -> {
      try {
        server.shutdown().get();
      } catch (InterruptedException | ExecutionException e) {
        e.printStackTrace();
      }
      future.complete(null);
    }));

    future.get();
  }

  private final List<ModeledNamespace> namespaces = new CopyOnWriteArrayList<>();

  private final OpcUaServer server;

  public ExampleServer() throws Exception {
    File securityTempDir = new File(System.getProperty("java.io.tmpdir"), "security");
    if (!securityTempDir.exists() && !securityTempDir.mkdirs()) {
      throw new Exception("unable to create security temp dir: " + securityTempDir);
    }
    LoggerFactory.getLogger(getClass()).info("security temp dir: {}", securityTempDir.getAbsolutePath());

    File pkiDir = securityTempDir.toPath().resolve("pki").toFile();
    if (!pkiDir.exists() && !pkiDir.mkdirs()) {
      throw new Exception("unable to create PKI dir: " + pkiDir);
    }
    LoggerFactory.getLogger(getClass()).info("pki dir: {}", pkiDir.getAbsolutePath());

    KeyStoreLoader loader = new KeyStoreLoader().load(securityTempDir);

    DefaultCertificateManager certificateManager = new DefaultCertificateManager(
        loader.getServerKeyPair(),
        loader.getServerCertificateChain()
    );

    DefaultTrustListManager trustListManager = new DefaultTrustListManager(pkiDir);

    DefaultServerCertificateValidator certificateValidator =
        new DefaultServerCertificateValidator(trustListManager);

    X509Certificate certificate = certificateManager.getCertificates()
        .stream()
        .findFirst()
        .orElseThrow(() -> new UaRuntimeException(StatusCodes.Bad_ConfigurationError, "no certificate found"));

    // The configured application URI must match the one in the certificate(s)
    String applicationUri = CertificateUtil.getSanUri(certificate)
        .orElseThrow(
            () -> new UaRuntimeException(
                StatusCodes.Bad_ConfigurationError,
                "certificate is missing the application URI")
        );

    Set<EndpointConfiguration> endpointConfigurations = createEndpointConfigurations(certificate);

    OpcUaServerConfig serverConfig = OpcUaServerConfig.builder()
        .setApplicationUri(applicationUri)
        .setApplicationName(LocalizedText.english("Eclipse Milo MachineTool Example Server"))
        .setEndpoints(endpointConfigurations)
        .setBuildInfo(
            new BuildInfo(
                "urn:eclipse:milo:example-server",
                "eclipse",
                "eclipse milo example server",
                OpcUaServer.SDK_VERSION,
                "", DateTime.now())
        )
        .setCertificateManager(certificateManager)
        .setTrustListManager(trustListManager)
        .setCertificateValidator(certificateValidator)
        .setProductUri("urn:eclipse:milo:example-server")
        .build();

    server = new OpcUaServer(serverConfig);

    try (InputStream is = ExampleServer.class.getResourceAsStream("/Opc.Ua.Di.NodeSet2.xml")) {
      namespaces.add(ModeledNamespace.createFromNodeSet(server, is));
    }

    try (InputStream is = ExampleServer.class.getResourceAsStream("/Opc.Ua.IA.NodeSet2.xml")) {
      namespaces.add(ModeledNamespace.createFromNodeSet(server, is));
    }

    try (InputStream is = ExampleServer.class.getResourceAsStream("/Opc.Ua.Machinery.NodeSet2.xml")) {
      namespaces.add(ModeledNamespace.createFromNodeSet(server, is));
    }

    try (InputStream is = ExampleServer.class.getResourceAsStream("/Opc.Ua.MachineTool.NodeSet2.xml")) {
      namespaces.add(ModeledNamespace.createFromNodeSet(server, is));
    }

    try (InputStream is = ExampleServer.class.getResourceAsStream("/Machinetool-Example.xml")) {
      namespaces.add(ModeledNamespace.createFromNodeSet(server, is));
    }
  }

  private Set<EndpointConfiguration> createEndpointConfigurations(X509Certificate certificate) {
    Set<EndpointConfiguration> endpointConfigurations = new LinkedHashSet<>();

    List<String> bindAddresses = newArrayList();
    bindAddresses.add("0.0.0.0");

    Set<String> hostnames = new LinkedHashSet<>();
    hostnames.add(HostnameUtil.getHostname());
    hostnames.addAll(HostnameUtil.getHostnames("0.0.0.0"));

    for (String bindAddress : bindAddresses) {
      for (String hostname : hostnames) {
        EndpointConfiguration.Builder builder = EndpointConfiguration.newBuilder()
            .setBindAddress(bindAddress)
            .setHostname(hostname)
            .setPath("/milo")
            .setCertificate(certificate)
            .addTokenPolicies(
                USER_TOKEN_POLICY_ANONYMOUS,
                USER_TOKEN_POLICY_USERNAME,
                USER_TOKEN_POLICY_X509
            );

        EndpointConfiguration.Builder noSecurityBuilder = builder.copy()
            .setSecurityPolicy(SecurityPolicy.None)
            .setSecurityMode(MessageSecurityMode.None);

        endpointConfigurations.add(buildTcpEndpoint(noSecurityBuilder));

        // TCP Basic256Sha256 / SignAndEncrypt
        endpointConfigurations.add(
            buildTcpEndpoint(
                builder.copy()
                    .setSecurityPolicy(SecurityPolicy.Basic256Sha256)
                    .setSecurityMode(MessageSecurityMode.SignAndEncrypt)
            )
        );

        /*
         * It's good practice to provide a discovery-specific endpoint with no security.
         * It's required practice if all regular endpoints have security configured.
         *
         * Usage of the  "/discovery" suffix is defined by OPC UA Part 6:
         *
         * Each OPC UA Server Application implements the Discovery Service Set. If the OPC UA Server requires a
         * different address for this Endpoint it shall create the address by appending the path "/discovery" to
         * its base address.
         */

        EndpointConfiguration.Builder discoveryBuilder = builder.copy()
            .setPath("/milo/discovery")
            .setSecurityPolicy(SecurityPolicy.None)
            .setSecurityMode(MessageSecurityMode.None);

        endpointConfigurations.add(buildTcpEndpoint(discoveryBuilder));
      }
    }

    return endpointConfigurations;
  }

  private static EndpointConfiguration buildTcpEndpoint(EndpointConfiguration.Builder base) {
    return base.copy()
        .setTransportProfile(TransportProfile.TCP_UASC_UABINARY)
        .setBindPort(62541)
        .build();
  }

  public CompletableFuture<OpcUaServer> startup() {
    return server.startup();
  }

  public CompletableFuture<OpcUaServer> shutdown() {
    namespaces.forEach(ManagedAddressSpaceFragmentWithLifecycle::shutdown);

    return server.shutdown();
  }

}
