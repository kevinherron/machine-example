package com.digitalpetri.opcua.machine.example;

import java.io.InputStream;
import javax.xml.bind.JAXBException;

import com.digitalpetri.opcua.nodeset.UaNodeSet;
import org.eclipse.milo.opcua.sdk.server.OpcUaServer;
import org.eclipse.milo.opcua.sdk.server.api.Namespace;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UShort;
import org.slf4j.LoggerFactory;

public class ModeledNamespace extends ModeledAddressSpace implements Namespace {

  private final String namespaceUri;
  private final UShort namespaceIndex;

  public ModeledNamespace(OpcUaServer server, String namespaceUri, UaNodeSet nodeSet) {
    super(server, nodeSet);

    this.namespaceUri = namespaceUri;
    this.namespaceIndex = server.getNamespaceTable().addUri(namespaceUri);
  }

  @Override
  public String getNamespaceUri() {
    return namespaceUri;
  }

  @Override
  public UShort getNamespaceIndex() {
    return namespaceIndex;
  }

  public static ModeledNamespace create(
      OpcUaServer server,
      String namespaceUri,
      InputStream modelInputStream
  ) throws JAXBException {

    try {
      UaNodeSet nodeSet = UaNodeSet.parse(modelInputStream);

      ModeledNamespace namespace = new ModeledNamespace(server, namespaceUri, nodeSet);

      namespace.startup();

      return namespace;
    } catch (JAXBException e) {
      LoggerFactory.getLogger(ModeledNamespace.class)
          .error("Error parsing node set: {}", e.getMessage(), e);

      throw e;
    }
  }

}
