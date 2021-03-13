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

  /**
   * Create a {@link ModeledNamespace} from the contents of a UANodeSet2 XML file.
   *
   * @param server      the {@link OpcUaServer} instance the namespace will belong to.
   * @param inputStream an {@link InputStream} to read the UANodeSet2 XML file from.
   * @return a {@link ModeledNamespace} containing the nodes defined by a UANodeSet2 XML file.
   * @throws JAXBException if an error occurs while parsing the UANodeSet2 XML file.
   */
  public static ModeledNamespace createFromNodeSet(
      OpcUaServer server,
      InputStream inputStream
  ) throws JAXBException {

    try {
      UaNodeSet nodeSet = UaNodeSet.parse(inputStream);

      // Namespace URI used by the model will always be at index 1 in the NamespaceTable of a
      // UaNodeSet. Additional namespaces referenced by the model will be at subsequent indices.
      // The standard OPC UA namespace is at index 0 as expected.
      String namespaceUri = nodeSet.getNamespaceTable().getUri(1);

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
