package com.digitalpetri.opcua.machine.example;

import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

import com.digitalpetri.opcua.nodeset.UaNodeSet;
import com.digitalpetri.opcua.nodeset.attributes.DataTypeNodeAttributes;
import com.digitalpetri.opcua.nodeset.attributes.MethodNodeAttributes;
import com.digitalpetri.opcua.nodeset.attributes.ObjectNodeAttributes;
import com.digitalpetri.opcua.nodeset.attributes.ObjectTypeNodeAttributes;
import com.digitalpetri.opcua.nodeset.attributes.ReferenceTypeNodeAttributes;
import com.digitalpetri.opcua.nodeset.attributes.VariableNodeAttributes;
import com.digitalpetri.opcua.nodeset.attributes.VariableTypeNodeAttributes;
import com.digitalpetri.opcua.nodeset.attributes.ViewNodeAttributes;
import org.eclipse.milo.opcua.sdk.core.Reference;
import org.eclipse.milo.opcua.sdk.server.ObjectTypeManager.ObjectNodeConstructor;
import org.eclipse.milo.opcua.sdk.server.OpcUaServer;
import org.eclipse.milo.opcua.sdk.server.VariableTypeManager;
import org.eclipse.milo.opcua.sdk.server.api.AddressSpaceFilter;
import org.eclipse.milo.opcua.sdk.server.api.DataItem;
import org.eclipse.milo.opcua.sdk.server.api.ManagedAddressSpaceFragmentWithLifecycle;
import org.eclipse.milo.opcua.sdk.server.api.MonitoredItem;
import org.eclipse.milo.opcua.sdk.server.api.SimpleAddressSpaceFilter;
import org.eclipse.milo.opcua.sdk.server.nodes.UaDataTypeNode;
import org.eclipse.milo.opcua.sdk.server.nodes.UaMethodNode;
import org.eclipse.milo.opcua.sdk.server.nodes.UaNode;
import org.eclipse.milo.opcua.sdk.server.nodes.UaObjectNode;
import org.eclipse.milo.opcua.sdk.server.nodes.UaObjectTypeNode;
import org.eclipse.milo.opcua.sdk.server.nodes.UaReferenceTypeNode;
import org.eclipse.milo.opcua.sdk.server.nodes.UaVariableNode;
import org.eclipse.milo.opcua.sdk.server.nodes.UaVariableTypeNode;
import org.eclipse.milo.opcua.sdk.server.nodes.UaViewNode;
import org.eclipse.milo.opcua.sdk.server.util.SubscriptionModel;
import org.eclipse.milo.opcua.stack.core.Identifiers;
import org.eclipse.milo.opcua.stack.core.NamespaceTable;
import org.eclipse.milo.opcua.stack.core.ReferenceType;
import org.eclipse.milo.opcua.stack.core.types.builtin.ByteString;
import org.eclipse.milo.opcua.stack.core.types.builtin.DataValue;
import org.eclipse.milo.opcua.stack.core.types.builtin.ExpandedNodeId;
import org.eclipse.milo.opcua.stack.core.types.builtin.ExtensionObject;
import org.eclipse.milo.opcua.stack.core.types.builtin.NodeId;
import org.eclipse.milo.opcua.stack.core.types.builtin.QualifiedName;
import org.eclipse.milo.opcua.stack.core.types.builtin.Variant;
import org.eclipse.milo.opcua.stack.core.types.builtin.XmlElement;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UShort;
import org.eclipse.milo.opcua.stack.core.types.enumerated.NodeClass;
import org.eclipse.milo.opcua.stack.core.types.structured.Argument;
import org.eclipse.milo.opcua.stack.core.util.ArrayUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.eclipse.milo.opcua.sdk.core.util.StreamUtil.opt2stream;

public class ModeledAddressSpace extends ManagedAddressSpaceFragmentWithLifecycle {

    protected final Logger logger = LoggerFactory.getLogger(getClass());

    private final SubscriptionModel subscriptionModel;
    private final AddressSpaceFilter addressSpaceFilter;

    private final UaNodeSet nodeSet;

    public ModeledAddressSpace(OpcUaServer server, UaNodeSet nodeSet) {
        super(server);

        this.nodeSet = nodeSet;

        addressSpaceFilter = SimpleAddressSpaceFilter.create(getNodeManager()::containsNode);

        subscriptionModel = new SubscriptionModel(server, this);

        getLifecycleManager().addStartupTask(() -> {
            nodeSet.getExplicitReferences().values().forEach(reference -> {
                Reference translatedReference = reindex(reference);

                getNodeManager().addReferences(translatedReference, getServer().getNamespaceTable());
            });

            nodeSet.getNodes().values().forEach(a -> {
                switch (a.getNodeClass()) {
                    case ObjectType: {
                        UaNode node = buildObjectTypeNode((ObjectTypeNodeAttributes) a);

                        getNodeManager().addNode(node);
                        break;
                    }
                    case VariableType: {
                        UaNode node = buildVariableTypeNode((VariableTypeNodeAttributes) a);

                        getNodeManager().addNode(node);
                        break;
                    }
                    default:
                        break;
                }
            });

            nodeSet.getNodes().values().forEach(a -> {
                switch (a.getNodeClass()) {
                    case DataType: {
                        UaNode node = buildDataTypeNode((DataTypeNodeAttributes) a);

                        getNodeManager().addNode(node);
                        break;
                    }
                    case Method: {
                        UaNode node = buildMethodNode((MethodNodeAttributes) a);

                        getNodeManager().addNode(node);
                        break;
                    }
                    case Object: {
                        UaNode node = buildObjectNode((ObjectNodeAttributes) a);

                        getNodeManager().addNode(node);
                        break;
                    }
                    case ReferenceType: {
                        UaReferenceTypeNode node = buildReferenceTypeNode((ReferenceTypeNodeAttributes) a);

                        getNodeManager().addNode(node);
                        break;
                    }
                    case Variable: {
                        UaNode node = buildVariableNode(nodeSet, (VariableNodeAttributes) a);

                        getNodeManager().addNode(node);
                        break;
                    }
                    case View: {
                        UaNode node = buildViewNode((ViewNodeAttributes) a);

                        getNodeManager().addNode(node);
                        break;
                    }
                    default:
                        break;
                }
            });

            List<UaReferenceTypeNode> referenceTypeNodes = nodeSet.getNodes().values().stream()
                .filter(a -> a.getNodeClass() == NodeClass.ReferenceType)
                .flatMap(a -> {
                    NodeId nodeId = reindex(a.getNodeId());
                    Optional<UaNode> node = getNodeManager().getNode(nodeId);
                    return opt2stream(node.map(UaReferenceTypeNode.class::cast));
                })
                .collect(Collectors.toList());

            referenceTypeNodes.forEach(node -> {
                final Optional<NodeId> superTypeId = node.getReferences().stream()
                    .filter(r -> Identifiers.HasSubtype.equals(r.getReferenceTypeId()) && !r.isForward())
                    .findFirst()
                    .map(Reference::getReferenceTypeId);

                getServer().getReferenceTypes().put(node.getNodeId(), new ReferenceType() {
                    @Override
                    public NodeId getNodeId() {
                        return node.getNodeId();
                    }

                    @Override
                    public QualifiedName getBrowseName() {
                        return node.getBrowseName();
                    }

                    @Override
                    public Optional<String> getInverseName() {
                        return Optional.ofNullable(node.getInverseName().getText());
                    }

                    @Override
                    public boolean isSymmetric() {
                        return node.getSymmetric();
                    }

                    @Override
                    public boolean isAbstract() {
                        return node.getIsAbstract();
                    }

                    @Override
                    public Optional<NodeId> getSuperTypeId() {
                        return superTypeId;
                    }
                });
            });
        });
    }

    @Override
    public AddressSpaceFilter getFilter() {
        return addressSpaceFilter;
    }

    @Override
    public void onDataItemsCreated(List<DataItem> dataItems) {
        subscriptionModel.onDataItemsCreated(dataItems);
    }

    @Override
    public void onDataItemsModified(List<DataItem> dataItems) {
        subscriptionModel.onDataItemsModified(dataItems);
    }

    @Override
    public void onDataItemsDeleted(List<DataItem> dataItems) {
        subscriptionModel.onDataItemsDeleted(dataItems);
    }

    @Override
    public void onMonitoringModeChanged(List<MonitoredItem> monitoredItems) {
        subscriptionModel.onMonitoringModeChanged(monitoredItems);
    }

    /**
     * Re-index {@code originalNodeId} from its original namespace index to the corresponding index in the server for
     * its original namespace URI.
     *
     * @param originalNodeId a {@link NodeId} from the {@link UaNodeSet}.
     * @return a {@link NodeId} that has been re-indexed for the current server.
     */
    protected NodeId reindex(NodeId originalNodeId) {
        NamespaceTable namespaceTable = getServer().getNamespaceTable();
        String namespaceUri = nodeSet.getNamespaceTable().getUri(originalNodeId.getNamespaceIndex());

        return originalNodeId.reindex(namespaceTable, namespaceUri);
    }

    /**
     * Re-index {@code originalExpandedNodeId} from its original namespace index to the corresponding index in the
     * server for its namespace URI derived from the original namespace index.
     *
     * @param originalExpandedNodeId an {@link ExpandedNodeId} from the {@link UaNodeSet}.
     * @return a {@link ExpandedNodeId} that has been re-indexed for the current server.
     */
    protected ExpandedNodeId reindex(ExpandedNodeId originalExpandedNodeId) {
        if (originalExpandedNodeId.isAbsolute()) {
            // namespaceUri is specified; namespaceIndex is ignored
            return originalExpandedNodeId;
        } else {
            NamespaceTable namespaceTable = getServer().getNamespaceTable();

            UShort originalNamespaceIndex = originalExpandedNodeId.getNamespaceIndex();
            String namespaceUri = nodeSet.getNamespaceTable().getUri(originalNamespaceIndex);
            UShort newNamespaceIndex = namespaceTable.getIndex(namespaceUri);

            if (newNamespaceIndex != null
                && !Objects.equals(newNamespaceIndex, originalNamespaceIndex)) {

                return new ExpandedNodeId(
                    newNamespaceIndex,
                    null,
                    originalExpandedNodeId.getIdentifier(),
                    originalExpandedNodeId.getServerIndex()
                );
            } else {
                return originalExpandedNodeId;
            }
        }
    }

    /**
     * Re-index the NodeIds in {@code originalReference} from their original namespace indices to the corresponding
     * indices in the server for the original namespace URIs.
     *
     * @param originalReference a {@link Reference} from the {@link UaNodeSet}.
     * @return a {@link Reference} that has been re-indexed for the current server.
     */
    protected Reference reindex(Reference originalReference) {
        String sourceNamespaceUri = nodeSet.getNamespaceTable()
            .getUri(originalReference.getSourceNodeId().getNamespaceIndex());

        String referenceNamespaceUri = nodeSet.getNamespaceTable()
            .getUri(originalReference.getReferenceTypeId().getNamespaceIndex());

        String targetNamespaceUri = nodeSet.getNamespaceTable()
            .getUri(originalReference.getTargetNodeId().getNamespaceIndex());

        return originalReference.reindex(
            getServer().getNamespaceTable(),
            sourceNamespaceUri,
            referenceNamespaceUri,
            targetNamespaceUri
        );
    }

    /**
     * Re-index {@code originalName} from its original namespace index to the corresponding index in the server for its
     * original namespace URI.
     *
     * @param originalName a {@link QualifiedName} from the {@link UaNodeSet}.
     * @return a {@link QualifiedName} that has been re-indexed for the current server.
     */
    protected QualifiedName reindex(QualifiedName originalName) {
        NamespaceTable namespaceTable = getServer().getNamespaceTable();
        String namespaceUri = nodeSet.getNamespaceTable().getUri(originalName.getNamespaceIndex());

        return originalName.reindex(namespaceTable, namespaceUri);
    }

    /**
     * Re-indexes a {@link DataValue} if necessary.
     * <p>
     * If {@code value} contains an ExtensionObject the encodingId is re-indexed. Then the struct is decoded and any
     * fields that qualify are also re-indexed (e.g. the dataType field in {@link Argument}).
     * <p>
     * This is verging on major hack because the OPC UA modelling concept is somewhat flawed when it comes to encoding
     * embedded values that reference non-absolute namespaces.
     *
     * @param value the {@link DataValue} to re-index.
     * @return a {@link DataValue} that has been re-indexed for the current server.
     */
    protected DataValue reindex(DataValue value) {
        try {
            if (value == null) return null;
            Variant variant = value.getValue();
            if (variant == null) return value;
            Object o = variant.getValue();
            if (o == null) return value;
            return new DataValue(new Variant(reindexValue(o)));
        } catch (Throwable t) {
            logger.warn("Re-indexing failed: {}", value, t);
            return value;
        }
    }

    protected Object reindexValue(Object value) {
        if (value == null) return null;

        Class<?> clazz = value.getClass();

        if (clazz.isArray()) {
            @SuppressWarnings("rawtypes")
            Class componentType = ArrayUtil.getType(value);

            if (componentType != NodeId.class
                && componentType != ExpandedNodeId.class
                && componentType != QualifiedName.class
                && componentType != ExtensionObject.class
            ) {

                return value;
            } else {
                //noinspection unchecked
                return ArrayUtil.transformArray(
                    value,
                    this::reindexValue,
                    componentType
                );
            }
        } else {
            if (clazz == NodeId.class) {
                return reindex((NodeId) value);
            } else if (clazz == ExpandedNodeId.class) {
                return reindex((ExpandedNodeId) value);
            } else if (clazz == QualifiedName.class) {
                return reindex((QualifiedName) value);
            } else if (clazz == ExtensionObject.class) {
                ExtensionObject xo = (ExtensionObject) value;

                if (xo.getBodyType() == ExtensionObject.BodyType.ByteString) {
                    xo = new ExtensionObject(
                        (ByteString) xo.getBody(),
                        reindex(xo.getEncodingId())
                    );
                } else if (xo.getBodyType() == ExtensionObject.BodyType.XmlElement) {
                    xo = new ExtensionObject(
                        (XmlElement) xo.getBody(),
                        reindex(xo.getEncodingId())
                    );
                }

                try {
                    Object struct = xo.decode(getServer().getSerializationContext());

                    if (struct instanceof Argument) {
                        Argument argument = (Argument) struct;

                        return ExtensionObject.encode(
                            getServer().getSerializationContext(),
                            new Argument(
                                argument.getName(),
                                reindex(argument.getDataType()),
                                argument.getValueRank(),
                                argument.getArrayDimensions(),
                                argument.getDescription()
                            )
                        );
                    } else {
                        return xo;
                    }
                } catch (Throwable t) {
                    logger.warn("Decoding failed: {}", xo, t);
                    return xo;
                }
            } else {
                return value;
            }
        }
    }

    protected UaNode buildDataTypeNode(DataTypeNodeAttributes attributes) {
        return new UaDataTypeNode(
            getNodeContext(),
            reindex(attributes.getNodeId()),
            reindex(attributes.getBrowseName()),
            attributes.getDisplayName(),
            attributes.getDescription(),
            attributes.getWriteMask(),
            attributes.getUserWriteMask(),
            attributes.isAbstract()
        );
    }

    protected UaNode buildMethodNode(MethodNodeAttributes attributes) {
        return new UaMethodNode(
            getNodeContext(),
            reindex(attributes.getNodeId()),
            reindex(attributes.getBrowseName()),
            attributes.getDisplayName(),
            attributes.getDescription(),
            attributes.getWriteMask(),
            attributes.getUserWriteMask(),
            attributes.isExecutable(),
            attributes.isUserExecutable()
        );
    }

    protected UaNode buildObjectNode(ObjectNodeAttributes attributes) {
        List<Reference> references = nodeSet.getExplicitReferences().get(attributes.getNodeId());

        NodeId typeDefinition = references.stream()
            .filter(Reference.HAS_TYPE_DEFINITION_PREDICATE)
            .findFirst()
            .flatMap(r -> r.getTargetNodeId().local(getServer().getNamespaceTable()))
            .orElse(NodeId.NULL_VALUE);

        Optional<ObjectNodeConstructor> nodeFactory =
            getServer().getObjectTypeManager().getNodeFactory(typeDefinition);

        return nodeFactory.map(factory -> {
            UaObjectNode node = factory.apply(
                getNodeContext(),
                reindex(attributes.getNodeId()),
                reindex(attributes.getBrowseName()),
                attributes.getDisplayName(),
                attributes.getDescription(),
                attributes.getWriteMask(),
                attributes.getUserWriteMask()
            );

            node.setEventNotifier(attributes.getEventNotifier());

            return node;
        }).orElseGet(() ->
            new UaObjectNode(
                getNodeContext(),
                reindex(attributes.getNodeId()),
                reindex(attributes.getBrowseName()),
                attributes.getDisplayName(),
                attributes.getDescription(),
                attributes.getWriteMask(),
                attributes.getUserWriteMask(),
                attributes.getEventNotifier()
            )
        );
    }

    protected UaNode buildObjectTypeNode(ObjectTypeNodeAttributes attributes) {
        return new UaObjectTypeNode(
            getNodeContext(),
            reindex(attributes.getNodeId()),
            reindex(attributes.getBrowseName()),
            attributes.getDisplayName(),
            attributes.getDescription(),
            attributes.getWriteMask(),
            attributes.getUserWriteMask(),
            attributes.isAbstract()
        );
    }

    protected UaReferenceTypeNode buildReferenceTypeNode(ReferenceTypeNodeAttributes attributes) {
        return new UaReferenceTypeNode(
            getNodeContext(),
            reindex(attributes.getNodeId()),
            reindex(attributes.getBrowseName()),
            attributes.getDisplayName(),
            attributes.getDescription(),
            attributes.getWriteMask(),
            attributes.getUserWriteMask(),
            attributes.isAbstract(),
            attributes.isSymmetric(),
            attributes.getInverseName()
        );
    }

    protected UaNode buildVariableNode(UaNodeSet nodeSet, VariableNodeAttributes attributes) {
        List<Reference> references = nodeSet.getExplicitReferences().get(attributes.getNodeId());

        NodeId typeDefinition = references.stream()
            .filter(Reference.HAS_TYPE_DEFINITION_PREDICATE)
            .findFirst()
            .flatMap(r -> r.getTargetNodeId().local(getServer().getNamespaceTable()))
            .orElse(NodeId.NULL_VALUE);

        Optional<VariableTypeManager.VariableNodeConstructor> nodeFactory =
            getServer().getVariableTypeManager().getNodeFactory(typeDefinition);

        return nodeFactory.map(factory -> {
            UaVariableNode node = factory.apply(
                getNodeContext(),
                reindex(attributes.getNodeId()),
                reindex(attributes.getBrowseName()),
                attributes.getDisplayName(),
                attributes.getDescription(),
                attributes.getWriteMask(),
                attributes.getUserWriteMask()
            );

            node.setValue(reindex(attributes.getValue()));
            node.setDataType(reindex(attributes.getDataType()));
            node.setValueRank(attributes.getValueRank());
            node.setArrayDimensions(attributes.getArrayDimensions());
            node.setAccessLevel(attributes.getAccessLevel());
            node.setUserAccessLevel(attributes.getUserAccessLevel());
            node.setMinimumSamplingInterval(attributes.getMinimumSamplingInterval());
            node.setHistorizing(attributes.isHistorizing());

            return node;
        }).orElseGet(() ->
            new UaVariableNode(
                getNodeContext(),
                reindex(attributes.getNodeId()),
                reindex(attributes.getBrowseName()),
                attributes.getDisplayName(),
                attributes.getDescription(),
                attributes.getWriteMask(),
                attributes.getUserWriteMask(),
                reindex(attributes.getValue()),
                reindex(attributes.getDataType()),
                attributes.getValueRank(),
                attributes.getArrayDimensions(),
                attributes.getAccessLevel(),
                attributes.getUserAccessLevel(),
                attributes.getMinimumSamplingInterval(),
                attributes.isHistorizing()
            )
        );
    }

    protected UaNode buildVariableTypeNode(VariableTypeNodeAttributes attributes) {
        return new UaVariableTypeNode(
            getNodeContext(),
            reindex(attributes.getNodeId()),
            reindex(attributes.getBrowseName()),
            attributes.getDisplayName(),
            attributes.getDescription(),
            attributes.getWriteMask(),
            attributes.getUserWriteMask(),
            reindex(attributes.getValue()),
            reindex(attributes.getDataType()),
            attributes.getValueRank(),
            attributes.getArrayDimensions(),
            attributes.isAbstract()
        );
    }

    protected UaNode buildViewNode(ViewNodeAttributes attributes) {
        return new UaViewNode(
            getNodeContext(),
            reindex(attributes.getNodeId()),
            reindex(attributes.getBrowseName()),
            attributes.getDisplayName(),
            attributes.getDescription(),
            attributes.getWriteMask(),
            attributes.getUserWriteMask(),
            attributes.isContainsNoLoops(),
            attributes.getEventNotifier()
        );
    }

}
